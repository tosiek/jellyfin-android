package org.jellyfin.mobile.tls

import android.content.Context
import android.security.KeyChain
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import org.json.JSONArray
import org.json.JSONObject
import timber.log.Timber
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.thread

private const val KEYSTORE_TIMEOUT_MS = 10_000L

/**
 * Run [block], which calls AndroidKeyStore or KeyChain (also by using a key of them), on its own thread and give up
 * after [KEYSTORE_TIMEOUT_MS] with a [TimeoutException]. These system services may never answer: on Android 11 the
 * reply of the keystore to getEntry got lost after the app had been restarted (emulator, "binder: transaction failed"
 * of the keystore process), the call blocked forever and the connection check never started.
 */
internal fun <T> withKeyStoreTimeout(block: () -> T): T {
    val task = FutureTask(block)
    thread(isDaemon = true, name = "tls-keystore") { task.run() }
    return try {
        task.get(KEYSTORE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
    } catch (err: ExecutionException) {
        throw err.cause ?: err
    }
}

class ClientKey(
    val privateKey: PrivateKey,
    val chain: Array<X509Certificate>,
)

/**
 * Stores and loads client keys. Imported keys go into AndroidKeyStore when the key passes the [KeySelfTest] there,
 * otherwise they are stored encrypted with an AndroidKeyStore AES key and loaded as a software key.
 */
class ClientKeyStore(private val context: Context) {
    private val clientDirectory = File(context.filesDir, "tls/client")
    private val cache = ConcurrentHashMap<ClientCertificate, ClientKey>()

    private val androidKeyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) } }

    /**
     * Store an imported key. Returns the [ClientCertificate] to save in the endpoint configuration.
     */
    @Suppress("TooGenericExceptionCaught")
    fun import(key: ClientKey): ClientCertificate.Imported {
        val alias = "$ALIAS_PREFIX${UUID.randomUUID()}"

        try {
            val usable = withKeyStoreTimeout {
                androidKeyStore.setEntry(
                    alias,
                    KeyStore.PrivateKeyEntry(key.privateKey, key.chain),
                    createKeyProtection(key)
                )
                val entry = androidKeyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
                KeySelfTest.run(entry.privateKey, key.chain.first())
            }
            if (usable) return ClientCertificate.Imported(alias, ClientCertificate.Imported.Storage.KEYSTORE)
            Timber.w("Key self-test failed in AndroidKeyStore, using encrypted file storage")
        } catch (err: Exception) {
            Timber.w(err, "Unable to import key into AndroidKeyStore, using encrypted file storage")
        }
        // Not waited for, the keystore may not answer
        thread(isDaemon = true, name = "tls-keystore-delete") { runCatching { androidKeyStore.deleteEntry(alias) } }

        if (!KeySelfTest.run(key.privateKey, key.chain.first())) throw KeyUnusableException()
        try {
            withKeyStoreTimeout { writeEncrypted(alias, key) }
        } catch (err: TimeoutException) {
            Timber.w(err, "AndroidKeyStore does not answer, the key cannot be stored")
            throw ImportException(ImportError.KeyStoreTimeout, err)
        }
        return ClientCertificate.Imported(alias, ClientCertificate.Imported.Storage.ENCRYPTED_FILE)
    }

    fun delete(certificate: ClientCertificate) {
        cache.remove(certificate)
        if (certificate !is ClientCertificate.Imported) return
        when (certificate.storage) {
            ClientCertificate.Imported.Storage.KEYSTORE -> runCatching {
                withKeyStoreTimeout { androidKeyStore.deleteEntry(certificate.alias) }
            }.onFailure {
                Timber.w(it, "Unable to delete client certificate $certificate from AndroidKeyStore")
            }

            ClientCertificate.Imported.Storage.ENCRYPTED_FILE -> File(clientDirectory, certificate.alias).delete()
        }
    }

    /**
     * Load a key. Must not be called on the main thread (KeyChain access). Returns null when unavailable.
     */
    fun load(certificate: ClientCertificate): ClientKey? = try {
        loadOrTimeout(certificate)
    } catch (_: TimeoutException) {
        null
    }

    /**
     * [load] that throws the [TimeoutException] when the keystore did not answer, to tell this apart from a missing
     * key. Tried twice: the lost reply (see [withKeyStoreTimeout]) is the one of a single call, the next one is answered.
     */
    @Suppress("InstanceOfCheckForException", "SwallowedException", "TooGenericExceptionCaught")
    fun loadOrTimeout(certificate: ClientCertificate): ClientKey? = cache[certificate] ?: try {
        try {
            read(certificate)
        } catch (err: TimeoutException) {
            Timber.w("Keystore did not answer loading client certificate $certificate, trying again")
            read(certificate)
        }
    } catch (err: Exception) {
        Timber.w(err, "Unable to load client certificate $certificate")
        if (err is TimeoutException) throw err
        null
    }?.also { cache[certificate] = it }

    /**
     * Load the key of the system certificate the user chose, or throw the [ImportException] to show.
     */
    fun loadChosen(certificate: ClientCertificate.System): ClientKey = try {
        loadOrTimeout(certificate)
    } catch (_: TimeoutException) {
        throw ImportException(ImportError.KeyStoreTimeout)
    } ?: throw ImportException(ImportError.NoPrivateKey)

    private fun read(certificate: ClientCertificate): ClientKey? = when (certificate) {
        ClientCertificate.None -> null
        is ClientCertificate.System -> withKeyStoreTimeout {
            val privateKey = KeyChain.getPrivateKey(context, certificate.alias)
            val chain = KeyChain.getCertificateChain(context, certificate.alias)
            if (privateKey != null && !chain.isNullOrEmpty()) ClientKey(privateKey, chain) else null
        }

        is ClientCertificate.Imported -> when (certificate.storage) {
            ClientCertificate.Imported.Storage.KEYSTORE -> withKeyStoreTimeout {
                val entry = androidKeyStore.getEntry(certificate.alias, null) as? KeyStore.PrivateKeyEntry
                val chain = entry?.certificateChain?.filterIsInstance<X509Certificate>()?.toTypedArray()
                if (entry != null && chain != null) ClientKey(entry.privateKey, chain) else null
            }

            ClientCertificate.Imported.Storage.ENCRYPTED_FILE -> withKeyStoreTimeout {
                readEncrypted(certificate.alias)
            }
        }
    }

    fun clearCache() = cache.clear()

    private fun createKeyProtection(key: ClientKey): KeyProtection {
        val isRsa = key.privateKey.algorithm.equals(KeyProperties.KEY_ALGORITHM_RSA, ignoreCase = true)
        // TLS signs with "NONEwith…" (digest NONE) and performs raw RSA (decrypt, no padding) for RSA-PSS
        val purposes = if (isRsa) {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN
        }
        return KeyProtection.Builder(purposes).apply {
            setDigests(
                KeyProperties.DIGEST_NONE,
                KeyProperties.DIGEST_SHA1,
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512,
            )
            if (isRsa) {
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            }
            setUserAuthenticationRequired(false)
        }.build()
    }

    private fun getWrappingKey(): SecretKey {
        (androidKeyStore.getKey(WRAPPING_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                WRAPPING_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(WRAPPING_KEY_BITS)
                .build()
        )
        return generator.generateKey()
    }

    private fun writeEncrypted(alias: String, key: ClientKey) {
        val payload = JSONObject()
            .put("algorithm", key.privateKey.algorithm)
            .put("key", key.privateKey.encoded.toHex())
            .put("chain", JSONArray(key.chain.map { it.encoded.toHex() }))
            .toString()
            .toByteArray()

        val cipher = Cipher.getInstance(WRAPPING_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getWrappingKey())
        clientDirectory.mkdirs()
        File(
            clientDirectory,
            alias
        ).writeBytes(byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + cipher.doFinal(payload))
    }

    private fun readEncrypted(alias: String): ClientKey? {
        val file = File(clientDirectory, alias)
        if (!file.exists()) return null
        val bytes = file.readBytes()
        val ivLength = bytes[0].toInt()
        val cipher = Cipher.getInstance(WRAPPING_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getWrappingKey(), GCMParameterSpec(GCM_TAG_LENGTH, bytes, 1, ivLength))
        val json = JSONObject(String(cipher.doFinal(bytes, 1 + ivLength, bytes.size - 1 - ivLength)))

        val privateKey = KeyFactory.getInstance(json.getString("algorithm"))
            .generatePrivate(PKCS8EncodedKeySpec(json.getString("key").fromHex()))
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val chainJson = json.getJSONArray("chain")
        val chain = Array(chainJson.length()) {
            certificateFactory.generateCertificate(chainJson.getString(it).fromHex().inputStream()) as X509Certificate
        }
        return ClientKey(privateKey, chain)
    }

    class KeyUnusableException : Exception("The private key cannot be used for TLS on this device")

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PREFIX = "jellyfin_tls_client_"
        const val WRAPPING_KEY_ALIAS = "jellyfin_tls_wrapping"
        const val WRAPPING_TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_LENGTH = 128
        const val WRAPPING_KEY_BITS = 256
        const val HEX_RADIX = 16

        fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
        fun String.fromHex() = chunked(2).map { it.toInt(HEX_RADIX).toByte() }.toByteArray()
    }
}

/**
 * Exercises the private key operations Conscrypt (Android's TLS stack) performs during client authentication:
 * - RSA: "NONEwithRSA" (PKCS#1 v1.5 over a digest) and raw RSA via "RSA/ECB/NoPadding" decrypt (used for RSA-PSS)
 * - EC: "NONEwithECDSA"
 * Each operation is verified with the public key from the certificate.
 */
object KeySelfTest {
    private const val TEST_DATA_SIZE = 32

    @Suppress("TooGenericExceptionCaught")
    fun run(privateKey: PrivateKey, certificate: X509Certificate): Boolean = try {
        // The key may live in AndroidKeyStore or KeyChain
        withKeyStoreTimeout {
            when (privateKey.algorithm.uppercase()) {
                "RSA" -> testRsa(privateKey, certificate)
                "EC", "ECDSA" -> testSignature("NONEwithECDSA", privateKey, certificate)
                else -> false
            }
        }
    } catch (err: Exception) {
        Timber.w(err, "Key self-test failed")
        false
    }

    private fun testSignature(algorithm: String, privateKey: PrivateKey, certificate: X509Certificate): Boolean {
        val data = ByteArray(TEST_DATA_SIZE).also(SecureRandom()::nextBytes)
        val signature = Signature.getInstance(algorithm).run {
            initSign(privateKey)
            update(data)
            sign()
        }
        return Signature.getInstance(algorithm).run {
            initVerify(certificate.publicKey)
            update(data)
            verify(signature)
        }
    }

    private fun testRsa(privateKey: PrivateKey, certificate: X509Certificate): Boolean {
        if (!testSignature("NONEwithRSA", privateKey, certificate)) return false

        // Raw RSA private operation, input must be smaller than the modulus
        val modulus = (certificate.publicKey as RSAKey).modulus
        val size = (modulus.bitLength() + Byte.SIZE_BITS - 1) / Byte.SIZE_BITS
        val input = ByteArray(size).also(SecureRandom()::nextBytes).also { it[0] = 0 }
        val output = Cipher.getInstance("RSA/ECB/NoPadding").run {
            init(Cipher.DECRYPT_MODE, privateKey)
            doFinal(input)
        }
        val roundTrip = Cipher.getInstance("RSA/ECB/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, certificate.publicKey)
            doFinal(output)
        }
        return BigInteger(1, roundTrip) == BigInteger(1, input)
    }
}
