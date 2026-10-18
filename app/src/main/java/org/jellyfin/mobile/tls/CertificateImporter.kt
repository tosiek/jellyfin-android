package org.jellyfin.mobile.tls

import android.os.Build
import java.io.ByteArrayInputStream
import java.io.IOException
import java.math.BigInteger
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.spec.InvalidKeySpecException
import java.util.Date
import kotlin.io.encoding.Base64

sealed interface ImportError {
    /** Not a certificate or PKCS#12 file. */
    data object UnrecognizedFormat : ImportError

    /** A PEM private key or certificate was picked as client certificate. */
    data object NotPkcs12 : ImportError

    data object WrongPassword : ImportError

    /**
     * Wrong password, or a correct password with non-ASCII characters Android can not use for this file (seen with
     * OpenSSL 3 files using legacy 3DES encryption).
     */
    data object WrongOrUnsupportedPassword : ImportError

    /** The PKCS#12 file uses encryption this Android version cannot read. */
    data class UnsupportedEncryption(val detected: List<String>, val supported: List<String>) : ImportError

    data object NoPrivateKey : ImportError

    /** A PKCS#12 file picked as CA certificate contains no CA certificate. */
    data object NoCaCertificate : ImportError

    data class UnsupportedKeyType(val keyType: String) : ImportError

    /** The private key could not be decoded, usually because its type is not supported by this Android version. */
    data object UnreadableKey : ImportError

    /** The key was read but failed the TLS operations self-test in every storage. */
    data object KeyUnusable : ImportError

    /** The system keystore did not answer when a key was stored or the key of a system certificate was requested. */
    data object KeyStoreTimeout : ImportError

    data class Expired(val date: Date) : ImportError
    data class NotYetValid(val date: Date) : ImportError
    data class InsecureSignature(val algorithm: String) : ImportError
}

class ImportException(val error: ImportError, cause: Throwable? = null) : Exception(error.toString(), cause)

sealed interface ImportWarning {
    /** The certificate is not a CA, it can only be used for this exact server certificate. */
    data class NotCertificateAuthority(val subject: String) : ImportWarning

    data class WeakSignature(val algorithm: String) : ImportWarning
    data class WeakKey(val bits: Int) : ImportWarning
}

data class ParsedCertificates(
    val certificates: List<X509Certificate>,
    val warnings: List<ImportWarning>,
)

data class ParsedClientKey(
    val key: ClientKey,
    val warnings: List<ImportWarning>,
    /** CA certificates in the file besides the client certificate, often the CA that issued it. */
    val caCertificates: List<X509Certificate> = emptyList(),
)

/**
 * A PKCS#12 file picked as CA certificate: its CA certificates and the aliases of the client keys it also contains.
 */
data class ParsedPkcs12Cas(
    val certificates: List<X509Certificate>,
    val keyAliases: List<String>,
)

@Suppress("TooManyFunctions")
object CertificateImporter {
    private val pemBlock = Regex("-----BEGIN ([A-Z0-9 ]+)-----([^-]+)-----END \\1-----")

    /**
     * Parse CA certificates from PEM (single, bundle, surrounded by text), DER or PKCS#7 data.
     */
    fun parseCertificates(data: ByteArray): ParsedCertificates {
        val certificates = readCertificates(data)
        if (certificates.isEmpty()) throw ImportException(ImportError.UnrecognizedFormat)

        val warnings = mutableListOf<ImportWarning>()
        certificates.forEach { certificate ->
            checkCertificate(certificate, warnings)
            if (certificate.basicConstraints < 0) {
                warnings += ImportWarning.NotCertificateAuthority(certificate.subjectX500Principal.name)
            }
        }

        return ParsedCertificates(certificates, warnings.distinct())
    }

    /**
     * Parse a PKCS#12 file. When multiple keys are present [alias] selects one, otherwise the first key is used.
     */
    @Suppress("CyclomaticComplexMethod", "ThrowsCount", "TooGenericExceptionCaught")
    fun parsePkcs12(data: ByteArray, password: CharArray, alias: String? = null): ParsedClientKey {
        val (keyStore, workingPassword) = loadPkcs12(data, password)
        val keyAliases = keyStore.aliases().toList().filter { keyStore.isKeyEntry(it) }
        val selectedAlias = alias?.takeIf { it in keyAliases } ?: keyAliases.firstOrNull()
            ?: throw ImportException(
                if (Pkcs12Algorithms.UNENCRYPTED_KEY in Pkcs12Algorithms.detect(data)) {
                    platformFailure(data)
                } else {
                    ImportError.NoPrivateKey
                }
            )

        val privateKey = try {
            keyStore.getKey(selectedAlias, workingPassword) as? PrivateKey
        } catch (err: UnrecoverableKeyException) {
            // A wrong password fails the decryption. A key that decrypts but can not be decoded (e.g. ML-DSA on the
            // JDK) is reported as unrecoverable too, with the failing key factory as cause.
            val undecodable = err.hasCause<NoSuchAlgorithmException>() || err.hasCause<InvalidKeySpecException>()
            val error = when {
                !undecodable -> wrongPassword(password)
                else -> unsupportedKeyType(err) ?: ImportError.UnreadableKey
            }
            throw ImportException(error, err)
        } catch (err: NoSuchAlgorithmException) {
            throw ImportException(unsupportedKeyType(err) ?: unsupportedEncryption(data), err)
        } catch (err: RuntimeException) {
            throw ImportException(platformFailure(data), err)
        } ?: throw ImportException(ImportError.NoPrivateKey)

        val chain = keyStore.getCertificateChain(selectedAlias)?.filterIsInstance<X509Certificate>()
            ?.takeIf { it.isNotEmpty() }
            ?: (keyStore.getCertificate(selectedAlias) as? X509Certificate)?.let(::listOf)
            ?: throw ImportException(ImportError.NoPrivateKey)

        val warnings = mutableListOf<ImportWarning>()
        checkKey(privateKey, chain.first(), warnings)
        checkCertificate(chain.first(), warnings)

        val caCertificates = containedCas(keyStore, chain.drop(1))
        return ParsedClientKey(ClientKey(privateKey, chain.toTypedArray()), warnings.distinct(), caCertificates)
    }

    /**
     * Parse the CA certificates of a PKCS#12 file picked as CA certificate, see [ParsedPkcs12Cas].
     */
    fun parsePkcs12Cas(data: ByteArray, password: CharArray): ParsedPkcs12Cas {
        val (keyStore) = loadPkcs12(data, password)
        val keyAliases = keyStore.aliases().toList().filter { keyStore.isKeyEntry(it) }
        val issuers = keyAliases.flatMap { alias ->
            keyStore.getCertificateChain(alias)?.filterIsInstance<X509Certificate>()?.drop(1).orEmpty()
        }
        val certificates = containedCas(keyStore, issuers)
        if (certificates.isEmpty()) throw ImportException(ImportError.NoCaCertificate)
        return ParsedPkcs12Cas(certificates, keyAliases)
    }

    /**
     * The CA certificates of a PKCS#12 file that are valid now: [issuers] (from the key chains) and the certificate
     * entries (openssl pkcs12 -certfile).
     */
    private fun containedCas(keyStore: KeyStore, issuers: List<X509Certificate>): List<X509Certificate> {
        val entries = keyStore.aliases().toList().filter(keyStore::isCertificateEntry)
            .mapNotNull { keyStore.getCertificate(it) as? X509Certificate }
        return (issuers + entries)
            .filter { it.basicConstraints >= 0 && runCatching { it.checkValidity() }.isSuccess }
            .distinctBy { it.sha256() }
    }

    /**
     * Whether [data] can be a PKCS#12 file (binary DER), e.g. one picked as CA certificate.
     */
    fun mayBePkcs12(data: ByteArray): Boolean = looksLikeDer(data)

    fun getPkcs12KeyAliases(data: ByteArray, password: CharArray): List<String> {
        val (keyStore) = loadPkcs12(data, password)
        return keyStore.aliases().toList().filter { keyStore.isKeyEntry(it) }
    }

    /**
     * Throws when [data] can not be a PKCS#12 file (PEM or unknown format), checked before the password is asked.
     */
    fun checkPkcs12Format(data: ByteArray) {
        if (!looksLikeDer(data)) {
            throw ImportException(
                if (pemBlock.containsMatchIn(
                        String(data, Charsets.ISO_8859_1)
                    )
                ) {
                    ImportError.NotPkcs12
                } else {
                    ImportError.UnrecognizedFormat
                }
            )
        }
    }

    /**
     * Load a PKCS#12 file, returns the key store and the password variant that opened it.
     */
    @Suppress("CyclomaticComplexMethod", "ThrowsCount", "TooGenericExceptionCaught")
    private fun loadPkcs12(data: ByteArray, password: CharArray): Pair<KeyStore, CharArray?> {
        checkPkcs12Format(data)

        val passwords = buildList {
            add(password)
            if (password.isEmpty()) add(null)
            // OpenSSL creates PKCS#12 files with non-ASCII passwords from the UTF-8 bytes interpreted as single characters
            // (legacy PBE encryption), OpenSSL itself tries this variant as well when reading
            if (password.any { it.code > MAX_ASCII_CODE }) {
                add(
                    String(password).toByteArray(Charsets.UTF_8).toString(Charsets.ISO_8859_1).toCharArray()
                )
            }
        }
        var lastError: Exception? = null
        for (candidate in passwords) {
            try {
                return KeyStore.getInstance("PKCS12").apply { load(ByteArrayInputStream(data), candidate) } to candidate
            } catch (err: IOException) {
                lastError = err
            } catch (err: NoSuchAlgorithmException) {
                throw ImportException(unsupportedKeyType(err) ?: unsupportedEncryption(data), err)
            } catch (err: RuntimeException) {
                // Bugs in the platform PKCS#12 reader, e.g. ClassCastException for unencrypted key bags on API 36 or
                // "error creating key" for unencrypted Ed25519 keys on API 28
                throw ImportException(platformFailure(data), err)
            }
        }

        val error = lastError
        throw when {
            unsupportedKeyType(error) != null -> ImportException(unsupportedKeyType(error)!!, error)
            error.hasCause<UnrecoverableKeyException>() -> ImportException(wrongPassword(password), error)
            // Android reports missing algorithms inside the IOException message, e.g.
            // "exception decrypting data - java.security.NoSuchAlgorithmException: 1.2.840.113549.1.5.12 SecretKeyFactory not available"
            error.hasCause<NoSuchAlgorithmException>() ||
                error.messageContains(
                    "unsupported", "not supported", "no such algorithm", "nosuchalgorithm", "not available",
                ) ->
                ImportException(unsupportedEncryption(data), error)

            // e.g. Ed25519 on older Android: "exception unwrapping private key - InvalidKeyException: Invalid key encoding."
            error.messageContains("unwrapping private key", "invalid key encoding", "invalid key spec") ->
                ImportException(ImportError.UnreadableKey, error)

            // Older Android (e.g. API 24 - 26) can not verify SHA-256 based integrity checks of OpenSSL 3 files and
            // reports them as wrong password, the AOSP Android 13 image can not compute them ("error constructing MAC").
            // Only a wrong password when the device supports the encryption.
            error.messageContains("mac invalid", "error constructing mac") && usesModernEncryption(data) &&
                !Pkcs12Algorithms.supportsModernEncryption() ->
                ImportException(unsupportedEncryption(data), error)

            error.messageContains("password", "mac", "integrity") -> ImportException(wrongPassword(password), error)
            else -> ImportException(ImportError.UnrecognizedFormat, error)
        }
    }

    private fun readCertificates(data: ByteArray): List<X509Certificate> {
        val factory = CertificateFactory.getInstance("X.509")
        val text = String(data, Charsets.ISO_8859_1).removePrefix("ï»¿")

        // Normalize PEM ourselves so every Android version gets plain DER
        val blocks = pemBlock.findAll(text).toList()
        if (blocks.isNotEmpty()) {
            return blocks.flatMap { block ->
                val type = block.groupValues[1]
                if (type !in CERTIFICATE_TYPES) return@flatMap emptyList()
                val der = runCatching { Base64.Default.decode(block.groupValues[2].filterNot(Char::isWhitespace)) }
                    .getOrNull() ?: return@flatMap emptyList()
                generate(factory, der)
            }.distinctBy { it.sha256() }
        }

        return if (looksLikeDer(data)) generate(factory, data) else emptyList()
    }

    private fun generate(factory: CertificateFactory, der: ByteArray): List<X509Certificate> = runCatching {
        factory.generateCertificates(ByteArrayInputStream(der)).filterIsInstance<X509Certificate>()
    }.getOrNull().orEmpty()

    @Suppress("ThrowsCount")
    private fun checkCertificate(certificate: X509Certificate, warnings: MutableList<ImportWarning>) {
        try {
            certificate.checkValidity()
        } catch (err: CertificateExpiredException) {
            throw ImportException(ImportError.Expired(certificate.notAfter), err)
        } catch (err: CertificateNotYetValidException) {
            throw ImportException(ImportError.NotYetValid(certificate.notBefore), err)
        }

        val signature = certificate.sigAlgName.uppercase()
        when {
            signature.contains("MD5") || signature.contains("MD2") -> throw ImportException(
                ImportError.InsecureSignature(certificate.sigAlgName)
            )
            signature.contains("SHA1") -> warnings += ImportWarning.WeakSignature(certificate.sigAlgName)
        }

        (certificate.publicKey as? RSAKey)?.modulus?.bitLength()?.let { bits ->
            if (bits < MIN_RSA_BITS) warnings += ImportWarning.WeakKey(bits)
        }
    }

    private fun checkKey(privateKey: PrivateKey, certificate: X509Certificate, warnings: MutableList<ImportWarning>) {
        when (val type = privateKey.algorithm.uppercase()) {
            "RSA" -> Unit
            "EC", "ECDSA" -> {
                // Check the exact curve, other curves of the same size (e.g. brainpoolP256r1) are not offered for TLS
                val order = (certificate.publicKey as? ECKey)?.params?.order
                if (order != null && order !in SUPPORTED_EC_ORDERS) {
                    val bits = order.bitLength()
                    val name = if (bits == P521_BITS) "EC P-521" else "EC ($bits bit curve, not P-256 / P-384)"
                    throw ImportException(ImportError.UnsupportedKeyType(name))
                }
            }

            else -> throw ImportException(ImportError.UnsupportedKeyType(privateKey.algorithm))
        }
        (privateKey as? RSAKey)?.modulus?.bitLength()?.let { bits ->
            if (bits < MIN_RSA_BITS) warnings += ImportWarning.WeakKey(bits)
        }
    }

    /**
     * Older Android versions fail to read keys of unsupported types (e.g. Ed25519) with a generic algorithm error.
     */
    private fun unsupportedKeyType(error: Throwable?): ImportError.UnsupportedKeyType? {
        val messages = generateSequence(error) { it.cause }.mapNotNull { it.message?.lowercase() }.toList()
        return unsupportedKeyAlgorithms.entries
            .firstOrNull { (marker, _) -> messages.any { it.contains(marker) } }
            ?.let { ImportError.UnsupportedKeyType(it.value) }
    }

    private val unsupportedKeyAlgorithms = mapOf(
        "ed25519" to "Ed25519",
        "1.3.101.112" to "Ed25519",
        "ed448" to "Ed448",
        "1.3.101.113" to "Ed448",
        "eddsa" to "EdDSA",
        "dsa key" to "DSA",
        "ml-dsa" to "ML-DSA",
        "2.16.840.1.101.3.4.3.17" to "ML-DSA",
        "2.16.840.1.101.3.4.3.18" to "ML-DSA",
        "2.16.840.1.101.3.4.3.19" to "ML-DSA",
    )

    private fun wrongPassword(password: CharArray) = when {
        password.any { it.code > MAX_ASCII_CODE } -> ImportError.WrongOrUnsupportedPassword
        else -> ImportError.WrongPassword
    }

    private fun usesModernEncryption(data: ByteArray) = Pkcs12Algorithms.detect(data).any {
        it == "PBES2" || it == "HMAC-SHA256" || it == "SHA-256" || it == "SHA-384" || it == "SHA-512"
    }

    private fun platformFailure(data: ByteArray): ImportError {
        val detected = Pkcs12Algorithms.detect(data)
        return when {
            Pkcs12Algorithms.ED25519_KEY in detected -> ImportError.UnsupportedKeyType("Ed25519")
            Pkcs12Algorithms.ED448_KEY in detected -> ImportError.UnsupportedKeyType("Ed448")
            Pkcs12Algorithms.UNENCRYPTED_KEY in detected -> unsupportedEncryption(data)
            else -> ImportError.UnreadableKey
        }
    }

    private fun unsupportedEncryption(data: ByteArray) = ImportError.UnsupportedEncryption(
        detected = Pkcs12Algorithms.detect(data),
        supported = Pkcs12Algorithms.supportedOnDevice(),
    )

    private fun looksLikeDer(data: ByteArray) = data.size > 2 && data[0] == 0x30.toByte()

    private inline fun <reified T : Throwable> Throwable?.hasCause(): Boolean =
        generateSequence(this) { it.cause }.any { it is T }

    private fun Throwable?.messageContains(vararg values: String): Boolean = generateSequence(this) { it.cause }
        .mapNotNull { it.message?.lowercase() }
        .any { message -> values.any { message.contains(it) } }

    private const val MIN_RSA_BITS = 2048
    private const val P521_BITS = 521
    private const val MAX_ASCII_CODE = 0x7f
    private const val HEX_RADIX = 16

    private val CERTIFICATE_TYPES = setOf("CERTIFICATE", "TRUSTED CERTIFICATE", "PKCS7")

    // P-521 requires ecdsa_secp521r1_sha512 in TLS 1.3, which Android's TLS stack does not offer for client
    // authentication (verified on API 29), so those keys would fail on every TLS 1.3 server.
    // Group orders of the supported curves: P-256 (secp256r1) and P-384 (secp384r1)
    private val SUPPORTED_EC_ORDERS = setOf(
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", HEX_RADIX),
        BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            HEX_RADIX,
        ),
    )
}

/**
 * Detects the encryption algorithms used in a PKCS#12 file and the ones the device can read.
 */
object Pkcs12Algorithms {
    const val UNENCRYPTED_KEY = "unencrypted private key"
    const val ED25519_KEY = "Ed25519 key"
    const val ED448_KEY = "Ed448 key"
    private const val MODERN_ENCRYPTION = "PBES2 / AES-256-CBC (PBKDF2)"

    private val knownAlgorithms = mapOf(
        // Key algorithms, only visible for unencrypted keys
        "1.3.101.112" to ED25519_KEY,
        "1.3.101.113" to ED448_KEY,
        "1.2.840.113549.1.12.10.1.1" to UNENCRYPTED_KEY,
        "1.2.840.113549.1.12.1.1" to "RC4-128 (SHA-1)",
        "1.2.840.113549.1.12.1.2" to "RC4-40 (SHA-1)",
        "1.2.840.113549.1.12.1.3" to "3DES (SHA-1)",
        "1.2.840.113549.1.12.1.4" to "2-key 3DES (SHA-1)",
        "1.2.840.113549.1.12.1.5" to "RC2-128 (SHA-1)",
        "1.2.840.113549.1.12.1.6" to "RC2-40 (SHA-1)",
        "1.2.840.113549.1.5.13" to "PBES2",
        "1.2.840.113549.1.5.12" to "PBKDF2",
        "2.16.840.1.101.3.4.1.2" to "AES-128-CBC",
        "2.16.840.1.101.3.4.1.22" to "AES-192-CBC",
        "2.16.840.1.101.3.4.1.42" to "AES-256-CBC",
        "1.2.840.113549.2.9" to "HMAC-SHA256",
        "1.2.840.113549.2.10" to "HMAC-SHA384",
        "1.2.840.113549.2.11" to "HMAC-SHA512",
        "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384",
        "2.16.840.1.101.3.4.2.3" to "SHA-512",
    )

    // Tiny certificate-only PKCS#12 files (password "probe") per encryption. Loading them with the platform reader is
    // the only reliable check, looking up the algorithms by name or OID differs from what the reader does.
    private val probes = listOf(
        "3DES (SHA-1)" to
            "MIICRAIBAzCCAgoGCSqGSIb3DQEHAaCCAfsEggH3MIIB8zCCAe8GCSqGSIb3DQEHBqCCAeAwggHcAgEAMIIB1QYJKoZIhvcNAQcB" +
            "MBwGCiqGSIb3DQEMAQMwDgQIJXgPHhWijzYCAggAgIIBqHJ+0mlnTTkGGMAZ7bKLmCz5QrzJBxXA3gqzz7cUwkiZbHyHcPMXdhg3" +
            "Xg0DK8dLPFAE3habU6RP7o8nNB9iCCi86S1QBgzRHcN2p378kCXKKtyBZ3QDkK0qoOVRqYR2BoWbG+aadOnbH0IRZKOdnlbvGbiZ" +
            "HMs2qFgE/WNuRgc9ejrtYHR1qFpHRzhblUkEtq8yioefYrp3YceY96+yJ26EqAqIJVD4p7jrLhGjvsZSt2mp0+dNV+GJxxc+i/0G" +
            "07Xq/y6HHedrkxuhwBlX0Le4qGg9tkzK/Rfr5+hRkA9TQqU17/2zgc2mwOne2bxpyuyftG421Hyj3fWFgRTAduUgDlNyU76e5Aet" +
            "qVJmDKMHU0iBOxcsbmdhgBAdmEVv/xd3Dls+ScMOrLJiVIxl9MSAirppiN71x4sny6hHTsxLxZMFM0zj3UI1zqbmMo+ulGJ/2Egh" +
            "y9en/kqcHv7ZVUJJsg+pHFCHOrKWJzvPMcAPwH2XrnFub7pOPBYF4Ckul42G9SBd8xFYDTsxLcXCo1bDckGMzELPxyF7c+JLpFG1" +
            "SW0W8kugrBowMTAhMAkGBSsOAwIaBQAEFAgXGYEVafZz994AFA5lqvQ2LAjiBAjbDne2KzLBTQICCAA=",
        "RC2-40 (SHA-1)" to
            "MIICRAIBAzCCAgoGCSqGSIb3DQEHAaCCAfsEggH3MIIB8zCCAe8GCSqGSIb3DQEHBqCCAeAwggHcAgEAMIIB1QYJKoZIhvcNAQcB" +
            "MBwGCiqGSIb3DQEMAQYwDgQIbc+WCZI1bFkCAggAgIIBqJJ1Izpi1VbUEorkMtdPkZ/9kwx2rY8d36cqswpFK85f/hospMysuX6m" +
            "io8wohb60rEcgroHtOqyjKmgdFqdYUTSXm7F8UTDf/Btpy/7owhxPbI5xTQsCJNcD/y4j1CwSYFCwhWGc+lAnoNBrcbbqyZ9RYX+" +
            "cg1NuuSnQIsMbnpzZy9sw/h0RXDqBm2HyFWw3mqUeq2zRzyOCxmeTiKlS7txcZNMfvS54ERTEB9v5S+e+ldJzwJBjv0A/5j45g0C" +
            "GcalWoK2d1uoh6Y2WNYhGQ6BLApmjx+UZyBmHq1KbOPuXs6Od1MEMPp/GnlSeCyNeLgNv6w8IIFNDDb7mprfj3QyuOV3SVQGe2tO" +
            "k4qyxXQJE1ahgnTwQ3sO2P8NaDNO7L0tYwKW1CKFQa6UKuayJDu1MGp8raJcSLggkcxnOi1AHzOHw3CaBRdHwDEc/tIfCDTGyLSf" +
            "IOsU3jdmrv/FSwD2yPyqaZDNqpOOqMe9mckrHqHUd7Q76Xi5kth7IespQNKIEetmwDjJjLdaqLDdUUqRSYAvk1tQj7Jz7zQPIHZp" +
            "HFsNeMHZCTEwMTAhMAkGBSsOAwIaBQAEFGl2HQF9oHS+r81XDLoP/0QO2qGpBAjphnHGqYzYowICCAA=",
        MODERN_ENCRYPTION to
            "MIICnwIBAzCCAlUGCSqGSIb3DQEHAaCCAkYEggJCMIICPjCCAjoGCSqGSIb3DQEHBqCCAiswggInAgEAMIICIAYJKoZIhvcNAQcB" +
            "MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDChw35szaWUb2oGDwRqeObAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFl" +
            "AwQBKgQQx9u1IOxpBL3ZkN3asLL21YCCAbC0+IEjAFvtDpp7tc420Rs2ioNonVL5qxcLMGCSDbMEY1kzKGDeMB89yz0FCS4B69iU" +
            "4gXywkBff5/GYgys8v0Nn2svl0yrITfUQt9np4eFUY7h1sMdUbM8Vi8lfP2RZ4S5fAicb0VYU3TlWSSoKip3pouGeUh1uWBfyUCp" +
            "oQ376R9K3LZ72Dzg0/NsCogczqHrX1i2wsimQ+yuTuWkvbWhb19DcNG5ho7kyhGM+YHwmczVUcHezhG+KkUzhHWbNjgQ0zczLiCW" +
            "f2spozS96ONjwE+5qeEOKYMQgxGCrheMqPNXx1IaVnTag0wVLF87svrOrvcD9SzKJbywqOfY/gniCaJU/26zS4YmxE8AYWe7Jc+H" +
            "ZVOklMMgRwdRWT27lCufOD24LPq4Dr6DK8DsqAn4CHHYDZBwg9Q5q7zxI3B4GB9sBGdRGLtRkFC9L1YrvqYcSwxo3MIuxOamX3SS" +
            "NEhl5ulngXG8QKaXLGdXcCu+Epo8wLhhGdCl/MAmdLbPFZchPzEHHOisfH1Wg50CRRQP5FAvr7qN7QljsR2AtHLRce3AcO9hdhpO" +
            "sJ9kHcxUqzEwQTAxMA0GCWCGSAFlAwQCAQUABCBR33V+E/mf3i3p3HOOBLpo61Ke83mJaQV0IUfiN0wdUgQIPXHjUI29ThsCAggA",
    )

    private val supported by lazy {
        probes.mapNotNull { (name, probe) ->
            runCatching {
                KeyStore.getInstance(
                    "PKCS12"
                ).load(ByteArrayInputStream(Base64.Default.decode(probe)), "probe".toCharArray())
            }.map { name }.getOrNull()
        }
    }

    // ASN.1 DER bytes: tag 0x06 (object identifier), then its length
    @Suppress("MagicNumber", "NestedBlockDepth")
    fun detect(data: ByteArray): List<String> {
        val found = linkedSetOf<String>()
        var index = 0
        while (index < data.size - 2) {
            if (data[index] == 0x06.toByte()) {
                val length = data[index + 1].toInt() and 0xff
                if (length in 1..20 && index + 2 + length <= data.size) {
                    decodeOid(data, index + 2, length)?.let { oid -> knownAlgorithms[oid]?.let(found::add) }
                }
            }
            index++
        }
        return found.toList()
    }

    fun supportsModernEncryption(): Boolean = MODERN_ENCRYPTION in supportedOnDevice()

    fun supportedOnDevice(): List<String> = supported

    val androidVersion: String get() = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"

    @Suppress("MagicNumber")
    private fun decodeOid(data: ByteArray, offset: Int, length: Int): String? {
        val first = data[offset].toInt() and 0xff
        val parts = mutableListOf(first / 40L, first % 40L)
        var value = 0L
        for (i in offset + 1 until offset + length) {
            val byte = data[i].toInt() and 0xff
            value = (value shl 7) or (byte and 0x7f).toLong()
            if (byte and 0x80 == 0) {
                parts += value
                value = 0
            }
        }
        if (value != 0L) return null
        return parts.joinToString(".")
    }
}
