package org.jellyfin.mobile.tls

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import org.jellyfin.mobile.tls.TlsFixtures.PASSWORD
import org.jellyfin.mobile.tls.TlsFixtures.read
import java.security.KeyStore

class CertificateImporterTests : FunSpec({
    context("CA formats") {
        val expectedCounts = mapOf(
            "ca/single.pem" to 1,
            "ca/bundle.pem" to 2,
            "ca/crlf.pem" to 1,
            "ca/bom.pem" to 1,
            "ca/with-text.pem" to 1,
            "ca/single.der" to 1,
            "ca/single.cer" to 1,
            "ca/bundle.p7b" to 2,
            "ca/bundle-der.p7b" to 2,
        )

        expectedCounts.forEach { (file, count) ->
            test("$file is parsed") {
                val parsed = CertificateImporter.parseCertificates(read(file))
                parsed.certificates shouldHaveSize count
                parsed.warnings.shouldBeEmpty()
            }
        }

        test("a leaf certificate is accepted with a warning") {
            val parsed = CertificateImporter.parseCertificates(read("ca/leaf-not-ca.pem"))
            parsed.certificates shouldHaveSize 1
            parsed.warnings.single().shouldBeInstanceOf<ImportWarning.NotCertificateAuthority>()
        }

        test("an expired CA is rejected") {
            shouldThrow<ImportException> { CertificateImporter.parseCertificates(read("ca/expired.pem")) }
                .error.shouldBeInstanceOf<ImportError.Expired>()
        }

        listOf("ca/garbage.bin", "ca/empty.pem", "ca/private-key-only.pem", "client/rsa2048-3des.p12").forEach { file ->
            test("$file is unrecognized") {
                shouldThrow<ImportException> { CertificateImporter.parseCertificates(read(file)) }
                    .error shouldBe ImportError.UnrecognizedFormat
            }
        }
    }

    context("PKCS#12 matrix") {
        TlsFixtures.keyTypes.forEach { keyType ->
            TlsFixtures.encryptions.forEach { encryption ->
                val file = "client/$keyType-$encryption.p12"
                test(file) {
                    val result = runCatching { CertificateImporter.parsePkcs12(read(file), PASSWORD.toCharArray()) }
                    withClue(result.exceptionOrNull()?.toString()) {
                        // The JDK PKCS#12 implementation ignores unencrypted key bags, Android is covered by the
                        // instrumented tests
                        val jvmLimitation = encryption == "nopbe" &&
                            (result.exceptionOrNull() as? ImportException)?.error is ImportError.UnsupportedEncryption
                        if (!jvmLimitation) {
                            when (keyType) {
                                "ed25519" -> (result.exceptionOrNull() as ImportException).error
                                    .shouldBeInstanceOf<ImportError.UnsupportedKeyType>()

                                "ec521" -> (result.exceptionOrNull() as ImportException).error shouldBe
                                    ImportError.UnsupportedKeyType("EC P-521")

                                "rsa1024" -> result.getOrThrow().warnings shouldContain ImportWarning.WeakKey(1024)

                                else -> {
                                    val parsed = result.getOrThrow()
                                    parsed.warnings.shouldBeEmpty()
                                    val subject = parsed.key.chain.first().subjectX500Principal.name
                                    subject.contains("client-$keyType") shouldBe true
                                    KeySelfTest.run(parsed.key.privateKey, parsed.key.chain.first()) shouldBe true
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    context("PKCS#12 variants") {
        test("empty password") {
            val parsed = CertificateImporter.parsePkcs12(read("client/rsa2048-empty-password.p12"), CharArray(0))
            parsed.key.chain shouldHaveSize 2
        }

        test("unicode password") {
            // Some Java versions (e.g. 21) can not read OpenSSL 3 files with a non-ASCII password at all, the import
            // then reports it like older Android versions do
            val data = read("client/rsa2048-unicode-password.p12")
            val password = TlsFixtures.UNICODE_PASSWORD.toCharArray()
            val readable = runCatching { KeyStore.getInstance("PKCS12").load(data.inputStream(), password) }.isSuccess
            if (readable) {
                CertificateImporter.parsePkcs12(data, password).key.chain shouldHaveSize 2
            } else {
                shouldThrow<ImportException> {
                    CertificateImporter.parsePkcs12(data, password)
                }.error shouldBe ImportError.WrongOrUnsupportedPassword
            }
        }

        test("wrong password") {
            shouldThrow<ImportException> {
                CertificateImporter.parsePkcs12(read("client/ec256-3des.p12"), "wrong".toCharArray())
            }.error shouldBe ImportError.WrongPassword
        }

        test("leaf only") {
            val parsed = CertificateImporter.parsePkcs12(read("client/ec256-leaf-only.p12"), PASSWORD.toCharArray())
            parsed.key.chain shouldHaveSize 1
        }

        test("CA certificate contained in the file") {
            val parsed = CertificateImporter.parsePkcs12(read("client/rsa2048-empty-password.p12"), CharArray(0))
            parsed.caCertificates shouldHaveSize 1
            parsed.caCertificates.first() shouldBe parsed.key.chain[1]
            (parsed.caCertificates.first().basicConstraints >= 0) shouldBe true
        }

        test("PKCS#12 picked as CA certificate: its CA and its client key") {
            val parsed = CertificateImporter.parsePkcs12Cas(read("client/rsa2048-empty-password.p12"), CharArray(0))
            parsed.certificates shouldHaveSize 1
            (parsed.certificates.first().basicConstraints >= 0) shouldBe true
            parsed.keyAliases shouldHaveSize 1
        }

        test("PKCS#12 without CA picked as CA certificate") {
            shouldThrow<ImportException> {
                CertificateImporter.parsePkcs12Cas(read("client/ec256-leaf-only.p12"), PASSWORD.toCharArray())
            }.error shouldBe ImportError.NoCaCertificate
        }

        test("PKCS#12 picked as CA certificate with a wrong password") {
            shouldThrow<ImportException> {
                CertificateImporter.parsePkcs12Cas(read("client/ec256-3des.p12"), "wrong".toCharArray())
            }.error shouldBe ImportError.WrongPassword
        }

        test("a PKCS#12 file is not a CA certificate file but may be PKCS#12") {
            val data = read("client/ec256-3des.p12")
            shouldThrow<ImportException> { CertificateImporter.parseCertificates(data) }.error shouldBe
                ImportError.UnrecognizedFormat
            CertificateImporter.mayBePkcs12(data) shouldBe true
            CertificateImporter.mayBePkcs12(read("client/pem-key-and-cert.pem")) shouldBe false
        }

        test("no CA certificate in a leaf-only file") {
            val parsed = CertificateImporter.parsePkcs12(read("client/ec256-leaf-only.p12"), PASSWORD.toCharArray())
            parsed.caCertificates.shouldBeEmpty()
        }

        test("reversed chain keeps the leaf first") {
            val parsed = CertificateImporter.parsePkcs12(
                read("client/ec256-reversed-chain.p12"),
                PASSWORD.toCharArray(),
            )
            parsed.key.chain.first().subjectX500Principal.name.contains("client-ec256") shouldBe true
        }

        test("certificate without key") {
            shouldThrow<ImportException> {
                CertificateImporter.parsePkcs12(read("client/cert-only.p12"), PASSWORD.toCharArray())
            }.error shouldBe ImportError.NoPrivateKey
        }

        test("two keys") {
            val data = read("client/two-keys.p12")
            val aliases = CertificateImporter.getPkcs12KeyAliases(data, PASSWORD.toCharArray())
            aliases.toSet() shouldBe setOf("first", "second")
            val second = CertificateImporter.parsePkcs12(data, PASSWORD.toCharArray(), "second")
            second.key.privateKey.algorithm shouldBe "RSA"
        }

        test("PEM key and certificate") {
            shouldThrow<ImportException> {
                CertificateImporter.parsePkcs12(read("client/pem-key-and-cert.pem"), PASSWORD.toCharArray())
            }.error shouldBe ImportError.NotPkcs12
        }

        test("garbage") {
            shouldThrow<ImportException> {
                CertificateImporter.parsePkcs12(read("ca/garbage.bin"), PASSWORD.toCharArray())
            }.error shouldBe ImportError.UnrecognizedFormat
        }

        test("format check without password") {
            shouldThrow<ImportException> {
                CertificateImporter.checkPkcs12Format(read("client/pem-key-and-cert.pem"))
            }.error shouldBe ImportError.NotPkcs12
            shouldThrow<ImportException> {
                CertificateImporter.checkPkcs12Format(read("ca/garbage.bin"))
            }.error shouldBe ImportError.UnrecognizedFormat
            // Encrypted PKCS#12 passes, the password is checked later
            CertificateImporter.checkPkcs12Format(read("client/ec256-3des.p12"))
        }
    }

    context("extra fixtures (jellyfin-desktop test cases)") {
        val p12 = { file: String, password: String ->
            runCatching { CertificateImporter.parsePkcs12(read("client/$file"), password.toCharArray()) }
        }

        test("CA with bag attributes") {
            CertificateImporter.parseCertificates(read("ca/extra-bag-attributes.pem")).certificates shouldHaveSize 1
        }

        test("CA bundle with comments") {
            val parsed = CertificateImporter.parseCertificates(read("ca/extra-bundle-comments.pem"))
            parsed.certificates shouldHaveSize 2
            parsed.warnings.single().shouldBeInstanceOf<ImportWarning.NotCertificateAuthority>()
        }

        test("RSA 8192") {
            val key = p12("extra-rsa8192-3des.p12", PASSWORD).getOrThrow().key
            KeySelfTest.run(key.privateKey, key.chain.first()) shouldBe true
        }

        test("brainpoolP256r1 is rejected although 256 bit") {
            val error = (p12("extra-brainpool256-3des.p12", PASSWORD).exceptionOrNull() as ImportException).error
            error.shouldBeInstanceOf<ImportError.UnsupportedKeyType>().keyType.contains("not P-256") shouldBe true
        }

        test("DSA is rejected") {
            (p12("extra-dsa2048-3des.p12", PASSWORD).exceptionOrNull() as ImportException).error shouldBe
                ImportError.UnsupportedKeyType("DSA")
        }

        test("ML-DSA is rejected") {
            // Readable by JDK 24 and newer, no TLS stack of Android offers ML-DSA signatures
            val error = (p12("extra-mldsa65-3des.p12", PASSWORD).exceptionOrNull() as ImportException).error
            (error is ImportError.UnsupportedKeyType || error == ImportError.UnreadableKey) shouldBe true
        }

        listOf("extra-ec256-aes128.p12", "extra-ec256-mac-sha512.p12", "extra-ec256-mac-sha384.p12").forEach { file ->
            test(file) { p12(file, PASSWORD).getOrThrow().key.chain.first().commonName() shouldBe "extra-ec256" }
        }

        test("PBES1 MD5 is either readable or reported as unsupported encryption") {
            val result = p12("extra-ec256-pbes1-md5.p12", PASSWORD)
            val unsupported = (result.exceptionOrNull() as? ImportException)?.error is ImportError.UnsupportedEncryption
            (result.isSuccess || unsupported) shouldBe true
        }

        // OpenSSL 3 legacy 3DES files with non-ASCII passwords can not be opened by Java (also not with the UTF-8 byte
        // variant OpenSSL accepts), explained instead of reported as plain wrong password
        test("UTF-8 password with legacy encryption") {
            val result = p12("extra-ec256-utf8-password.p12", "Pässwörd!123_üöä€")
            (result.exceptionOrNull() as ImportException).error shouldBe ImportError.WrongOrUnsupportedPassword
        }

        test("wrong ASCII password stays wrong password") {
            (p12("extra-ec256-utf8-password.p12", "wrong").exceptionOrNull() as ImportException).error shouldBe
                ImportError.WrongPassword
        }

        test("UTF-8 subject is shown as common name") {
            val leaf = p12("extra-utf8-subject-3des.p12", PASSWORD).getOrThrow().key.chain.first()
            leaf.commonName() shouldBe "Тестовый клиент ü€"
        }

        test("certificate without CN is shown with its subject") {
            val name = p12("extra-no-cn-3des.p12", PASSWORD).getOrThrow().key.chain.first().commonName()
            name.contains("No Common Name") shouldBe true
        }

        test("expired client certificate") {
            (p12("extra-expired-client-3des.p12", PASSWORD).exceptionOrNull() as ImportException).error
                .shouldBeInstanceOf<ImportError.Expired>()
        }
    }

    context("supported encryption probes") {
        test("the JVM reads all probe files") {
            Pkcs12Algorithms.supportedOnDevice() shouldBe
                listOf("3DES (SHA-1)", "RC2-40 (SHA-1)", "PBES2 / AES-256-CBC (PBKDF2)")
            Pkcs12Algorithms.supportsModernEncryption() shouldBe true
        }
    }

    context("algorithm detection") {
        test("OpenSSL 3 default") {
            val detected = Pkcs12Algorithms.detect(read("client/ec256-aes.p12"))
            detected shouldContain "PBES2"
            detected shouldContain "AES-256-CBC"
        }

        test("legacy") {
            val detected = Pkcs12Algorithms.detect(read("client/ec256-legacy.p12"))
            detected shouldContain "RC2-40 (SHA-1)"
            detected shouldContain "3DES (SHA-1)"
        }
    }
})
