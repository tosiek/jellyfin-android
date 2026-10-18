package org.jellyfin.mobile.tls

object TlsFixtures {
    const val PASSWORD = "jellyfin"
    const val UNICODE_PASSWORD = "zażółć-ü"

    val keyTypes = listOf("rsa2048", "rsa4096", "rsa1024", "ec256", "ec384", "ec521", "ed25519")
    val encryptions = listOf("aes", "legacy", "3des", "nopbe")

    fun read(path: String): ByteArray = requireNotNull(TlsFixtures::class.java.getResource("/tls/$path")) {
        "Missing fixture $path, run app/src/test/resources/tls/generate.sh"
    }.readBytes()
}
