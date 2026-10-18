package org.jellyfin.mobile.tls

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class TlsEndpointTests : FunSpec({
    test("https without port defaults to 443") {
        TlsEndpoint.fromUrl("https://jf.example.com")?.key shouldBe "jf.example.com_443"
        TlsEndpoint.fromUrl("https://jf.example.com:443")?.key shouldBe "jf.example.com_443"
        TlsEndpoint.fromUrl("https://jf.example.com/web/index.html?x=1")?.key shouldBe "jf.example.com_443"
    }

    test("address without scheme is treated as https") {
        TlsEndpoint.fromUrl("jf.example.com")?.key shouldBe "jf.example.com_443"
        TlsEndpoint.fromUrl("jf.example.com:8920")?.key shouldBe "jf.example.com_8920"
    }

    test("different ports are different endpoints") {
        TlsEndpoint.fromUrl("https://h:8920") shouldNotBe TlsEndpoint.fromUrl("https://h")
    }

    test("http never has an endpoint") {
        TlsEndpoint.fromUrl("http://jf.example.com") shouldBe null
        TlsEndpoint.fromUrl("http://jf.example.com:8096") shouldBe null
    }

    test("host is normalized") {
        TlsEndpoint.fromUrl("https://JF.Example.COM.")?.key shouldBe "jf.example.com_443"
        TlsEndpoint.of("H.", 0)?.key shouldBe "h_443"
        TlsEndpoint.of("münchen.example", 443)?.key shouldBe "xn--mnchen-3ya.example_443"
    }

    test("hosts are not resolved") {
        val keys = listOf("localhost", "127.0.0.1", "::1").map { TlsEndpoint.of(it, 8920)?.key }
        keys shouldBe listOf("localhost_8920", "127.0.0.1_8920", "::1_8920")
    }

    test("IPv6 literals are canonicalized") {
        TlsEndpoint.fromUrl("https://[0:0:0:0:0:0:0:1]:8920")?.key shouldBe "::1_8920"
        TlsEndpoint.fromUrl("https://[2001:DB8:0:0:1:0:0:1]")?.key shouldBe "2001:db8::1:0:0:1_443"
        TlsEndpoint.of("[fe80::1%eth0]", 443)?.key shouldBe "fe80::1_443"
        TlsEndpoint.of("::1", 8920)?.display shouldBe "[::1]:8920"
    }

    test("keys round-trip") {
        listOf("jf.example.com_443", "127.0.0.1_8920", "::1_8920", "2001:db8::1_443").forEach { key ->
            TlsEndpoint.fromKey(key)?.key shouldBe key
        }
        TlsEndpoint.fromKey("no-port") shouldBe null
        TlsEndpoint.fromKey("host_99999") shouldBe null
    }

    test("WebView port -1 means 443") {
        TlsEndpoint.of("jf.example.com", -1)?.key shouldBe "jf.example.com_443"
    }
})
