package org.jellyfin.mobile.setup

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import org.jellyfin.sdk.api.client.exception.ApiClientException
import org.jellyfin.sdk.api.client.exception.InvalidContentException
import org.jellyfin.sdk.api.client.exception.InvalidStatusException
import org.jellyfin.sdk.api.client.exception.SecureConnectionException
import org.jellyfin.sdk.api.client.exception.TimeoutException
import java.io.IOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException

// Wrapped the way the SDK's OkHttp client wraps them
private fun timeout(cause: Throwable) = TimeoutException("Connection timed out", cause)

class ConnectionFailureTests : FunSpec({
    test("HTTP status codes") {
        ConnectionFailure.classify(InvalidStatusException(302)) shouldBe ConnectionFailure.Redirect(302)
        ConnectionFailure.classify(InvalidStatusException(308)) shouldBe ConnectionFailure.Redirect(308)
        ConnectionFailure.classify(InvalidStatusException(401)) shouldBe ConnectionFailure.AccessDenied(401)
        ConnectionFailure.classify(InvalidStatusException(403)) shouldBe ConnectionFailure.AccessDenied(403)
        ConnectionFailure.classify(InvalidStatusException(404)) shouldBe ConnectionFailure.NotFound
        ConnectionFailure.classify(InvalidStatusException(502)) shouldBe ConnectionFailure.ServerError(502)
        ConnectionFailure.classify(InvalidStatusException(418)) shouldBe ConnectionFailure.HttpStatus(418)
    }

    test("network causes inside the SDK timeout") {
        ConnectionFailure.classify(timeout(UnknownHostException("Unable to resolve host"))) shouldBe
            ConnectionFailure.UnknownHost
        ConnectionFailure.classify(timeout(ConnectException("Failed to connect to /10.0.2.2:1"))) shouldBe
            ConnectionFailure.Refused
        ConnectionFailure.classify(timeout(NoRouteToHostException("No route to host"))) shouldBe
            ConnectionFailure.Refused
        ConnectionFailure.classify(timeout(SocketTimeoutException("timeout"))) shouldBe ConnectionFailure.Timeout
        ConnectionFailure.classify(TimeoutException()) shouldBe ConnectionFailure.Timeout
    }

    test("TLS failures") {
        val handshake = SSLHandshakeException("Handshake failed").apply {
            initCause(CertificateException("Trust anchor for certification path not found."))
        }
        ConnectionFailure.classify(SecureConnectionException("Unknown SSL error", handshake)) shouldBe
            ConnectionFailure.Tls
        ConnectionFailure.classify(SecureConnectionException()) shouldBe ConnectionFailure.Tls
    }

    test("an answer that is not a Jellyfin server") {
        val error = InvalidContentException("Deserialization failed", SerializationException("x"))
        ConnectionFailure.classify(error) shouldBe ConnectionFailure.NotJellyfin
    }

    test("anything else has no mapped text") {
        val error = ApiClientException("Unknown IO error", IOException("unexpected end of stream"))
        ConnectionFailure.classify(error) shouldBe ConnectionFailure.Other
        ConnectionFailure.classify(IllegalStateException()) shouldBe ConnectionFailure.Other
    }

    test("raw cause is the deepest exception") {
        ConnectionFailure.rawCause(timeout(UnknownHostException("Unable to resolve host \"x.invalid\""))) shouldBe
            "UnknownHostException: Unable to resolve host \"x.invalid\""
        val handshake = SSLHandshakeException("Handshake failed").apply {
            initCause(CertificateException("Trust anchor for certification path not found."))
        }
        ConnectionFailure.rawCause(SecureConnectionException("Unknown SSL error", handshake)) shouldBe
            "CertificateException: Trust anchor for certification path not found."
        ConnectionFailure.rawCause(TimeoutException("Connection timed out", SocketTimeoutException())) shouldBe
            "SocketTimeoutException"
    }

    test("no raw cause for a bare HTTP status") {
        ConnectionFailure.rawCause(InvalidStatusException(302)) shouldBe null
    }
})
