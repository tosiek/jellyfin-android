package org.jellyfin.mobile.tls.ui

import java.net.ServerSocket
import kotlin.concurrent.thread

/**
 * Plain HTTP server for the "load from URL" flows serving the test fixtures.
 */
class TestFileServer(private val read: (String) -> ByteArray) : AutoCloseable {
    private val socket = ServerSocket(0)

    init {
        thread(isDaemon = true) {
            while (!socket.isClosed) {
                val client = runCatching { socket.accept() }.getOrNull() ?: break
                thread(isDaemon = true) {
                    runCatching {
                        client.use {
                            val path = it.getInputStream().bufferedReader().readLine().split(' ')[1].removePrefix("/")
                            val body = runCatching { read(path) }.getOrNull()
                            val status = if (body != null) "200 OK" else "404 Not Found"
                            it.getOutputStream().apply {
                                write("HTTP/1.1 $status\r\nContent-Length: ${body?.size ?: 0}\r\nConnection: close\r\n\r\n".toByteArray())
                                body?.let(::write)
                                flush()
                            }
                        }
                    }
                }
            }
        }
    }

    fun url(path: String) = "http://127.0.0.1:${socket.localPort}/$path"

    override fun close() = socket.close()
}
