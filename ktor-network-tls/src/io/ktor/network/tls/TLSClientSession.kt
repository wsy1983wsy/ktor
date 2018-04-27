package io.ktor.network.tls

import io.ktor.cio.*
import io.ktor.http.cio.internals.*
import io.ktor.network.sockets.*
import kotlinx.coroutines.experimental.channels.*
import kotlinx.coroutines.experimental.io.*
import kotlinx.io.core.*
import javax.net.ssl.*
import kotlin.coroutines.experimental.*

internal class TLSClientSession(
    rawInput: ByteReadChannel,
    rawOutput: ByteWriteChannel,
    private val coroutineContext: CoroutineContext,
    trustManager: X509TrustManager?,
    randomAlgorithm: String,
    serverName: String?
) : AReadable, AWritable {
    private var readerJob: ReaderJob? = null
    private var writerJob: WriterJob? = null

    private val handshaker = TLSClientHandshake(rawInput, rawOutput, trustManager, randomAlgorithm, serverName)
    private val input = handshaker.input
    private val output = handshaker.output

    suspend fun start() {
        handshaker.negotiate()
    }

    override fun attachForReading(channel: ByteChannel): WriterJob {
        writerJob = writer(coroutineContext, channel) {
            appDataInputLoop(this.channel)
        }
        return writerJob!!
    }

    override fun attachForWriting(channel: ByteChannel): ReaderJob {
        readerJob = reader(coroutineContext, channel) {
            appDataOutputLoop(this.channel)
        }
        return readerJob!!
    }

    private suspend fun appDataInputLoop(pipe: ByteWriteChannel) {
        input.consumeEach { record ->
            val packet = record.packet
            val length = packet.remaining
            when (record.type) {
                TLSRecordType.ApplicationData -> {
                    pipe.writePacket(record.packet)
                    pipe.flush()
                }
                else -> throw TLSException("Unexpected record ${record.type} ($length bytes)")
            }
        }
    }

    private suspend fun appDataOutputLoop(pipe: ByteReadChannel) = DefaultByteBufferPool.use { buffer ->
        while (true) {
            buffer.clear()
            val rc = pipe.readAvailable(buffer)
            if (rc == -1) break

            buffer.flip()
            output.send(TLSRecord(TLSRecordType.ApplicationData, packet = buildPacket { writeFully(buffer) }))
        }
    }
}
