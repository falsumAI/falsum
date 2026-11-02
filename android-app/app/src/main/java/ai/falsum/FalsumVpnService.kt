package ai.falsum

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.random.Random

/**
 * FalsumVpnService — local, on-device tracker filtering.
 *
 * Modelled on the TrackerControl / NetGuard approach: a [VpnService] creates
 * a TUN interface, the app reads raw IP packets from it, inspects them
 * locally, and decides per-packet what happens:
 *
 *  - DNS queries to known tracker / stalkerware-C2 domains are sinkholed
 *    (answered locally with 0.0.0.0 — the request never leaves the phone).
 *  - Other UDP is forwarded through a protected socket.
 *  - TCP is relayed through a minimal userspace TCP state machine so the
 *    phone keeps working while every connection is visible to the user.
 *
 * NOTHING is sent to any server for "analysis". Filtering decisions use the
 * [TrackerList] shipped inside the APK. No root required.
 */
class FalsumVpnService : VpnService() {

    companion object {
        private const val TAG = "FalsumVpn"
        private const val CHANNEL_ID = "falsum_protection"

        const val ACTION_START = "ai.falsum.START_VPN"
        const val ACTION_STOP = "ai.falsum.STOP_VPN"

        // TUN interface addressing (private, local-only).
        private const val VPN_ADDRESS = "10.8.0.2"
        private const val VPN_DNS = "10.8.0.1"
        private const val VPN_ADDRESS_INT = (10 shl 24) or (8 shl 16) or 2
        private const val MTU = 1500

        // Upstream DNS used ONLY for non-blocked queries, via protected socket.
        private const val UPSTREAM_DNS = "1.1.1.1"

        private const val FLAG_FIN = 0x01
        private const val FLAG_SYN = 0x02
        private const val FLAG_RST = 0x04
        private const val FLAG_PSH = 0x08
        private const val FLAG_ACK = 0x10

        /** Live counters visible to MainActivity. */
        @Volatile var blockedTrackers: Long = 0
            private set
        @Volatile var forwardedPackets: Long = 0
            private set

        fun resetStats() {
            blockedTrackers = 0
            forwardedPackets = 0
        }
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var tunOut: FileOutputStream? = null
    @Volatile private var running = false

    private val threadPoolLock = Any()
    private var threadPool = Executors.newCachedThreadPool()
    private val tcpTable = ConcurrentHashMap<String, TcpRelay>()
    private val udpTable = ConcurrentHashMap<String, UdpRelay>()
    private val writeLock = Any()

    private lateinit var vault: VaultLogger

    // ------------------------------------------------------------------ lifecycle

    override fun onCreate() {
        super.onCreate()
        vault = VaultLogger(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        if (running) return START_STICKY
        try {
            startForegroundNotification()
            establishTun()
            running = true
            resetStats()
            synchronized(threadPoolLock) {
                if (threadPool.isShutdown) {
                    threadPool = Executors.newCachedThreadPool()
                }
            }
            threadPool.execute { packetLoop() }
            threadPool.execute { sessionSweeper() }
            vault.log("vpn", "Falsum VPN started")
            Log.i(TAG, "VPN started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN", e)
            stopVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked by system/user")
        vault.log("vpn", "VPN revoked")
        stopVpn()
        super.onRevoke()
    }

    private fun stopVpn() {
        running = false
        try { tunFd?.close() } catch (_: Exception) { }
        tunFd = null
        tunOut = null
        tcpTable.values.forEach { it.close() }
        tcpTable.clear()
        udpTable.values.forEach { it.close() }
        udpTable.clear()
        threadPool.shutdownNow()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    // ------------------------------------------------------------- setup

    private fun startForegroundNotification() {
        val mgr = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Falsum Protection", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val notification = builder
            .setContentTitle("Falsum")
            .setContentText("Blocking trackers on this device. Tap to open.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }
    }

    private fun establishTun() {
        val builder = Builder()
        builder.setSession("Falsum")
            .setMtu(MTU)
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(VPN_DNS)   // DNS goes through us so we can sinkhole trackers
            .addRoute("0.0.0.0", 0)  // route everything through the TUN
            .addDisallowedApplication(packageName) // don't loop our own traffic
        val fd = builder.establish() ?: throw IllegalStateException("VpnService.Builder.establish() returned null")
        tunFd = fd
        tunOut = FileOutputStream(fd.fileDescriptor)
        Log.i(TAG, "TUN established")
    }

    // ------------------------------------------------------------- packet loop

    private fun packetLoop() {
        val fd = tunFd ?: return
        val tunIn = FileInputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        Log.i(TAG, "Packet loop started")
        while (running) {
            val n = try {
                tunIn.read(buf)
            } catch (e: Exception) {
                if (running) Log.w(TAG, "TUN read error: ${e.message}")
                -1
            }
            if (n <= 0) {
                // Brief pause to avoid hot-spinning on errors.
                try { Thread.sleep(10) } catch (_: InterruptedException) { break }
                continue
            }
            try {
                handlePacket(buf, n)
            } catch (e: Exception) {
                Log.w(TAG, "handlePacket failed: ${e.message}")
            }
        }
        Log.i(TAG, "Packet loop ended")
    }

    /** Remove UDP sessions idle for > 60s so the table doesn't grow forever. */
    private fun sessionSweeper() {
        while (running) {
            try {
                Thread.sleep(30_000)
                val now = System.currentTimeMillis()
                val stale = udpTable.entries.filter { now - it.value.lastActivity > 60_000 }
                stale.forEach { (k, v) -> v.close(); udpTable.remove(k) }
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    private fun handlePacket(buf: ByteArray, len: Int) {
        if (len < 20) return
        val verIhl = buf[0].toInt() and 0xFF
        if (verIhl shr 4 != 4) return // IPv4 only
        val ihl = (verIhl and 0x0F) * 4
        if (len < ihl) return
        val protocol = buf[9].toInt() and 0xFF
        val srcIp = ipToInt(buf, 12)
        val dstIp = ipToInt(buf, 16)
        when (protocol) {
            6 -> handleTcp(buf, len, ihl, srcIp, dstIp)
            17 -> handleUdp(buf, len, ihl, srcIp, dstIp)
            else -> { /* ICMP etc: drop silently for now */ }
        }
    }

    // ------------------------------------------------------------- TCP

    private fun handleTcp(buf: ByteArray, len: Int, ipHl: Int, srcIp: Int, dstIp: Int) {
        if (len < ipHl + 20) return
        val t = ipHl
        val srcPort = getU16(buf, t)
        val dstPort = getU16(buf, t + 2)
        val seq = getU32(buf, t + 4)
        val ack = getU32(buf, t + 8)
        val flags = buf[t + 13].toInt() and 0xFF
        val dataOffset = ((buf[t + 12].toInt() and 0xFF) shr 4) * 4
        val payloadStart = t + dataOffset
        if (payloadStart > len) return
        val payload = buf.copyOfRange(payloadStart, len)

        val key = "$srcIp:$srcPort->$dstIp:$dstPort"
        val relay = tcpTable[key]
        if (relay != null) {
            relay.onClientPacket(flags, seq, ack, payload)
            return
        }
        // New connection: only accept SYN (drop stray packets).
        if (flags and FLAG_SYN != 0 && flags and FLAG_ACK == 0) {
            val r = TcpRelay(srcIp, srcPort, dstIp, dstPort)
            tcpTable[key] = r
            if (!r.start(seq)) {
                tcpTable.remove(key)
            }
        }
    }

    /**
     * Minimal userspace TCP relay: completes the handshake with the local
     * app, opens a real (protected) socket to the destination, and shuttles
     * bytes both ways with correct seq/ack bookkeeping.
     *
     * Simplified vs a full stack: requires in-order client segments and does
     * not implement window scaling, SACK, or retransmission timers. The
     * VS Code agent can harden this; the structure is correct.
     */
    private inner class TcpRelay(
        val clientIp: Int,
        val clientPort: Int,
        val serverIp: Int,
        val serverPort: Int
    ) {
        private val socket = Socket()
        private val lock = Any()
        @Volatile private var closed = false

        /** Next sequence number we will send to the client. */
        private var sndNxt: Long = 0
        /** Next sequence number we expect from the client. */
        private var rcvNxt: Long = 0
        /** Guard against answering a retransmitted FIN twice. */
        private var finSent = false

        val key = "$clientIp:$clientPort->$serverIp:$serverPort"

        /** Returns false if the real connection could not be opened (client gets RST). */
        fun start(clientSeq: Long): Boolean {
            return try {
                protect(socket) // bypass our own VPN or we'd loop forever
                socket.connect(InetSocketAddress(ipToString(serverIp), serverPort), 10_000)
                socket.soTimeout = 30_000
                rcvNxt = clientSeq + 1
                sndNxt = Random.nextLong(0, 0xFFFFFFFFL)
                sendToClient(ByteArray(0), FLAG_SYN or FLAG_ACK, sndNxt, rcvNxt)
                sndNxt += 1
                vault.log("tcp-open", "${ipToString(serverIp)}:$serverPort")
                threadPool.execute { relayServerToClient() }
                true
            } catch (e: Exception) {
                Log.w(TAG, "TCP connect failed ${ipToString(serverIp)}:$serverPort: ${e.message}")
                // Refuse cleanly so the app fails fast instead of hanging.
                sendToClient(ByteArray(0), FLAG_RST or FLAG_ACK, 0, clientSeq + 1)
                close()
                false
            }
        }

        fun onClientPacket(flags: Int, seq: Long, ack: Long, payload: ByteArray) {
            synchronized(lock) {
                if (closed) return
                if (flags and FLAG_RST != 0) {
                    close()
                    return
                }
                if (payload.isNotEmpty()) {
                    if (seq == rcvNxt) {
                        try {
                            socket.getOutputStream().write(payload)
                            socket.getOutputStream().flush()
                            rcvNxt += payload.size
                        } catch (e: Exception) {
                            close()
                            return
                        }
                    } else {
                        // Out-of-order: re-ACK what we expect (simplified, no buffering).
                        Log.w(TAG, "TCP out-of-order segment, re-acking")
                    }
                    sendToClient(ByteArray(0), FLAG_ACK, sndNxt, rcvNxt)
                } else if (flags and FLAG_FIN != 0) {
                    if (!finSent) {
                        rcvNxt += 1
                        sendToClient(ByteArray(0), FLAG_FIN or FLAG_ACK, sndNxt, rcvNxt)
                        sndNxt += 1
                        finSent = true
                    } else {
                        // Retransmitted FIN: just re-ACK, don't advance state.
                        sendToClient(ByteArray(0), FLAG_ACK, sndNxt, rcvNxt)
                    }
                    try { socket.shutdownOutput() } catch (_: Exception) { }
                }
                // Pure ACKs need no action.
            }
        }

        private fun relayServerToClient() {
            try {
                val inp = socket.getInputStream()
                val tmp = ByteArray(8192)
                while (!closed) {
                    val n = inp.read(tmp)
                    if (n < 0) break
                    val payload = tmp.copyOf(n)
                    synchronized(lock) {
                        if (!closed) {
                            sendToClient(payload, FLAG_PSH or FLAG_ACK, sndNxt, rcvNxt)
                            sndNxt += n
                            forwardedPackets++
                        }
                    }
                }
            } catch (e: Exception) {
                Log.d(TAG, "TCP relay read ended: ${e.message}")
            }
            synchronized(lock) {
                if (!closed) {
                    sendToClient(ByteArray(0), FLAG_FIN or FLAG_ACK, sndNxt, rcvNxt)
                    sndNxt += 1
                }
            }
            close()
        }

        /** Craft an IP/TCP packet back to the local app. Must hold [lock]. */
        private fun sendToClient(payload: ByteArray, flags: Int, seq: Long, ack: Long) {
            val pkt = buildTcpPacket(
                srcIp = serverIp, dstIp = clientIp,
                srcPort = serverPort, dstPort = clientPort,
                seq = seq, ack = ack, flags = flags, payload = payload
            )
            writeTun(pkt)
        }

        fun close() {
            synchronized(lock) {
                if (closed) return
                closed = true
            }
            try { socket.close() } catch (_: Exception) { }
            tcpTable.remove(key)
        }
    }

    // ------------------------------------------------------------- UDP + DNS

    private fun handleUdp(buf: ByteArray, len: Int, ipHl: Int, srcIp: Int, dstIp: Int) {
        if (len < ipHl + 8) return
        val u = ipHl
        val srcPort = getU16(buf, u)
        val dstPort = getU16(buf, u + 2)
        val payloadStart = u + 8
        if (payloadStart > len) return
        val payload = buf.copyOfRange(payloadStart, len)

        // DNS gets special handling: tracker domains are sinkholed locally.
        if (dstPort == 53) {
            handleDns(payload, srcIp, srcPort, dstIp)
            return
        }

        val key = "$srcIp:$srcPort->$dstIp:$dstPort"
        var relay = udpTable[key]
        if (relay == null) {
            relay = UdpRelay(key, dstIp, dstPort)
            udpTable[key] = relay
            relay.startReplyLoop(srcIp, srcPort)
        }
        relay.sendToServer(payload)
        forwardedPackets++
    }

    private fun handleDns(query: ByteArray, srcIp: Int, srcPort: Int, serverIp: Int) {
        val qname = parseDnsQueryName(query)
        if (qname != null && TrackerList.isTracker(qname)) {
            // Sinkhole: answer locally with 0.0.0.0. The query NEVER leaves the phone.
            blockedTrackers++
            vault.log("tracker-blocked", qname)
            Log.i(TAG, "Blocked tracker DNS: $qname")
            val resp = buildDnsSinkhole(query)
            if (resp != null) {
                writeTun(buildUdpPacket(serverIp, srcIp, 53, srcPort, resp))
            }
            return
        }
        // Allowed: forward to upstream DNS on a protected socket, off the TUN thread
        // so a slow resolver can't stall all traffic.
        val q = query.copyOf()
        threadPool.execute {
            var fwd: DatagramSocket? = null
            try {
                fwd = DatagramSocket()
                protect(fwd)
                fwd.soTimeout = 5_000
                fwd.send(DatagramPacket(q, q.size, InetAddress.getByName(UPSTREAM_DNS), 53))
                val rbuf = ByteArray(4096)
                val rp = DatagramPacket(rbuf, rbuf.size)
                fwd.receive(rp)
                val answer = rp.data.copyOf(rp.length)
                writeTun(buildUdpPacket(serverIp, srcIp, 53, srcPort, answer))
                forwardedPackets++
            } catch (e: Exception) {
                Log.w(TAG, "DNS forward failed: ${e.message}")
            } finally {
                try { fwd?.close() } catch (_: Exception) { }
            }
        }
    }

    /** Extract the QNAME from a DNS query. Null if malformed. */
    private fun parseDnsQueryName(query: ByteArray): String? {
        if (query.size < 12) return null
        val sb = StringBuilder()
        var i = 12
        var jumps = 0
        while (i < query.size) {
            val len = query[i].toInt() and 0xFF
            if (len == 0) break
            if (len and 0xC0 == 0xC0) {
                // Compression pointer: follow it (once is enough for queries).
                if (i + 1 >= query.size || ++jumps > 4) return null
                i = ((len and 0x3F) shl 8) or (query[i + 1].toInt() and 0xFF)
                continue
            }
            if (len > 63 || i + 1 + len > query.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(query, i + 1, len, Charsets.US_ASCII))
            i += 1 + len
        }
        return sb.toString().lowercase().takeIf { it.isNotEmpty() }
    }

    /**
     * Build a DNS response that sinkholes the query: one A record pointing
     * at 0.0.0.0. The app thinks DNS resolved; the tracker gets nothing.
     */
    private fun buildDnsSinkhole(query: ByteArray): ByteArray? {
        if (query.size < 12) return null
        // Find end of question section: QNAME + QTYPE(2) + QCLASS(2).
        var i = 12
        var jumps = 0
        while (i < query.size) {
            val len = query[i].toInt() and 0xFF
            if (len == 0) { i += 1; break }
            if (len and 0xC0 == 0xC0) { i += 2; break }
            if (len > 63 || i + 1 + len > query.size) return null
            if (++jumps > 8) return null
            i += 1 + len
        }
        if (i + 4 > query.size) return null
        val questionEnd = i + 4
        val resp = ByteArray(questionEnd + 16)
        query.copyInto(resp, 0, 0, questionEnd)
        resp[2] = 0x81.toByte() // QR=1, RD=1
        resp[3] = 0x80.toByte() // RA=1, RCODE=0
        putU16(resp, 6, 1)      // ANCOUNT = 1
        putU16(resp, 8, 0)      // NSCOUNT = 0
        putU16(resp, 10, 0)     // ARCOUNT = 0
        var o = questionEnd
        resp[o++] = 0xC0.toByte() // NAME: pointer to QNAME at offset 12
        resp[o++] = 0x0C.toByte()
        putU16(resp, o, 1); o += 2   // TYPE A
        putU16(resp, o, 1); o += 2   // CLASS IN
        putU32(resp, o, 60); o += 4  // TTL 60s
        putU16(resp, o, 4); o += 2   // RDLENGTH
        resp[o++] = 0; resp[o++] = 0; resp[o++] = 0; resp[o] = 0 // 0.0.0.0
        return resp
    }

    /** Generic UDP relay session with a background reply reader. */
    private inner class UdpRelay(
        val key: String,
        private val dstIp: Int,
        private val dstPort: Int
    ) {
        private val socket = DatagramSocket()
        @Volatile private var closed = false
        @Volatile var lastActivity: Long = System.currentTimeMillis()
            private set

        init {
            protect(socket) // bypass our own VPN
            socket.soTimeout = 30_000
        }

        fun sendToServer(payload: ByteArray) {
            lastActivity = System.currentTimeMillis()
            try {
                socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(ipToString(dstIp)), dstPort))
            } catch (e: Exception) {
                Log.w(TAG, "UDP send failed: ${e.message}")
            }
        }

        fun startReplyLoop(clientIp: Int, clientPort: Int) {
            threadPool.execute {
                val buf = ByteArray(8192)
                try {
                    while (!closed) {
                        val p = DatagramPacket(buf, buf.size)
                        socket.receive(p) // throws on timeout/close -> ends loop
                        val payload = p.data.copyOf(p.length)
                        // Reply as if from the original destination.
                        writeTun(buildUdpPacket(dstIp, clientIp, dstPort, clientPort, payload))
                        lastActivity = System.currentTimeMillis()
                        forwardedPackets++
                    }
                } catch (e: Exception) {
                    Log.d(TAG, "UDP relay ended: ${e.message}")
                }
            }
        }

        fun close() {
            closed = true
            try { socket.close() } catch (_: Exception) { }
        }
    }

    // ------------------------------------------------------------- packet builders

    private fun buildTcpPacket(
        srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int,
        seq: Long, ack: Long, flags: Int, payload: ByteArray
    ): ByteArray {
        val pkt = ByteArray(20 + 20 + payload.size)
        // IPv4 header
        pkt[0] = 0x45.toByte()
        pkt[1] = 0
        putU16(pkt, 2, pkt.size)
        putU16(pkt, 4, Random.nextInt(0, 65536))
        putU16(pkt, 6, 0x4000) // DF
        pkt[8] = 64.toByte()   // TTL
        pkt[9] = 6.toByte()    // TCP
        putU16(pkt, 10, 0)
        putU32(pkt, 12, srcIp.toLong() and 0xFFFFFFFFL)
        putU32(pkt, 16, dstIp.toLong() and 0xFFFFFFFFL)
        putU16(pkt, 10, ipChecksum(pkt, 0, 20))
        // TCP header
        val t = 20
        putU16(pkt, t, srcPort)
        putU16(pkt, t + 2, dstPort)
        putU32(pkt, t + 4, seq)
        putU32(pkt, t + 8, ack)
        pkt[t + 12] = 0x50.toByte() // data offset 5, no options
        pkt[t + 13] = flags.toByte()
        putU16(pkt, t + 14, 65535)  // window
        putU16(pkt, t + 16, 0)
        putU16(pkt, t + 18, 0)
        payload.copyInto(pkt, t + 20)
        putU16(pkt, t + 16, tcpChecksum(srcIp, dstIp, pkt, t, 20 + payload.size))
        return pkt
    }

    private fun buildUdpPacket(
        srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int, payload: ByteArray
    ): ByteArray {
        val pkt = ByteArray(20 + 8 + payload.size)
        pkt[0] = 0x45.toByte()
        pkt[1] = 0
        putU16(pkt, 2, pkt.size)
        putU16(pkt, 4, Random.nextInt(0, 65536))
        putU16(pkt, 6, 0x4000)
        pkt[8] = 64.toByte()
        pkt[9] = 17.toByte() // UDP
        putU16(pkt, 10, 0)
        putU32(pkt, 12, srcIp.toLong() and 0xFFFFFFFFL)
        putU32(pkt, 16, dstIp.toLong() and 0xFFFFFFFFL)
        putU16(pkt, 10, ipChecksum(pkt, 0, 20))
        val u = 20
        putU16(pkt, u, srcPort)
        putU16(pkt, u + 2, dstPort)
        putU16(pkt, u + 4, 8 + payload.size)
        putU16(pkt, u + 6, 0) // UDP checksum optional for IPv4; zero = none
        payload.copyInto(pkt, u + 8)
        return pkt
    }

    private fun writeTun(pkt: ByteArray) {
        synchronized(writeLock) {
            try {
                tunOut?.write(pkt)
            } catch (e: Exception) {
                Log.w(TAG, "TUN write failed: ${e.message}")
            }
        }
    }

    // ------------------------------------------------------------- byte helpers

    private fun getU16(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun getU32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or
                ((b[o + 1].toLong() and 0xFF) shl 16) or
                ((b[o + 2].toLong() and 0xFF) shl 8) or
                (b[o + 3].toLong() and 0xFF)

    private fun putU16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 8).toByte()
        b[o + 1] = v.toByte()
    }

    private fun putU32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v ushr 24).toByte()
        b[o + 1] = (v ushr 16).toByte()
        b[o + 2] = (v ushr 8).toByte()
        b[o + 3] = v.toByte()
    }

    private fun ipToInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or
                ((b[o + 1].toInt() and 0xFF) shl 16) or
                ((b[o + 2].toInt() and 0xFF) shl 8) or
                (b[o + 3].toInt() and 0xFF)

    private fun ipToString(ip: Int): String =
        "${ip ushr 24}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"

    private fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < offset + length) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun tcpChecksum(srcIp: Int, dstIp: Int, pkt: ByteArray, tcpOffset: Int, tcpLen: Int): Int {
        var sum = 0L
        sum += (srcIp.toLong() ushr 16) and 0xFFFF
        sum += srcIp.toLong() and 0xFFFF
        sum += (dstIp.toLong() ushr 16) and 0xFFFF
        sum += dstIp.toLong() and 0xFFFF
        sum += 6       // protocol: TCP
        sum += tcpLen  // TCP length
        var i = tcpOffset
        val end = tcpOffset + tcpLen
        while (i < end - 1) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (pkt[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}
