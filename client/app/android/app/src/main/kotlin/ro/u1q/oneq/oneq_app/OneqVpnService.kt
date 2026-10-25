package ro.u1q.oneq.oneq_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import org.json.JSONObject
import java.net.InetAddress

/**
 * The oneq node as an Android foreground service: it owns the whole life cycle (login, VPN interface, engine, retry
 * after failures) so the node keeps running when the app is closed, shows a status-bar notification, and can start
 * at boot or as the system's always-on VPN. Only the mesh subnet is routed through the interface, so the core's own
 * sockets (relay, UDP to peers) use the normal network and need no `protect()`.
 */
class OneqVpnService : VpnService() {
    companion object {
        const val ACTION_START = "ro.1q.oneq.START"   // extras: config (JSON), persist (Boolean)
        const val ACTION_STOP = "ro.1q.oneq.STOP"
        const val ACTION_BOOT = "ro.1q.oneq.BOOT"     // start with the saved config, if any
        private const val CHANNEL = "oneq-status"
        private const val NOTIFICATION_ID = 1

        @Volatile var running = false
        @Volatile var lastError = ""
    }

    @Volatile private var stopping = false
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val cfg = intent.getStringExtra("config") ?: return START_NOT_STICKY
                if (intent.getBooleanExtra("persist", false)) ConfigStore.save(this, cfg) else ConfigStore.clear(this)
                begin(cfg)
            }
            else -> {
                // ACTION_BOOT, or the system's always-on VPN (an intent without our extras)
                val cfg = ConfigStore.load(this)
                if (cfg == null) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                begin(cfg)
            }
        }
        return START_STICKY
    }

    private fun begin(cfg: String) {
        startForegroundCompat(notification("Starting…"))
        if (running) return
        running = true
        stopping = false
        lastError = ""
        worker = Thread({ loop(cfg) }, "oneq-node").also { it.start() }
    }

    private fun loop(cfg: String) {
        var wait = 5000L
        while (!stopping) {
            if (NativeCore.prepare(cfg) != 0) {
                lastError = NativeCore.lastError()
                notify("Offline: $lastError")
                if (!sleep(wait)) break
                wait = minOf(wait * 2, 60000L)
                continue
            }
            wait = 5000L
            lastError = ""
            val st = JSONObject(NativeCore.status())
            val nets = routeNets(st)
            val pfd = buildInterface(st.getString("ip"), st.getInt("prefix"), st.getInt("mtu"), nets)
            if (pfd == null) {
                lastError = "The system refused to create the VPN interface (permission revoked?)."
                NativeCore.stop()
                break
            }
            if (NativeCore.run(pfd.detachFd()) != 0) {
                lastError = NativeCore.lastError()
                NativeCore.stop()
                if (!sleep(wait)) break
                continue
            }
            // supervise: leave when asked to stop, when the engine reports an error or when the routed networks change
            var rerouted = false
            while (!stopping) {
                val s = try { JSONObject(NativeCore.status()) } catch (e: Exception) { null }
                if (s != null) {
                    val peers = s.optJSONArray("peers")
                    var up = 0
                    for (i in 0 until (peers?.length() ?: 0)) if (peers!!.getJSONObject(i).optBoolean("session")) up++
                    if (s.optString("state") == "error") {
                        lastError = s.optString("message")
                        break
                    }
                    notify("${s.optString("ip")} · $up peer${if (up == 1) "" else "s"} connected")
                    // the VPN interface only carries the networks it was built with: build it again when the list changes
                    if (routeNets(s) != nets) {
                        rerouted = true
                        break
                    }
                }
                if (!sleep(3000)) break
            }
            NativeCore.stop()
            if (rerouted) continue
            if (!stopping && !sleep(wait)) break
        }
        NativeCore.stop()
        running = false
        if (stopping) stopSelfDelayed()
    }

    private fun sleep(ms: Long): Boolean {
        var left = ms
        while (left > 0 && !stopping) {
            Thread.sleep(minOf(left, 250))
            left -= 250
        }
        return !stopping
    }

    /** The networks routed through gateway members (accept_routes), as sorted "a.b.c.d/len" strings. */
    private fun routeNets(st: JSONObject): List<String> {
        val a = st.optJSONArray("route_nets") ?: return emptyList()
        return (0 until a.length()).map { a.getString(it) }.sorted()
    }

    private fun buildInterface(ip: String, prefix: Int, mtu: Int, routed: List<String>): ParcelFileDescriptor? = try {
        val addr = InetAddress.getByName(ip).address
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        val net = ByteArray(4) { i -> (addr[i].toInt() and (mask ushr (24 - 8 * i)) and 0xff).toByte() }
        val b = Builder()
            .setSession("oneq")
            .addAddress(ip, prefix)
            .addRoute(InetAddress.getByAddress(net).hostAddress!!, prefix)
            .setMtu(mtu)
        for (r in routed) {
            val (n, p) = r.split("/")
            b.addRoute(n, p.toInt())
        }
        b.establish()
    } catch (e: Exception) {
        null
    }

    private fun shutdown() {
        stopping = true
        NativeCore.stop()
        stopSelfDelayed()
    }

    private fun stopSelfDelayed() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ------------------------------------------------------------------ notification
    private fun notification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Connection status", NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 1, Intent(this, OneqVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE
        )
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL) else Notification.Builder(this)
        return b.setSmallIcon(R.drawable.ic_stat_oneq)
            .setContentTitle("oneq")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .build()
    }

    private var lastText = ""
    private fun notify(text: String) {
        if (text == lastText) return
        lastText = text
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    private fun startForegroundCompat(n: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    override fun onRevoke() {
        // another VPN took over, or the user switched this one off in the system settings
        lastError = "The VPN was revoked by the system."
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopping = true
        super.onDestroy()
    }
}
