package ro.u1q.oneq.oneq_app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/** Channel `ro.1q.oneq/vpn`: the UI only asks the service to start/stop; status is polled through dart:ffi. */
class MainActivity : FlutterActivity() {
    private val vpnRequest = 7001
    private var pendingStart: Pair<String, Boolean>? = null
    private var pendingResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7002) // for the status-bar notification
        }
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "ro.1q.oneq/vpn").setMethodCallHandler { call, result ->
            when (call.method) {
                "filesDir" -> result.success(filesDir.absolutePath)
                "downloadsDir" -> result.success(
                    (getExternalFilesDir(android.os.Environment.DIRECTORY_DOWNLOADS) ?: filesDir).absolutePath
                )
                "start" -> {
                    val cfg = call.argument<String>("config")!!
                    val persist = call.argument<Boolean>("persist") ?: false
                    val intent = VpnService.prepare(this)
                    if (intent == null) {
                        startNode(cfg, persist)
                        result.success(true)
                    } else {
                        pendingStart = Pair(cfg, persist)
                        pendingResult = result
                        startActivityForResult(intent, vpnRequest)
                    }
                }
                "stop" -> {
                    startService(Intent(this, OneqVpnService::class.java).setAction(OneqVpnService.ACTION_STOP))
                    result.success(null)
                }
                "state" -> result.success(
                    mapOf("running" to OneqVpnService.running, "error" to OneqVpnService.lastError, "autostart" to ConfigStore.exists(this))
                )
                "forgetAutostart" -> {
                    ConfigStore.clear(this)
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun startNode(cfg: String, persist: Boolean) {
        startForegroundService(
            Intent(this, OneqVpnService::class.java).setAction(OneqVpnService.ACTION_START).putExtra("config", cfg).putExtra("persist", persist)
        )
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == vpnRequest) {
            val p = pendingStart
            val r = pendingResult
            pendingStart = null
            pendingResult = null
            if (p != null && r != null) {
                if (resultCode == Activity.RESULT_OK) {
                    startNode(p.first, p.second)
                    r.success(true)
                } else {
                    r.success(false)
                }
            }
            return
        }
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
    }
}
