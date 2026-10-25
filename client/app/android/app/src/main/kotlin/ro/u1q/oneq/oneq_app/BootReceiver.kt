package ro.u1q.oneq.oneq_app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/** Starts the node after boot when the user enabled it (a saved config exists) and the VPN permission was granted. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!ConfigStore.exists(ctx)) return
        if (VpnService.prepare(ctx) != null) return // permission not granted: needs the app to ask first
        ctx.startForegroundService(Intent(ctx, OneqVpnService::class.java).setAction(OneqVpnService.ACTION_BOOT))
    }
}
