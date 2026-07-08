package com.juliuswwj.tbox.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.juliuswwj.tbox.libbox.TunOptions
import com.juliuswwj.tbox.mobile.Mobile
import com.juliuswwj.tbox.mobile.Options
import com.juliuswwj.tbox.mobile.Service

/**
 * VpnService that runs the embedded sing-box (VLESS-REALITY outbound behind a
 * tun inbound) via libbox. The whole connection lifecycle lives here; the UI
 * just starts/stops this service and observes [listener].
 */
class TboxVpnService : VpnService() {

    private var boxService: Service? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopVpn(null)
                return START_NOT_STICKY
            }
            else -> {
                val token = intent?.getStringExtra(EXTRA_TOKEN)?.takeIf { it.isNotBlank() }
                    ?: Prefs.token(this)
                startVpn(token)
            }
        }
        return START_STICKY
    }

    private fun startVpn(token: String) {
        if (boxService != null) return
        setState(State.CONNECTING, null)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(), type)
        try {
            tunIp = Mobile.defaultTunAddress()

            val opts = Options().apply {
                setLogLevel("info")
                setBasePath(filesDir.absolutePath)
                setWorkingPath(filesDir.absolutePath)
                setTempPath(cacheDir.absolutePath)
            }
            boxService = Mobile.start(token, opts, TboxPlatform(this, this))
            setState(State.CONNECTED, null)
        } catch (e: Exception) {
            Log.e("tbox", "start failed", e)
            stopVpn(e.message ?: e.toString())
        }
    }

    private fun stopVpn(error: String?) {
        runCatching { boxService?.close() }
        boxService = null
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        setState(State.IDLE, error)
        stopSelf()
    }

    /** Called back by libbox (via TboxPlatform.openTun) to establish the tun. */
    fun createTun(options: TunOptions): Int {
        val builder = Builder()
        builder.setMtu(options.getMTU())
        builder.setSession("tbox")

        addPrefixes(options.inet4Address) { addr, prefix -> builder.addAddress(addr, prefix) }
        addPrefixes(options.inet6Address) { addr, prefix -> builder.addAddress(addr, prefix) }

        if (options.autoRoute) {
            if (!addPrefixes(options.inet4RouteAddress) { a, p -> builder.addRoute(a, p) }) {
                builder.addRoute("0.0.0.0", 0)
            }
            val hasInet6 = options.inet6Address.hasNext()
            if (!addPrefixes(options.inet6RouteAddress) { a, p -> builder.addRoute(a, p) } && hasInet6) {
                builder.addRoute("::", 0)
            }
        }

        // Use a non-local address inside the TUN subnet as DNS. Android sends
        // DNS to the VPN's DNS server; if we set the TUN address itself
        // (198.18.0.1), the Linux stack delivers those packets locally
        // (no listener on :53), bypassing the TUN and the hijack-dns rule.
        // A sibling address (198.18.0.2) routes through the TUN and gets
        // intercepted correctly.
        val parts = tunIp.split("/")
        val ipParts = parts[0].split(".")
        val dnsAddr = "${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.${ipParts[3].toInt() + 1}"
        builder.addDnsServer(dnsAddr)

        // Never route our own traffic; the carrier socket is protected anyway.
        runCatching { builder.addDisallowedApplication(packageName) }

        val pfd = builder.establish() ?: throw IllegalStateException("VpnService.establish() returned null")
        return pfd.detachFd()
    }

    private inline fun addPrefixes(
        it: com.juliuswwj.tbox.libbox.RoutePrefixIterator,
        add: (String, Int) -> Unit,
    ): Boolean {
        var any = false
        while (it.hasNext()) {
            val p = it.next()
            add(p.address(), p.prefix())
            any = true
        }
        return any
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW),
            )
        }
        val disconnect = PendingIntent.getService(
            this, 0,
            Intent(this, TboxVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.notif_title))
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(0, getString(R.string.disconnect), disconnect)
            .build()
    }

    override fun onDestroy() {
        runCatching { boxService?.close() }
        boxService = null
        super.onDestroy()
    }

    enum class State { IDLE, CONNECTING, CONNECTED }

    companion object {
        const val ACTION_DISCONNECT = "com.juliuswwj.tbox.android.DISCONNECT"
        const val EXTRA_TOKEN = "token"
        private const val CHANNEL = "tbox"
        private const val NOTIF_ID = 1

        @Volatile
        var state: State = State.IDLE
            private set

        @Volatile
        var tunIp: String = ""
            private set

        /** UI observer; set by MainActivity while visible. (state, error) */
        var listener: ((State, String?) -> Unit)? = null

        private fun setStateStatic(s: State, error: String?) {
            state = s
            if (s == State.IDLE) tunIp = ""
            listener?.invoke(s, error)
        }

        fun start(context: Context, token: String) {
            Prefs.setToken(context, token)
            val i = Intent(context, TboxVpnService::class.java).putExtra(EXTRA_TOKEN, token)
            ContextCompat.startForegroundService(context, i)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, TboxVpnService::class.java).setAction(ACTION_DISCONNECT))
        }
    }

    private fun setState(s: State, error: String?) = setStateStatic(s, error)
}
