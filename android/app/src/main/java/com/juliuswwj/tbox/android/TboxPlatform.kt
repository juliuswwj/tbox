package com.juliuswwj.tbox.android

import android.content.Context
import android.util.Log
import com.juliuswwj.tbox.libbox.InterfaceUpdateListener
import com.juliuswwj.tbox.libbox.LocalDNSTransport
import com.juliuswwj.tbox.libbox.NetworkInterfaceIterator
import com.juliuswwj.tbox.libbox.Notification
import com.juliuswwj.tbox.libbox.PlatformInterface
import com.juliuswwj.tbox.libbox.StringIterator
import com.juliuswwj.tbox.libbox.TunOptions
import com.juliuswwj.tbox.libbox.WIFIState

/**
 * PlatformInterface implementation handed to libbox. It wires sing-box's tun
 * runtime to Android: OpenTun builds the VpnService tun and returns its fd, and
 * AutoDetectInterfaceControl maps to VpnService.protect so the carrier socket to
 * the server bypasses the tunnel (no routing loop).
 */
class TboxPlatform(
    private val service: TboxVpnService,
    context: Context,
) : PlatformInterface {

    private val monitor = DefaultNetworkMonitor(context.applicationContext)

    override fun openTun(options: TunOptions): Int = service.createTun(options)

    override fun autoDetectInterfaceControl(fd: Int) {
        if (!service.protect(fd)) throw Exception("VpnService.protect($fd) failed")
    }

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) = monitor.start(listener)

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) = monitor.close(listener)

    override fun getInterfaces(): NetworkInterfaceIterator = monitor.interfaces()

    override fun writeLog(message: String) {
        Log.i("tbox", message)
    }

    override fun useProcFS(): Boolean = false

    // Process-owner lookups: our config uses no process rules, so these are not
    // exercised. Provide safe no-op behavior rather than crashing if they are.
    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): Int = -1

    override fun packageNameByUid(uid: Int): String = ""

    override fun uidByPackageName(packageName: String): Int = -1

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    // We run sing-box's own DNS; no Android platform DNS transport.
    override fun localDNSTransport(): LocalDNSTransport? = null

    override fun readWIFIState(): WIFIState? = null

    override fun systemCertificates(): StringIterator = StringList(emptyList())

    override fun clearDNSCache() {}

    override fun sendNotification(notification: Notification) {}
}
