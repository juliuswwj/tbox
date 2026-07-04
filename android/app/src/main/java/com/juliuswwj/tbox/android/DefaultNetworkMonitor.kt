package com.juliuswwj.tbox.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import com.juliuswwj.tbox.libbox.InterfaceUpdateListener
import com.juliuswwj.tbox.libbox.NetworkInterface as LibboxNetworkInterface
import com.juliuswwj.tbox.libbox.NetworkInterfaceIterator

/**
 * Bridges Android connectivity into libbox so route.auto_detect_interface can
 * bind the carrier socket to the real underlying network. Implements the two
 * PlatformInterface concerns: default-interface change notifications and
 * enumeration of interfaces.
 */
class DefaultNetworkMonitor(context: Context) {

    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val callbacks = HashMap<InterfaceUpdateListener, ConnectivityManager.NetworkCallback>()

    fun start(listener: InterfaceUpdateListener) {
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = update(listener, network, null)
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) =
                update(listener, network, lp)

            override fun onLost(network: Network) {
                listener.updateDefaultInterface("", -1, false, false)
            }
        }
        synchronized(callbacks) { callbacks[listener] = cb }
        cm.registerDefaultNetworkCallback(cb)
    }

    fun close(listener: InterfaceUpdateListener) {
        val cb = synchronized(callbacks) { callbacks.remove(listener) } ?: return
        runCatching { cm.unregisterNetworkCallback(cb) }
    }

    private fun update(listener: InterfaceUpdateListener, network: Network, linkProps: LinkProperties?) {
        val lp = linkProps ?: cm.getLinkProperties(network) ?: return
        val name = lp.interfaceName ?: return
        val index = runCatching { java.net.NetworkInterface.getByName(name)?.index ?: -1 }.getOrDefault(-1)
        val caps: NetworkCapabilities? = cm.getNetworkCapabilities(network)
        val expensive = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
        listener.updateDefaultInterface(name, index, expensive, false)
    }

    /**
     * Enumerate interfaces for libbox. Addresses are intentionally left empty:
     * libbox parses them with netip.MustParsePrefix (which panics on malformed
     * input such as zoned IPv6), and interface binding only needs name/index.
     */
    fun interfaces(): NetworkInterfaceIterator {
        val out = ArrayList<LibboxNetworkInterface>()
        val ifaces = runCatching { java.net.NetworkInterface.getNetworkInterfaces() }.getOrNull()
        while (ifaces != null && ifaces.hasMoreElements()) {
            val ni = ifaces.nextElement()
            val item = LibboxNetworkInterface()
            item.setIndex(ni.index)
            item.setMTU(runCatching { ni.mtu }.getOrDefault(0))
            item.setName(ni.name)
            item.setFlags(linkFlags(ni))
            item.setType(INTERFACE_TYPE_OTHER)
            item.setAddresses(StringList(emptyList()))
            item.setDNSServer(StringList(emptyList()))
            item.setMetered(false)
            out.add(item)
        }
        return NetworkInterfaceList(out)
    }

    private fun linkFlags(ni: java.net.NetworkInterface): Int {
        var f = 0
        runCatching {
            if (ni.isUp) f = f or IFF_UP or IFF_RUNNING
            if (ni.isLoopback) f = f or IFF_LOOPBACK
            if (ni.isPointToPoint) f = f or IFF_POINTOPOINT
            if (ni.supportsMulticast()) f = f or IFF_MULTICAST
            f = f or IFF_BROADCAST
        }
        return f
    }

    private companion object {
        // linux/uapi if.h IFF_* values; libbox decodes these into net.Flags.
        const val IFF_UP = 0x1
        const val IFF_BROADCAST = 0x2
        const val IFF_LOOPBACK = 0x8
        const val IFF_POINTOPOINT = 0x10
        const val IFF_RUNNING = 0x40
        const val IFF_MULTICAST = 0x1000
        const val INTERFACE_TYPE_OTHER = 3
    }
}
