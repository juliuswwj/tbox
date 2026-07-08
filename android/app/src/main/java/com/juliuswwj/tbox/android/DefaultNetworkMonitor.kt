package com.juliuswwj.tbox.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import com.juliuswwj.tbox.libbox.InterfaceUpdateListener
import com.juliuswwj.tbox.libbox.NetworkInterface as LibboxNetworkInterface
import com.juliuswwj.tbox.libbox.NetworkInterfaceIterator

/**
 * Bridges Android connectivity into libbox so route.auto_detect_interface can
 * bind the carrier socket to the real underlying network. Implements the two
 * PlatformInterface concerns: default-interface change notifications and
 * enumeration of interfaces.
 *
 * Uses ConnectivityManager.requestNetwork with a non-VPN filter so the default
 * interface reported to sing-box is always a physical network (wifi/cellular),
 * never the TUN VPN interface itself.
 */
class DefaultNetworkMonitor(context: Context) {

    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val callbacks = HashMap<InterfaceUpdateListener, ConnectivityManager.NetworkCallback>()
    private val knownNetworks = HashMap<Int, NetworkInfo>() // index -> info

    private data class NetworkInfo(
        val interfaceType: Int,
        var metered: Boolean,
    )

    fun start(listener: InterfaceUpdateListener) {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .apply {
                if (Build.VERSION.SDK_INT >= 29) {
                    addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                }
            }
            .build()

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) =
                update(listener, network, null, true)

            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) =
                update(listener, network, lp, false)

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                updateCaps(network, caps)

            override fun onLost(network: Network) {
                val lp = cm.getLinkProperties(network)
                val name = lp?.interfaceName ?: return
                val index = runCatching {
                    java.net.NetworkInterface.getByName(name)?.index ?: -1
                }.getOrDefault(-1)
                knownNetworks.remove(index)
                // If the lost network was the one we reported, fall back.
                listener.updateDefaultInterface("", -1, false, false)
            }
        }
        synchronized(callbacks) { callbacks[listener] = cb }
        cm.requestNetwork(request, cb)
    }

    fun close(listener: InterfaceUpdateListener) {
        val cb = synchronized(callbacks) { callbacks.remove(listener) } ?: return
        runCatching { cm.unregisterNetworkCallback(cb) }
    }

    private fun updateCaps(network: Network, caps: NetworkCapabilities) {
        val lp = cm.getLinkProperties(network) ?: return
        val name = lp.interfaceName ?: return
        val index = runCatching {
            java.net.NetworkInterface.getByName(name)?.index ?: -1
        }.getOrDefault(-1)
        if (index < 0) return
        knownNetworks[index]?.metered =
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
    }

    private fun update(listener: InterfaceUpdateListener, network: Network, linkProps: LinkProperties?, available: Boolean) {
        val caps: NetworkCapabilities? = cm.getNetworkCapabilities(network)

        // Safety: skip VPN networks even if the request filter above should
        // already exclude them (belt-and-suspenders for API < 29).
        if (Build.VERSION.SDK_INT >= 29 && caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
            return
        }

        val lp = linkProps ?: cm.getLinkProperties(network) ?: return
        val name = lp.interfaceName ?: return
        val index = runCatching { java.net.NetworkInterface.getByName(name)?.index ?: -1 }.getOrDefault(-1)
        if (index < 0) return

        val ifType = interfaceType(caps)
        val metered = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false

        if (available) {
            knownNetworks[index] = NetworkInfo(ifType, metered)
        }

        listener.updateDefaultInterface(name, index, metered, false)
    }

    private fun interfaceType(caps: NetworkCapabilities?): Int {
        if (caps == null) return INTERFACE_TYPE_OTHER
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> INTERFACE_TYPE_WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> INTERFACE_TYPE_CELLULAR
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> INTERFACE_TYPE_ETHERNET
            else -> INTERFACE_TYPE_OTHER
        }
    }

    /** Enumerate physical interfaces only (exclude TUN and loopback). */
    fun interfaces(): NetworkInterfaceIterator {
        val out = ArrayList<LibboxNetworkInterface>()
        val ifaces = runCatching { java.net.NetworkInterface.getNetworkInterfaces() }.getOrNull()
        while (ifaces != null && ifaces.hasMoreElements()) {
            val ni = ifaces.nextElement()
            if (ni.isLoopback || ni.name.startsWith("tun")) continue
            val info = knownNetworks[ni.index]
            val item = LibboxNetworkInterface()
            item.setIndex(ni.index)
            item.setMTU(runCatching { ni.mtu }.getOrDefault(0))
            item.setName(ni.name)
            item.setFlags(linkFlags(ni))
            item.setType(info?.interfaceType ?: INTERFACE_TYPE_OTHER)
            item.setAddresses(StringList(emptyList()))
            item.setDNSServer(StringList(emptyList()))
            item.setMetered(info?.metered ?: false)
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
        const val INTERFACE_TYPE_WIFI = 0
        const val INTERFACE_TYPE_CELLULAR = 1
        const val INTERFACE_TYPE_ETHERNET = 2
        const val INTERFACE_TYPE_OTHER = 3
    }
}
