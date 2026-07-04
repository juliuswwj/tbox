package com.juliuswwj.tbox.android

import com.juliuswwj.tbox.libbox.NetworkInterface as LibboxNetworkInterface
import com.juliuswwj.tbox.libbox.NetworkInterfaceIterator
import com.juliuswwj.tbox.libbox.StringIterator

/** Adapts a Kotlin list into libbox's StringIterator. */
class StringList(private val items: List<String>) : StringIterator {
    private var i = 0
    override fun hasNext(): Boolean = i < items.size
    override fun len(): Int = items.size
    override fun next(): String = items[i++]
}

/** Adapts a Kotlin list into libbox's NetworkInterfaceIterator. */
class NetworkInterfaceList(private val items: List<LibboxNetworkInterface>) : NetworkInterfaceIterator {
    private var i = 0
    override fun hasNext(): Boolean = i < items.size
    override fun next(): LibboxNetworkInterface = items[i++]
}
