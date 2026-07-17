package com.atom.sgwregistry.internal

private const val HEX = "0123456789abcdef"

internal fun byteToHex(b: Byte): String {
    val v = b.toInt() and 0xFF
    return "${HEX[v ushr 4]}${HEX[v and 0x0F]}"
}

internal fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString("") { byteToHex(it) }
