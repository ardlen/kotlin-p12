@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package com.atom.sgwregistry

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.dataWithContentsOfFile
import platform.posix.memcpy

actual object TestFixtures {
    private fun bundleDir(): String = NSBundle.mainBundle.bundlePath?.trimEnd('/') ?: "."

    actual fun rootDir(): String = bundleDir()

    actual fun exists(relativePath: String): Boolean {
        val path = resolvePath(relativePath)
        return NSFileManager.defaultManager.fileExistsAtPath(path)
    }

    actual fun readBytes(relativePath: String): ByteArray {
        val path = resolvePath(relativePath)
        val data = NSData.dataWithContentsOfFile(path)
            ?: error("Test file not found: $relativePath (path=$path, bundle=${bundleDir()})")
        return data.toByteArray()
    }

    private fun resolvePath(relativePath: String): String {
        val normalized = relativePath.trimStart('/')
        val sibling = "${bundleDir()}/$normalized"
        if (NSFileManager.defaultManager.fileExistsAtPath(sibling)) {
            return sibling
        }
        val parts = normalized.split('/')
        if (parts.size >= 2) {
            val base = parts.last().substringBeforeLast('.')
            val ext = parts.last().substringAfterLast('.', "")
            NSBundle.mainBundle.pathForResource(base, ext)?.let { return it }
        } else {
            val base = normalized.substringBeforeLast('.')
            val ext = normalized.substringAfterLast('.', "")
            NSBundle.mainBundle.pathForResource(base, ext)?.let { return it }
        }
        return sibling
    }

    private fun NSData.toByteArray(): ByteArray {
        val len = length.toInt()
        if (len == 0) return byteArrayOf()
        val raw = bytes ?: error("NSData.bytes is null")
        return ByteArray(len).also { arr ->
            arr.usePinned { pinned ->
                memcpy(pinned.addressOf(0), raw, len.convert())
            }
        }
    }
}
