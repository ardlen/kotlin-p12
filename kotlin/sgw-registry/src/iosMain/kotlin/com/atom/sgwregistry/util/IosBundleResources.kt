@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package com.atom.sgwregistry.util

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.Foundation.dataWithContentsOfFile
import platform.posix.memcpy

/**
 * Чтение файла из main bundle по относительному пути (`config.json`, `certs/signer.pem`, …).
 * iOS-only; для KMP-приложений.
 */
fun readMainBundleResource(relativePath: String, bundle: NSBundle = NSBundle.mainBundle): ByteArray {
    val slash = relativePath.lastIndexOf('/')
    val fileName = if (slash >= 0) relativePath.substring(slash + 1) else relativePath
    val name = fileName.substringBeforeLast('.')
    val ext = fileName.substringAfterLast('.')
    val subdir = if (slash >= 0) relativePath.substring(0, slash) else ""
    return if (subdir.isEmpty()) {
        readBundleResource(bundle, name, ext)
    } else {
        readBundleResourceInSubdir(bundle, name, ext, subdir)
            ?: readBundleResource(bundle, name, ext) // fallback: плоский bundle (Create Groups)
    }
}

private fun readBundleResource(bundle: NSBundle, name: String, ext: String): ByteArray {
    val filePath = bundle.pathForResource(name, ext)
        ?: error("Bundle resource not found: $name.$ext")
    return nsDataToBytes(NSData.dataWithContentsOfFile(filePath) ?: error("Failed to read $name.$ext"))
}

private fun readBundleResourceInSubdir(
    bundle: NSBundle,
    name: String,
    ext: String,
    subdir: String,
): ByteArray? {
    val filePath = bundle.pathForResource(name, ext, subdir) ?: return null
    return nsDataToBytes(NSData.dataWithContentsOfFile(filePath) ?: error("Failed to read $subdir/$name.$ext"))
}

private fun nsDataToBytes(data: NSData): ByteArray {
    val len = data.length.toInt()
    if (len == 0) return byteArrayOf()
    val raw = data.bytes ?: return byteArrayOf()
    return ByteArray(len).also { arr ->
        arr.usePinned { pinned ->
            memcpy(pinned.addressOf(0), raw, len.convert())
        }
    }
}
