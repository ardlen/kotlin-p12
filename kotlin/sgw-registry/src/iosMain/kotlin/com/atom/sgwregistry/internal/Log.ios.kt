package com.atom.sgwregistry.internal

internal actual object Log {
    actual fun fine(message: String) {
        // no-op on iOS
    }

    actual fun warn(message: String, cause: Throwable?) {
        println("WARN [sgw-registry] $message${cause?.let { ": $it" } ?: ""}")
    }
}
