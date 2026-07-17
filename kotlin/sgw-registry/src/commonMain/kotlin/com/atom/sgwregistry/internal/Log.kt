package com.atom.sgwregistry.internal

internal expect object Log {
    fun fine(message: String)
    fun warn(message: String, cause: Throwable? = null)
}
