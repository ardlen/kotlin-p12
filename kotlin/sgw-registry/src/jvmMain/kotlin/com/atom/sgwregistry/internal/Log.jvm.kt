package com.atom.sgwregistry.internal

import java.util.logging.Level
import java.util.logging.Logger

internal actual object Log {
    private val logger = Logger.getLogger("com.atom.sgwregistry")

    actual fun fine(message: String) {
        if (logger.isLoggable(Level.FINE)) logger.fine(message)
    }

    actual fun warn(message: String, cause: Throwable?) {
        if (cause != null) logger.log(Level.WARNING, message, cause)
        else logger.warning(message)
    }
}
