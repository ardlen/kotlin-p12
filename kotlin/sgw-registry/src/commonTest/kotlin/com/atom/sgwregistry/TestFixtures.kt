package com.atom.sgwregistry

expect object TestFixtures {
    fun rootDir(): String

    fun exists(relativePath: String): Boolean

    fun readBytes(relativePath: String): ByteArray
}
