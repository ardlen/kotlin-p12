/** contentEquals для nullable ByteArray/IntArray в data class equals/hashCode. */
package com.atom.sgwregistry.internal

internal fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean =
    when {
        this === other -> true
        this == null || other == null -> false
        else -> this.contentEquals(other)
    }

internal fun IntArray?.contentEqualsNullable(other: IntArray?): Boolean =
    when {
        this === other -> true
        this == null || other == null -> false
        else -> this.contentEquals(other)
    }
