/**
 * Иммутабельные копии байтовых полей [RegistryContainer] после разбора.
 */
package com.atom.sgwregistry.internal

internal fun ByteArray?.copyImmutable(): ByteArray? = this?.copyOf()

internal fun List<ByteArray>.copyImmutableList(): List<ByteArray> =
    map { it.copyOf() }

internal fun copySafeBagInfos(bags: List<com.atom.sgwregistry.model.SafeBagInfo>) =
    bags.map { bag ->
        bag.copy(
            localKeyId = bag.localKeyId?.copyOf(),
            certValueDer = bag.certValueDer?.copyOf(),
        )
    }
