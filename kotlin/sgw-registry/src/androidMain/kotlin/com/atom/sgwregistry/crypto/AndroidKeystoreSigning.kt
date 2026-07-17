package com.atom.sgwregistry.crypto

import java.security.KeyStore
import java.security.PrivateKey

/**
 * Обёртка JCA [PrivateKey] для подписи реестра.
 *
 * Подходит для ключей **Android Keystore** (в т.ч. non-exportable): PEM не нужен,
 * достаточно `KeyStore.getKey(alias)`.
 */
fun signingKeyFromPrivateKey(privateKey: PrivateKey): SigningKey = signingKeyFrom(privateKey)

/** Загрузить [SigningKey] по alias из `AndroidKeyStore`. */
fun signingKeyFromAndroidKeyStore(
    alias: String,
    keyStore: KeyStore = androidKeyStore(),
): SigningKey {
    val key = keyStore.getKey(alias, null) as? PrivateKey
        ?: throw IllegalArgumentException("No private key for alias: $alias")
    return signingKeyFromPrivateKey(key)
}

/** Открытый AndroidKeyStore (без пароля). */
fun androidKeyStore(): KeyStore =
    KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
