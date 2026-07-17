package com.atom.sgwregistry.crypto

import java.security.PrivateKey

/** Обёртка JCA [PrivateKey] для [SigningKey] (desktop / JVM Keystore). */
fun signingKeyFromPrivateKey(privateKey: PrivateKey): SigningKey = signingKeyFrom(privateKey)
