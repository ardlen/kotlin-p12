package com.atom.sgwregistry.crypto

/** Platform cryptography: SHA-256, ECDSA (NONEwithECDSA), certificate and key import. */
expect object PlatformCrypto {
    fun sha256(data: ByteArray): ByteArray
    fun parseCertificate(der: ByteArray): PlatformCertificate
    fun parseEcPrivateKey(pemOrDer: ByteArray): SigningKey
    fun getSubjectKeyId(cert: PlatformCertificate): ByteArray
    fun signHashEcdsaDer(key: SigningKey, hash: ByteArray): ByteArray
    fun verifyHashEcdsaDer(cert: PlatformCertificate, hash: ByteArray, sigDer: ByteArray): Boolean
}
