package com.atom.sgwregistry.crypto

import java.io.File
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.X509Certificate

/** JVM-утилиты PEM/DER и загрузка из файлов. */
object PemUtils {
    fun loadCertificate(pemOrDer: ByteArray): X509Certificate {
        val der = PemEncoding.decodePemOrDer(pemOrDer)
        return java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(der.inputStream()) as X509Certificate
    }

    fun loadCertificateFromFile(path: String): X509Certificate =
        loadCertificate(File(path).readBytes())

    fun loadPrivateKey(path: String): PrivateKey = loadKeyPair(path).private

    fun loadPrivateKeyFromPem(pem: String): PrivateKey = loadKeyPairFromPem(pem).private

    fun loadKeyPair(path: String): KeyPair = loadKeyPairFromPem(File(path).readText())

    fun loadKeyPairFromPem(pem: String): KeyPair = parseEcKeyPairFromPem(pem)

    fun loadFirstPemBlock(path: String, label: String): ByteArray =
        loadFirstPemBlockFromString(File(path).readText(), label)

    fun loadFirstPemBlockFromString(pem: String, label: String): ByteArray =
        PemEncoding.decodePemBlock(pem, label)

    fun certToPem(certDer: ByteArray): String = PemEncoding.certToPem(certDer)

    fun getSubjectKeyId(cert: X509Certificate): ByteArray =
        PlatformCrypto.getSubjectKeyId(PlatformCrypto.parseCertificate(cert.encoded))

    fun decodeSkidHex(hex: String): ByteArray = PemEncoding.decodeSkidHex(hex)

    fun skidToHex(skid: ByteArray): String = PemEncoding.skidToHex(skid)

    fun signHashEcdsaDer(privateKey: PrivateKey, hash: ByteArray): ByteArray =
        PlatformCrypto.signHashEcdsaDer(signingKeyFrom(privateKey), hash)

    fun verifyHashEcdsaDer(cert: X509Certificate, hash: ByteArray, signatureDer: ByteArray): Boolean =
        PlatformCrypto.verifyHashEcdsaDer(PlatformCrypto.parseCertificate(cert.encoded), hash, signatureDer)
}
