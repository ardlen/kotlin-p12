package com.atom.sgwregistry.crypto

import com.atom.sgwregistry.asn1.AsnReader
import com.atom.sgwregistry.asn1.DerUtils
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import kotlinx.datetime.Instant

actual class SigningKey internal constructor(
    private val key: PrivateKey,
) {
    actual val native: Any get() = key

    internal fun asPrivateKey(): PrivateKey = key

    override fun equals(other: Any?): Boolean = other is SigningKey && key == other.key

    override fun hashCode(): Int = key.hashCode()
}

internal fun signingKeyFrom(privateKey: PrivateKey): SigningKey = SigningKey(privateKey)

actual object PlatformCrypto {
    private val certFactory: CertificateFactory by lazy {
        CertificateFactory.getInstance("X.509")
    }

    actual fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    actual fun parseCertificate(der: ByteArray): PlatformCertificate {
        val cert = loadCertificate(der)
        return cert.toPlatformCertificate(der)
    }

    actual fun parseEcPrivateKey(pemOrDer: ByteArray): SigningKey {
        val der = PemEncoding.decodePemOrDer(pemOrDer)
        val label = if (PemEncoding.isPem(pemOrDer)) {
            PemEncoding.detectPemLabel(pemOrDer.decodeToString())
        } else {
            "EC PRIVATE KEY"
        }
        val sec1 = when (label) {
            "EC PRIVATE KEY" -> der
            "PRIVATE KEY" -> unwrapPkcs8PrivateKey(der)
            else -> throw IllegalArgumentException("Unsupported PEM key type: $label")
        }
        return signingKeyFrom(parseSec1EcKeyPair(sec1).private)
    }

    actual fun getSubjectKeyId(cert: PlatformCertificate): ByteArray =
        if (cert.subjectKeyId.isNotEmpty()) cert.subjectKeyId else getSubjectKeyIdFromDer(cert.der)

    actual fun signHashEcdsaDer(key: SigningKey, hash: ByteArray): ByteArray {
        val sig = Signature.getInstance("NONEwithECDSA")
        sig.initSign(key.asPrivateKey())
        sig.update(hash)
        return sig.sign()
    }

    actual fun verifyHashEcdsaDer(cert: PlatformCertificate, hash: ByteArray, sigDer: ByteArray): Boolean {
        val x509 = loadCertificate(cert.der)
        val sig = Signature.getInstance("NONEwithECDSA")
        sig.initVerify(x509.publicKey)
        sig.update(hash)
        return sig.verify(sigDer)
    }

    private fun loadCertificate(pemOrDer: ByteArray): X509Certificate {
        val der = PemEncoding.decodePemOrDer(pemOrDer)
        return certFactory.generateCertificate(der.inputStream()) as X509Certificate
    }

    private fun X509Certificate.toPlatformCertificate(der: ByteArray): PlatformCertificate {
        var skid = getSubjectKeyIdFromCert(this)
        return PlatformCertificate(
            subject = subjectX500Principal.name,
            issuer = issuerX500Principal.name,
            serialHex = serialNumber.toString(16),
            serialBytes = serialNumber.toByteArray(),
            issuerDer = issuerX500Principal.encoded,
            notBefore = Instant.fromEpochMilliseconds(notBefore.time),
            notAfter = Instant.fromEpochMilliseconds(notAfter.time),
            keyAlgorithm = keyAlgName(this),
            der = der,
            publicKeyDer = publicKey.encoded,
            subjectKeyId = skid,
        )
    }

    private fun keyAlgName(cert: X509Certificate): String = when (cert.publicKey.algorithm) {
        "EC", "ECDSA" -> "ECDSA"
        "RSA" -> "RSA"
        else -> cert.publicKey.algorithm
    }

    private fun getSubjectKeyIdFromCert(cert: X509Certificate): ByteArray {
        var ext = cert.getExtensionValue("2.5.29.14") ?: return byteArrayOf()
        while (ext.isNotEmpty() && ext[0].toInt() == DerUtils.TAG_OCTET_STRING) {
            val next = DerUtils.unwrapOctetString(ext) ?: break
            if (next.size >= ext.size) break
            ext = next
        }
        return ext
    }

    private fun getSubjectKeyIdFromDer(der: ByteArray): ByteArray =
        getSubjectKeyIdFromCert(loadCertificate(der))
}

internal fun parseEcKeyPairFromPem(pem: String): KeyPair {
    val label = PemEncoding.detectPemLabel(pem)
    val der = PemEncoding.decodePemBlock(pem, label)
    val sec1 = when (label) {
        "EC PRIVATE KEY" -> der
        "PRIVATE KEY" -> unwrapPkcs8PrivateKey(der)
        else -> throw IllegalArgumentException("Unsupported PEM key type: $label")
    }
    return parseSec1EcKeyPair(sec1)
}

private fun parseSec1EcKeyPair(der: ByteArray): KeyPair {
        val seq = AsnReader(der).readSequence()
        seq.readInteger()
        val privateKeyBytes = seq.readOctetString()
        var curveName = "secp256r1"
        seq.tryReadContextSpecific(0)?.let { params ->
            val oid = params.readObjectIdentifierString()
            curveName = namedCurveToJcaName(oid)
        }
        val ecSpec = ecParameterSpec(curveName)
        val privateKey = KeyFactory.getInstance("EC").generatePrivate(
            ECPrivateKeySpec(BigInteger(1, privateKeyBytes), ecSpec),
        )
        val publicKey = seq.tryReadContextSpecific(1)?.let { tag ->
            val tlv = tag.readEncodedValue()
            val pointBytes = readBitStringBytes(tlv)
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(decodeEcPoint(pointBytes, ecSpec), ecSpec))
        } ?: throw IllegalArgumentException("EC PRIVATE KEY must include publicKey [1]")
        return KeyPair(publicKey, privateKey)
}

private fun unwrapPkcs8PrivateKey(der: ByteArray): ByteArray {
        val seq = AsnReader(der).readSequence()
        seq.readInteger()
        seq.readSequence()
        return seq.readOctetString()
}

private fun ecParameterSpec(curveName: String): ECParameterSpec {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec(curveName))
        return params.getParameterSpec(ECParameterSpec::class.java)
}

private fun namedCurveToJcaName(oid: String): String = when (oid) {
        "1.2.840.10045.3.1.7", "1.3.132.0.10" -> "secp256r1"
        "1.3.132.0.34" -> "secp384r1"
        "1.3.132.0.35" -> "secp521r1"
        else -> "secp256r1"
}

private fun readBitStringBytes(tlv: ByteArray): ByteArray {
        val (_, nlen, ok) = DerUtils.parseLength(tlv, 1)
        if (!ok) return byteArrayOf()
        val start = 1 + nlen
        if (start >= tlv.size) return byteArrayOf()
        val unusedBits = tlv[start].toInt() and 0xFF
        require(unusedBits == 0) { "Non-zero unused bits in BIT STRING" }
        return tlv.copyOfRange(start + 1, tlv.size)
}

private fun decodeEcPoint(pointBytes: ByteArray, spec: ECParameterSpec): ECPoint {
        require(pointBytes.isNotEmpty() && pointBytes[0] == 0x04.toByte()) { "Expected uncompressed EC point" }
        val fieldSize = (spec.curve.field.fieldSize + 7) / 8
        val x = BigInteger(1, pointBytes.copyOfRange(1, 1 + fieldSize))
        val y = BigInteger(1, pointBytes.copyOfRange(1 + fieldSize, 1 + 2 * fieldSize))
        return ECPoint(x, y)
}
