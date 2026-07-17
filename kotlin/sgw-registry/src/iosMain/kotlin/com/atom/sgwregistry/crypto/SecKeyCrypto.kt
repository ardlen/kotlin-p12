@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package com.atom.sgwregistry.crypto

import com.atom.sgwregistry.asn1.AsnReader
import com.atom.sgwregistry.asn1.DerUtils
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.kCFAllocatorDefault
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyCreateWithData
import platform.Security.SecKeyVerifySignature
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
import platform.posix.memcpy

private const val P256_FIELD_SIZE = 32
private const val P256_RAW_PRIVATE_KEY_SIZE = P256_FIELD_SIZE * 3 + 1

internal typealias SecKeyRef = platform.Security.SecKeyRef?

internal fun ByteArray.toCFData(): platform.CoreFoundation.CFDataRef? {
    if (isEmpty()) return CFDataCreate(kCFAllocatorDefault, null, 0)
    return usePinned { pinned ->
        CFDataCreate(
            kCFAllocatorDefault,
            pinned.addressOf(0).reinterpret<UByteVar>(),
            size.convert(),
        )
    }
}

internal fun createPrivateSecKey(sec1Der: ByteArray): SecKeyRef {
    val rawKey = sec1DerToAppleRawPrivateKey(sec1Der)
    return createSecKey(rawKey, kSecAttrKeyClassPrivate)
}

internal fun createPublicSecKeyFromSpki(spkiDer: ByteArray): SecKeyRef {
    val rawKey = spkiDerToAppleRawPublicKey(spkiDer)
    return createSecKey(rawKey, kSecAttrKeyClassPublic)
}

internal fun signDigestEcdsaDer(privateKey: SecKeyRef, digest: ByteArray): ByteArray = memScoped {
    val digestData = digest.toCFData() ?: throw IllegalStateException("Failed to create CFData for digest")
    try {
        val error = alloc<CFErrorRefVar>()
        val signature = SecKeyCreateSignature(
            privateKey,
            kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
            digestData,
            error.ptr,
        ) ?: throw IllegalStateException("SecKeyCreateSignature failed")
        signature.toByteArray()
    } finally {
        CFRelease(digestData)
    }
}

internal fun verifyDigestEcdsaDer(publicKey: SecKeyRef, digest: ByteArray, signatureDer: ByteArray): Boolean = memScoped {
    val digestData = digest.toCFData() ?: return false
    val sigData = signatureDer.toCFData() ?: return false
    try {
        val error = alloc<CFErrorRefVar>()
        SecKeyVerifySignature(
            publicKey,
            kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
            digestData,
            sigData,
            error.ptr,
        )
    } finally {
        CFRelease(digestData)
        CFRelease(sigData)
    }
}

internal fun secKeysEqual(a: SecKeyRef, b: SecKeyRef): Boolean {
    if (a == null || b == null) return a == b
    if (a === b) return true
    return secKeyExternalBytes(a).contentEquals(secKeyExternalBytes(b))
}

private fun secKeyExternalBytes(key: SecKeyRef): ByteArray = memScoped {
    val error = alloc<CFErrorRefVar>()
    val data = SecKeyCopyExternalRepresentation(key, error.ptr)
        ?: return byteArrayOf()
    try {
        data.toByteArray()
    } finally {
        CFRelease(data)
    }
}

private fun createSecKey(rawKey: ByteArray, keyClass: platform.CoreFoundation.CFTypeRef?): SecKeyRef = memScoped {
    val keyData = rawKey.toCFData() ?: throw IllegalStateException("Failed to create CFData for key")
    val attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 2, null, null)
        ?: throw IllegalStateException("Failed to create key attributes")
    try {
        CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(attributes, kSecAttrKeyClass, keyClass)
        val error = alloc<CFErrorRefVar>()
        SecKeyCreateWithData(keyData, attributes, error.ptr)
            ?: throw IllegalStateException("SecKeyCreateWithData failed")
    } finally {
        CFRelease(keyData)
        CFRelease(attributes)
    }
}

private fun sec1DerToAppleRawPrivateKey(sec1Der: ByteArray): ByteArray {
    val seq = AsnReader(sec1Der).readSequence()
    seq.readInteger()
    val privateKeyBytes = seq.readOctetString()
    seq.tryReadContextSpecific(0)
    val publicKeyBytes = seq.tryReadContextSpecific(1)?.let { tag ->
        readBitStringBytes(tag.readEncodedValue())
    } ?: throw IllegalArgumentException("EC PRIVATE KEY must include publicKey [1]")
    require(publicKeyBytes.isNotEmpty() && publicKeyBytes[0] == 0x04.toByte()) {
        "Expected uncompressed EC public key"
    }
    val rawKey = ByteArray(P256_RAW_PRIVATE_KEY_SIZE)
    publicKeyBytes.copyInto(rawKey, 0, 0, minOf(publicKeyBytes.size, P256_RAW_PRIVATE_KEY_SIZE))
    privateKeyBytes.copyInto(
        rawKey,
        destinationOffset = P256_RAW_PRIVATE_KEY_SIZE - privateKeyBytes.size,
        startIndex = 0,
        endIndex = privateKeyBytes.size,
    )
    return rawKey
}

private fun spkiDerToAppleRawPublicKey(spkiDer: ByteArray): ByteArray {
    val spki = AsnReader(spkiDer).readSequence()
    spki.readSequence()
    val pointBytes = readBitStringBytes(spki.readEncodedValue())
    require(pointBytes.isNotEmpty() && pointBytes[0] == 0x04.toByte()) {
        "Expected uncompressed EC public key in SPKI"
    }
    return pointBytes
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

private fun unwrapPkcs8PrivateKey(der: ByteArray): ByteArray {
    val seq = AsnReader(der).readSequence()
    seq.readInteger()
    seq.readSequence()
    return seq.readOctetString()
}

internal fun parseEcPrivateKeyDer(pemOrDer: ByteArray): SecKeyRef {
    val der = PemEncoding.decodePemOrDer(pemOrDer)
    val sec1 = if (PemEncoding.isPem(pemOrDer)) {
        val label = PemEncoding.detectPemLabel(pemOrDer.decodeToString())
        when (label) {
            "EC PRIVATE KEY" -> der
            "PRIVATE KEY" -> unwrapPkcs8PrivateKey(der)
            else -> throw IllegalArgumentException("Unsupported PEM key type: $label")
        }
    } else {
        der
    }
    return createPrivateSecKey(sec1)
}

private fun platform.CoreFoundation.CFDataRef.toByteArray(): ByteArray {
    val length = CFDataGetLength(this).toInt()
    if (length == 0) return byteArrayOf()
    val ptr = CFDataGetBytePtr(this) ?: return byteArrayOf()
    return ByteArray(length).also { bytes ->
        bytes.usePinned { pinned ->
            memcpy(pinned.addressOf(0), ptr, length.convert())
        }
    }
}
