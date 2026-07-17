package com.atom.sgwregistry.model

import com.atom.sgwregistry.builder.RegistryBuilder
import com.atom.sgwregistry.crypto.SigningKey
import com.atom.sgwregistry.crypto.signingKeyFrom
import com.atom.sgwregistry.util.EPOCH_INSTANT
import com.atom.sgwregistry.util.parseRfc3339Instant
import java.security.PrivateKey
import java.security.cert.X509Certificate
import kotlinx.datetime.Instant

fun buildConfigFromJvm(
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    vin: String = "",
    verTimestamp: Instant = EPOCH_INSTANT,
    verVersion: Int = 0,
    uid: String = "",
    safeBags: List<SafeBagInput> = emptyList(),
): BuildConfig = BuildConfig(
    signerCertDer = signerCert.encoded,
    signerKey = signingKeyFrom(signerKey),
    vin = vin,
    verTimestamp = verTimestamp,
    verVersion = verVersion,
    uid = uid,
    safeBags = safeBags,
)

fun addCertificateRequestFromJvm(
    existingP12: ByteArray,
    newBag: SafeBagInput,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
    rejectDuplicateCert: Boolean = true,
): AddCertificateRequest = AddCertificateRequest(
    existingP12 = existingP12,
    newBag = newBag,
    signerCertDer = signerCert.encoded,
    signerKey = signingKeyFrom(signerKey),
    signerAttrs = signerAttrs,
    rejectDuplicateCert = rejectDuplicateCert,
)

fun removeCertificateBySkidRequestFromJvm(
    existingP12: ByteArray,
    subjectKeyId: ByteArray,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
    removeAllMatches: Boolean = false,
): RemoveCertificateBySkidRequest = RemoveCertificateBySkidRequest(
    existingP12 = existingP12,
    subjectKeyId = subjectKeyId,
    signerCertDer = signerCert.encoded,
    signerKey = signingKeyFrom(signerKey),
    signerAttrs = signerAttrs,
    removeAllMatches = removeAllMatches,
)

fun RegistryBuilder.addCertificateAndResign(
    existingP12: ByteArray,
    newBag: SafeBagInput,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
): ByteArray = addCertificateAndResign(
    addCertificateRequestFromJvm(
        existingP12 = existingP12,
        newBag = newBag,
        signerCert = signerCert,
        signerKey = signerKey,
        signerAttrs = signerAttrs,
    ),
)

fun RegistryBuilder.removeCertificateBySkidAndResign(
    existingP12: ByteArray,
    subjectKeyId: ByteArray,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
    removeAllMatches: Boolean = false,
): ByteArray = removeCertificateBySkidAndResign(
    removeCertificateBySkidRequestFromJvm(
        existingP12 = existingP12,
        subjectKeyId = subjectKeyId,
        signerCert = signerCert,
        signerKey = signerKey,
        signerAttrs = signerAttrs,
        removeAllMatches = removeAllMatches,
    ),
)

fun RegistryBuilder.removeCertificateBySkidAndResign(
    existingP12: ByteArray,
    subjectKeyIdHex: String,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    signerAttrs: SignerAttrs? = null,
    removeAllMatches: Boolean = false,
): ByteArray = removeCertificateBySkidAndResign(
    existingP12 = existingP12,
    subjectKeyIdHex = subjectKeyIdHex,
    signerCertDer = signerCert.encoded,
    signerKey = signingKeyFrom(signerKey),
    signerAttrs = signerAttrs,
    removeAllMatches = removeAllMatches,
)

fun RegistryBuilder.resignWithSafeBags(
    safeBags: List<SafeBagInput>,
    signerCert: X509Certificate,
    signerKey: PrivateKey,
    attrs: SignerAttrs,
): ByteArray = resignWithSafeBags(
    safeBags = safeBags,
    signerCertDer = signerCert.encoded,
    signerKey = signingKeyFrom(signerKey),
    attrs = attrs,
)

/** JVM helper for config loading — parses RFC3339 or returns [EPOCH_INSTANT]. */
fun parseRfc3339FromJvm(s: String?): Instant = parseRfc3339Instant(s)
