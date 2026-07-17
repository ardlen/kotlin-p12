package com.atom.sgwregistry.examples

import com.atom.sgwregistry.crypto.PemEncoding
import java.io.ByteArrayInputStream
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

/**
 * JVM PKIX: проверка цепочки leaf → (intermediates) → trust anchors из `root_cas`.
 */
object JvmCertificateTrust {
    private val certFactory: CertificateFactory by lazy {
        CertificateFactory.getInstance("X.509")
    }

    fun loadX509(pemOrDer: ByteArray): X509Certificate {
        val der = PemEncoding.decodePemOrDer(pemOrDer)
        return certFactory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    fun loadX509(pem: String): X509Certificate = loadX509(pem.encodeToByteArray())

    /**
     * @param validationDate дата PKIX-проверки; по умолчанию «сейчас».
     *   Для короткоживущих stage-leaf можно передать `leaf.notBefore` / время подписи CMS.
     * @return Pair(ok, detail) — detail при успехе краткое описание пути, при ошибке сообщение.
     */
    fun verifyChain(
        leafDer: ByteArray,
        trustAnchorPems: List<String>,
        intermediatePems: List<String> = emptyList(),
        validationDate: Date? = null,
    ): Pair<Boolean, String> {
        require(trustAnchorPems.isNotEmpty()) { "trust anchors (root_cas) are empty" }
        val leaf = loadX509(leafDer)
        val anchors = trustAnchorPems.map { TrustAnchor(loadX509(it), null) }.toSet()
        val intermediates = intermediatePems.map { loadX509(it) }
        val at = validationDate ?: Date()

        return try {
            val pathCerts = buildList {
                add(leaf)
                addAll(intermediates)
            }
            val path = certFactory.generateCertPath(pathCerts)
            val params = PKIXParameters(anchors).apply {
                isRevocationEnabled = false
                date = at
            }
            CertPathValidator.getInstance("PKIX").validate(path, params)
            true to "PKIX OK: ${leaf.subjectX500Principal.name} → trust anchors (${anchors.size})"
        } catch (e: Exception) {
            false to (e.message ?: e::class.simpleName ?: "PKIX failed")
        }
    }
}
