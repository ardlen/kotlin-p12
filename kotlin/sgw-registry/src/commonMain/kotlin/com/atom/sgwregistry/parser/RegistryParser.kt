/**
 * Разбор ATOM-PKCS12-REGISTRY (.p12) в [RegistryContainer].
 */
package com.atom.sgwregistry.parser

import com.atom.sgwregistry.api.ParseOptions
import com.atom.sgwregistry.api.RegistryParserService
import com.atom.sgwregistry.asn1.AsnReader
import com.atom.sgwregistry.asn1.AttributeDecoder
import com.atom.sgwregistry.asn1.DerUtils
import com.atom.sgwregistry.asn1.Oids
import com.atom.sgwregistry.crypto.CertificateCache
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.internal.Log
import com.atom.sgwregistry.model.CertSummary
import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.model.SafeBagInfo
import com.atom.sgwregistry.util.instantToIsoString

object RegistryParser : RegistryParserService {
    private val pkcs7DataOidValue = byteArrayOf(
        0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x07, 0x01,
    )

    fun parse(p12Der: ByteArray): RegistryContainer = parse(p12Der, ParseOptions())

    /**
     * Разбор standalone CMS SignedData (ContentInfo), для `cloud_config_pem`.
     * Объект cloud configuration не требует обёртки PFX v3.
     */
    fun parseCms(cmsDer: ByteArray, options: ParseOptions = ParseOptions()): RegistryContainer {
        require(cmsDer.isNotEmpty()) { "Empty CMS data" }
        val warnings = ArrayList<String>()
        val cache = CertificateCache()
        val contentInfo = AsnReader(cmsDer).readSequence()
        val contentType = contentInfo.readObjectIdentifierString()
        require(Oids.oidEquals(contentType, Oids.pkcs7SignedData)) {
            "CMS contentType is not pkcs7-signedData: $contentType"
        }
        var signedDataDer = readContentValue(contentInfo) ?: throw IllegalStateException("Empty SignedData")
        if (signedDataDer.isEmpty() || signedDataDer[0].toInt() != DerUtils.TAG_SEQUENCE) {
            signedDataDer = DerUtils.prependTlv(DerUtils.TAG_SEQUENCE, signedDataDer)
        }
        signedDataDer = DerUtils.normalizeSignerInfosInSignedDataDer(signedDataDer)
        val raw = parseSignedData(signedDataDer, pfxVersion = 0, rawPfx = cmsDer, cache, warnings)
        if (options.strict && warnings.isNotEmpty()) {
            throw IllegalStateException("Strict parse failed: ${warnings.joinToString("; ")}")
        }
        return RegistryContainer.immutable(raw)
    }

    override fun parse(p12Der: ByteArray, options: ParseOptions): RegistryContainer {
        require(p12Der.isNotEmpty()) { "Empty PFX data" }
        val warnings = ArrayList<String>()
        val cache = CertificateCache()

        val pfx = AsnReader(p12Der).readSequence()
        val version = pfx.readInteger()
        require(version == 3) { "Unsupported PFX version: $version" }

        val contentInfo = when (pfx.peekTag()) {
            0xA0, 0x80 -> pfx.readContextSpecific(0).readSequence()
            else -> pfx.readSequence()
        }
        val contentType = contentInfo.readObjectIdentifierString()
        require(Oids.oidEquals(contentType, Oids.pkcs7SignedData)) {
            "authSafe contentType is not pkcs7-signedData: $contentType"
        }

        var signedDataDer = readContentValue(contentInfo) ?: throw IllegalStateException("Empty SignedData")
        if (signedDataDer.isEmpty() || signedDataDer[0].toInt() != DerUtils.TAG_SEQUENCE) {
            signedDataDer = DerUtils.prependTlv(DerUtils.TAG_SEQUENCE, signedDataDer)
        }
        signedDataDer = DerUtils.normalizeSignerInfosInSignedDataDer(signedDataDer)

        val raw = parseSignedData(signedDataDer, version, p12Der, cache, warnings)
        if (options.strict && warnings.isNotEmpty()) {
            throw IllegalStateException("Strict parse failed: ${warnings.joinToString("; ")}")
        }
        return RegistryContainer.immutable(raw)
    }

    private fun readContentValue(seq: AsnReader): ByteArray? {
        if (!seq.hasData()) return null
        val tag = seq.peekTag() ?: return null
        return when (tag) {
            0xA0, 0x80 -> unwrapOctet(seq.readContextSpecific(0).readEncodedValue())
            DerUtils.TAG_OCTET_STRING, DerUtils.TAG_CONSTRUCTED_OCTET_STRING ->
                unwrapOctet(seq.readEncodedValue())
            DerUtils.TAG_SEQUENCE -> seq.readEncodedValue()
            else -> unwrapOctet(seq.readEncodedValue())
        }
    }

    private fun unwrapOctet(tlvOrContent: ByteArray): ByteArray =
        DerUtils.unwrapOctetString(tlvOrContent) ?: tlvOrContent

    private fun parseSignedData(
        signedDataDer: ByteArray,
        pfxVersion: Int,
        rawPfx: ByteArray,
        cache: CertificateCache,
        warnings: MutableList<String>,
    ): RegistryContainer {
        val sd = AsnReader(signedDataDer).readSequence()
        sd.readInteger()
        if (sd.peekTag() == DerUtils.TAG_SET) sd.readSet()

        val encap = sd.readSequence()
        val eContentTypeOid = encap.readObjectIdentifierString()

        var eContentBytes: ByteArray? = null
        if (encap.hasData()) {
            eContentBytes = readContentValue(encap)
        }
        val fromReader = eContentBytes?.let { DerUtils.unwrapOctetString(it) ?: it }
        // Сканируем только если EncapsulatedContentInfo не дал eContent (для .p12 SafeContents).
        // Для mob-dev cloud_config_pem eContent — произвольные octets (JSON); скан по всему CMS очень дорогой.
        val needScan = fromReader == null || fromReader.isEmpty()
        val fromSignedData = if (needScan) scanForEContentAfterPkcs7DataOid(signedDataDer) else null
        val fromPfx = if (needScan && fromSignedData == null) scanForEContentAfterPkcs7DataOid(rawPfx) else null
        eContentBytes = when {
            fromReader != null && fromReader.isNotEmpty() -> fromReader
            fromSignedData != null && fromSignedData.isNotEmpty() -> fromSignedData
            fromPfx != null && fromPfx.isNotEmpty() -> fromPfx
            else -> fromReader ?: eContentBytes
        }

        var certsDer = emptyList<ByteArray>()
        sd.tryReadContextSpecific(0)?.let { certsTag ->
            val setBytes = certsTag.readEncodedValue()
            certsDer = parseCertificateSet(
                if (setBytes.isNotEmpty() && setBytes[0].toInt() == DerUtils.TAG_SET) setBytes
                else DerUtils.prependTlv(DerUtils.TAG_SET, setBytes),
                cache,
                warnings,
            )
        }

        var safeBags = emptyList<SafeBagInfo>()
        if (eContentBytes != null && eContentBytes.isNotEmpty() &&
            eContentBytes[0] == DerUtils.TAG_SEQUENCE.toByte()
        ) {
            safeBags = parseSafeContents(eContentBytes, cache, warnings)
        }

        var signerInfo = SignerParseResult()
        extractSignerInfoTlv(sd)?.let { siTlv ->
            signerInfo = parseSignerInfoSequence(siTlv, certsDer, cache, warnings)
        } ?: warnings.add("SignerInfo not found in SignedData")

        var signerCertDer = signerInfo.signerCertDer
        var signerResolved = signerInfo.signerCertResolved
        if (signerCertDer == null && certsDer.isNotEmpty()) {
            warnings.add("Signer certificate not resolved by SKID/issuerAndSerial; verify may fail")
            Log.warn("Signer certificate not resolved; no fallback to certs[0]")
        }

        return RegistryContainer(
            pfxVersion = pfxVersion,
            contentType = Oids.oidString(Oids.pkcs7SignedData),
            certificatesDer = certsDer,
            safeBagInfos = safeBags,
            signerCertDer = signerCertDer,
            eContentBytes = eContentBytes,
            authenticatedAttributesSetBytes = signerInfo.authAttrs,
            encryptedDigest = signerInfo.encryptedDigest,
            digestAlgorithmOid = signerInfo.digestOid,
            signatureAlgorithmOid = signerInfo.signatureOid,
            firstSignerSidTag = signerInfo.sidTag,
            signerCertResolved = signerResolved,
            parseWarnings = warnings.toList(),
        )
    }

    private data class SignerParseResult(
        val authAttrs: ByteArray? = null,
        val encryptedDigest: ByteArray? = null,
        val digestOid: IntArray? = null,
        val signatureOid: IntArray? = null,
        val sidTag: Int = 0,
        val signerCertDer: ByteArray? = null,
        val signerCertResolved: Boolean = false,
    )

    private fun parseCertificateSet(
        setBytes: ByteArray,
        cache: CertificateCache,
        warnings: MutableList<String>,
    ): List<ByteArray> {
        val list = ArrayList<ByteArray>()
        if (setBytes.isEmpty()) return list
        val tag = setBytes[0].toInt() and 0xFF
        when (tag) {
            DerUtils.TAG_SET -> {
                val set = AsnReader(setBytes).readSet()
                while (set.hasData()) {
                    extractCertificateDer(set.readEncodedValue(), cache, warnings)?.let { list.add(it) }
                }
            }
            DerUtils.TAG_SEQUENCE -> {
                extractCertificateDer(setBytes, cache, warnings)?.let { list.add(it) }
            }
            else -> warnings.add("Unknown certificate container tag 0x${tag.toString(16)}")
        }
        return list
    }

    private fun extractCertificateDer(
        tlv: ByteArray,
        cache: CertificateCache,
        warnings: MutableList<String>,
    ): ByteArray? {
        val tag = tlv[0].toInt() and 0xFF
        val certDer = when (tag) {
            DerUtils.TAG_OCTET_STRING -> DerUtils.unwrapOctetString(tlv)
            DerUtils.TAG_SEQUENCE -> tlv
            else -> null
        } ?: return null
        if (cache.tryLoad(certDer) != null) return certDer
        if (tag == DerUtils.TAG_SEQUENCE) {
            try {
                val seq = AsnReader(certDer).readSequence()
                if (seq.hasData()) {
                    val inner = seq.readEncodedValue()
                    if (inner.isNotEmpty() && inner[0].toInt() == DerUtils.TAG_SEQUENCE &&
                        cache.tryLoad(inner) != null
                    ) {
                        return inner
                    }
                }
            } catch (_: Exception) {
                // fall through
            }
        }
        warnings.add("Skipped invalid certificate in SignedData (${certDer.size} bytes)")
        return null
    }

    private fun parseSafeContents(
        content: ByteArray,
        cache: CertificateCache,
        warnings: MutableList<String>,
    ): List<SafeBagInfo> {
        val list = ArrayList<SafeBagInfo>()
        try {
            val seq = AsnReader(content).readSequence()
            while (seq.hasData()) {
                val tlv = seq.readEncodedValue()
                if (tlv[0].toInt() == DerUtils.TAG_SEQUENCE) {
                    parseSafeBag(tlv, cache, warnings)?.let { list.add(it) }
                }
            }
        } catch (e: Exception) {
            warnings.add("SafeContents parse failed: ${e.message}")
            Log.warn("SafeContents parse failed", e)
        }
        return list
    }

    private fun parseSafeBag(
        bagTlv: ByteArray,
        cache: CertificateCache,
        warnings: MutableList<String>,
    ): SafeBagInfo? = try {
        val bag = AsnReader(bagTlv).readSequence()
        val bagId = bag.readObjectIdentifierString()
        val valueTag = bag.readContextSpecific(0)
        var certValueDer: ByteArray? = null
        var certId = ""
        var certTypeName = ""
        if (Oids.oidEquals(bagId, Oids.certBag)) {
            val certBag = valueTag.readSequence()
            certId = certBag.readObjectIdentifierString()
            certTypeName = if (Oids.oidEquals(certId, Oids.x509Certificate)) "X.509 Certificate" else certId
            certValueDer = certBag.tryReadContextSpecific(0)?.readOctetString()
                ?: certBag.readOctetString()
        }
        var info = SafeBagInfo(
            certValueDer = certValueDer,
            bagId = bagId,
            certId = certId,
            certTypeName = certTypeName,
        )
        if (bag.hasData()) {
            val attrsSet = bag.readEncodedValue()
            info = applyBagAttributes(attrsSet, info, warnings)
        }
        if (certValueDer != null) {
            cache.tryLoad(certValueDer)?.let { cert ->
                info = info.copy(
                    certSummary = CertSummary(
                        subject = cert.subject,
                        issuer = cert.issuer,
                        serial = cert.serialHex,
                        notBefore = instantToIsoString(cert.notBefore),
                        notAfter = instantToIsoString(cert.notAfter),
                        keyAlg = cert.keyAlgorithm,
                    ),
                )
            }
        }
        info
    } catch (e: Exception) {
        warnings.add("SafeBag parse skipped: ${e.message}")
        Log.fine("SafeBag parse skipped: ${e.message}")
        null
    }

    private fun applyBagAttributes(setTlv: ByteArray, info: SafeBagInfo, warnings: MutableList<String>): SafeBagInfo =
        try {
            AttributeDecoder.applyBagAttributes(info, AttributeDecoder.parseBagAttributes(setTlv))
        } catch (e: Exception) {
            warnings.add("Bag attributes parse partial failure: ${e.message}")
            Log.fine("Bag attributes: ${e.message}")
            info
        }

    private fun extractSignerInfoTlv(sd: AsnReader): ByteArray? {
        while (sd.hasData()) {
            when (sd.peekTag()) {
                DerUtils.TAG_SET -> {
                    val set = sd.readSet()
                    if (set.hasData()) return set.readEncodedValue()
                }
                DerUtils.TAG_SEQUENCE -> return sd.readEncodedValue()
                0xA1, 0x81 -> {
                    val ctx = sd.readContextSpecific(1)
                    firstSignerInfoTlv(ctx)?.let { return it }
                }
                else -> sd.readEncodedValue()
            }
        }
        return null
    }

    private fun firstSignerInfoTlv(reader: AsnReader): ByteArray? = when (reader.peekTag()) {
        DerUtils.TAG_SEQUENCE -> reader.readEncodedValue()
        DerUtils.TAG_SET -> {
            val set = reader.readSet()
            if (!set.hasData()) null else firstSignerInfoTlv(AsnReader(set.readEncodedValue()))
                ?: set.readEncodedValue()
        }
        else -> null
    }

    private fun openSignerInfo(siTlv: ByteArray): AsnReader {
        var tlv = siTlv
        while (tlv.isNotEmpty() && tlv[0].toInt() == DerUtils.TAG_SET) {
            val set = AsnReader(tlv).readSet()
            if (!set.hasData()) break
            tlv = set.readEncodedValue()
        }
        return AsnReader(tlv).readSequence()
    }

    private fun parseSignerInfoSequence(
        siTlv: ByteArray,
        certs: List<ByteArray>,
        cache: CertificateCache,
        warnings: MutableList<String>,
    ): SignerParseResult {
        val si = openSignerInfo(siTlv)
        si.readInteger()
        var sidTag = 0
        var skid: ByteArray? = null
        var issuerDer: ByteArray? = null
        var serial: ByteArray? = null
        when (si.peekTag()) {
            DerUtils.TAG_SEQUENCE -> {
                sidTag = DerUtils.TAG_SEQUENCE
                val issSerial = si.readSequence()
                issuerDer = issSerial.readEncodedValue()
                serial = issSerial.readIntegerBytes()
            }
            0xA0, 0x80 -> {
                sidTag = 0xA0
                val ctx = si.readContextSpecific(0)
                skid = when (ctx.peekTag()) {
                    DerUtils.TAG_OCTET_STRING, DerUtils.TAG_CONSTRUCTED_OCTET_STRING -> ctx.readOctetString()
                    else -> {
                        val raw = ctx.readRemainingBytes()
                        DerUtils.unwrapOctetString(raw) ?: raw
                    }
                }
            }
            0xA1, 0x81 -> {
                sidTag = 0x81
                val issSerial = si.readContextSpecific(1).readSequence()
                issuerDer = issSerial.readEncodedValue()
                serial = issSerial.readIntegerBytes()
            }
        }

        val digestAlg = si.readSequence()
        val digestOid = digestAlg.readObjectIdentifier()
        if (digestAlg.hasData()) digestAlg.readNull()

        var authAttrs: ByteArray? = null
        si.tryReadContextSpecific(0)?.let { attrs ->
            authAttrs = when (attrs.peekTag()) {
                DerUtils.TAG_SET -> attrs.readEncodedValue()
                else -> {
                    val content = attrs.readRemainingBytes()
                    if (content.isEmpty()) null
                    else DerUtils.prependTlv(DerUtils.TAG_SET, content)
                }
            }
        }

        val signAlg = si.readSequence()
        val sigOid = signAlg.readObjectIdentifier()
        if (signAlg.hasData()) signAlg.readNull()

        val encDigest = si.readOctetString()

        var signerCertDer: ByteArray? = null
        var resolved = false
        if (skid != null && skid.isNotEmpty()) {
            for (certDer in certs) {
                val cert = cache.tryLoad(certDer) ?: continue
                if (PlatformCrypto.getSubjectKeyId(cert).contentEquals(skid)) {
                    signerCertDer = certDer
                    resolved = true
                    break
                }
            }
            if (!resolved) warnings.add("No certificate matches SignerInfo SKID")
        } else if (issuerDer != null && serial != null) {
            for (certDer in certs) {
                val cert = cache.tryLoad(certDer) ?: continue
                val issuerMatch = cert.issuerDer.contentEquals(issuerDer) ||
                    cert.issuerDer.contentEquals(
                        DerUtils.unwrapOctetString(issuerDer) ?: issuerDer,
                    )
                if (DerUtils.integerBytesEqual(cert.serialBytes, serial) && issuerMatch) {
                    signerCertDer = certDer
                    resolved = true
                    break
                }
            }
            if (!resolved) warnings.add("No certificate matches SignerInfo issuerAndSerial")
        }

        return SignerParseResult(authAttrs, encDigest, digestOid, sigOid, sidTag, signerCertDer, resolved)
    }

    private fun scanForEContentAfterPkcs7DataOid(data: ByteArray): ByteArray? {
        val oid = pkcs7DataOidValue
        val minTail = oid.size + 4
        if (data.size < minTail) return null
        val maxI = data.size - minTail
        var i = 0
        while (i <= maxI) {
            if (data[i].toInt() != 0x06) {
                i++
                continue
            }
            val oidLen = data[i + 1].toInt() and 0xFF
            if (oidLen != 0x08 && oidLen != 0x09) {
                i++
                continue
            }
            val oidStart = if (oidLen == 9) i + 3 else i + 2
            if (oidStart + oid.size > data.size) {
                i++
                continue
            }
            var match = true
            for (j in oid.indices) {
                if (data[oidStart + j] != oid[j]) {
                    match = false
                    break
                }
            }
            if (!match) {
                i++
                continue
            }
            val afterOid = i + 2 + oidLen
            if (afterOid >= data.size) return null
            val tag = data[afterOid].toInt() and 0xFF
            if (tag != 0xA0 && tag != 0x80) {
                i = oidStart
                continue
            }
            val (len, nlen, ok) = DerUtils.parseLength(data, afterOid + 1)
            if (!ok || len < 0) {
                i++
                continue
            }
            val valStart = afterOid + 1 + nlen
            if (valStart + len > data.size) {
                i++
                continue
            }
            val content = data.copyOfRange(valStart, valStart + len)
            val unwrapped = DerUtils.unwrapOctetString(content) ?: content
            if (unwrapped.isNotEmpty() && unwrapped[0] == DerUtils.TAG_SEQUENCE.toByte()) return unwrapped
            i = valStart + len
        }
        return null
    }
}
