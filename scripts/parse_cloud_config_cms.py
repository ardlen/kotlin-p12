#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Разбор ATOM cloud_config_pem / TBOX CMS SignedData (-----BEGIN CMS-----).

Поток работы (удобно читать сверху вниз)
----------------------------------------
  1. load_der()              — PEM/DER → байты
  2. parse_content_info()    — ContentInfo → SignedData SEQUENCE
  3. parse_signed_data()     — поля SignedData по порядку RFC 5652:
       version → digestAlgs → encapContentInfo (JSON)
       → certificates → crls → signerInfos
  4. print_report()          — человекочитаемый отчёт

Почему не openssl cms
---------------------
sgw-registry кладёт certificates как SET { OCTET STRING(cert) },
а не SET OF Certificate. OpenSSL/asn1crypto падают; мы идём по TLV вручную.

Запуск (из корня репозитория)
-----------------------------
  python3 scripts/parse_cloud_config_cms.py kotlin-out/cloud-config-tbox-signed.pem
  python3 scripts/parse_cloud_config_cms.py … --trace          # пошаговый лог
  python3 scripts/parse_cloud_config_cms.py … --json-out /tmp/e.json --cert-out /tmp/s.pem
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Optional


# =============================================================================
# 0. Константы ASN.1 (чтобы в коде не было «магических» чисел)
# =============================================================================

class Tag:
    """UNIVERSAL-номера и часто используемые context-specific."""

    BOOLEAN = 1
    INTEGER = 2
    BIT_STRING = 3
    OCTET_STRING = 4
    NULL = 5
    OBJECT_ID = 6
    UTF8_STRING = 12
    SEQUENCE = 16
    SET = 17
    PRINTABLE_STRING = 19
    T61_STRING = 20
    IA5_STRING = 22
    UTC_TIME = 23
    GENERALIZED_TIME = 24
    BMP_STRING = 30

    CLASS_UNIVERSAL = 0
    CLASS_CONTEXT = 2

    # ContentInfo / SignedData / SignerInfo
    CTX_CONTENT = 0          # content [0] EXPLICIT
    CTX_CERTIFICATES = 0     # certificates [0]
    CTX_CRLS = 1             # crls [1]
    CTX_SKID = 0             # subjectKeyIdentifier [0]
    CTX_SIGNED_ATTRS = 0     # signedAttrs [0]
    CTX_ISSUER_SERIAL_ALT = 1  # вариант sgw-registry для IssuerAndSerial


OID_NAMES: dict[str, str] = {
    "1.2.840.113549.1.7.2": "pkcs7-signedData",
    "1.2.840.113549.1.7.1": "pkcs7-data",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.113549.1.9.3": "contentType",
    "1.2.840.113549.1.9.4": "messageDigest",
    "1.2.840.113549.1.9.5": "signingTime",
    "1.2.840.113549.1.9.52": "cmsAlgorithmProtection",
    "1.2.840.113549.1.9.16.2.47": "signingCertificateV2",
}

DN_ATTR_NAMES: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.1": "UID",
}


# =============================================================================
# 1. DER TLV — низкий уровень
# =============================================================================

@dataclass
class Tlv:
    """Один ASN.1/DER-элемент с привязкой к смещению в буфере."""

    tag: int
    tag_class: int
    constructed: bool
    value: bytes
    header_len: int
    offset: int

    @property
    def end(self) -> int:
        return self.offset + self.header_len + len(self.value)

    @property
    def content_offset(self) -> int:
        return self.offset + self.header_len

    def is_univ(self, tag: int) -> bool:
        return self.tag_class == Tag.CLASS_UNIVERSAL and self.tag == tag

    def is_ctx(self, tag: int) -> bool:
        return self.tag_class == Tag.CLASS_CONTEXT and self.tag == tag


def _read_len(data: bytes, i: int) -> tuple[int, int]:
    """Читает Length → (длина, индекс после поля length)."""
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    if n == 0 or n > 4:
        raise ValueError(f"unsupported DER length at {i - 1}")
    return int.from_bytes(data[i : i + n], "big"), i + n


def parse_tlv(data: bytes, offset: int = 0) -> Tlv:
    """Один TLV с data[offset]."""
    i = offset
    tag_byte = data[i]
    i += 1
    tag_class = tag_byte >> 6
    constructed = bool(tag_byte & 0x20)
    tag = tag_byte & 0x1F
    if tag == 0x1F:  # длинный номер тега
        tag = 0
        while True:
            b = data[i]
            i += 1
            tag = (tag << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    length, i = _read_len(data, i)
    return Tlv(tag, tag_class, constructed, data[i : i + length], i - offset, offset)


def iter_children(parent: Tlv, buf: bytes) -> Iterator[Tlv]:
    if not parent.constructed:
        return
    i = parent.content_offset
    while i < parent.end:
        child = parse_tlv(buf, i)
        yield child
        i = child.end


def children(parent: Tlv, buf: bytes) -> list[Tlv]:
    return list(iter_children(parent, buf))


def walk(buf: bytes, node: Tlv) -> Iterator[Tlv]:
    """Обход дерева в глубину."""
    yield node
    if node.constructed:
        for c in iter_children(node, buf):
            yield from walk(buf, c)


def oid_to_str(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    nums = [str(first // 40), str(first % 40)]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            nums.append(str(n))
            n = 0
    return ".".join(nums)


def oid_name(value: bytes) -> str:
    oid = oid_to_str(value)
    return OID_NAMES.get(oid, oid)


def algo_name(seq: Tlv, buf: bytes) -> str:
    """AlgorithmIdentifier SEQUENCE → имя OID."""
    for c in iter_children(seq, buf):
        if c.is_univ(Tag.OBJECT_ID):
            return oid_name(c.value)
    return "?"


# =============================================================================
# 2. Модель результата
# =============================================================================

@dataclass
class CmsReport:
    """Сводка по CMS (без проверки подписи)."""

    content_type: str = ""
    digest_algorithms: list[str] = field(default_factory=list)
    econtent: bytes = b""
    certificates_der: list[bytes] = field(default_factory=list)
    signer_sid: str = ""
    signature_algorithm: str = ""
    authenticated_attributes: list[tuple[str, Any]] = field(default_factory=list)
    signature_der: bytes = b""
    warnings: list[str] = field(default_factory=list)
    # заполняется при --trace
    trace: list[str] = field(default_factory=list)

    def note(self, msg: str, enabled: bool) -> None:
        if enabled:
            self.trace.append(msg)


# =============================================================================
# 3. Загрузка файла
# =============================================================================

def decode_pem_or_der(raw: bytes) -> bytes:
    """PEM (BEGIN CMS/…) → DER; иначе raw как DER."""
    text = raw.decode("ascii", errors="ignore")
    if "-----BEGIN" not in text:
        return raw
    lines = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.startswith("-----")
    ]
    return base64.b64decode("".join(lines))


def load_der(path: Path) -> bytes:
    return decode_pem_or_der(path.read_bytes())


# =============================================================================
# 4. Разбор CMS — отдельные шаги (по структуре RFC 5652)
# =============================================================================

def parse_content_info(der: bytes, report: CmsReport, trace: bool) -> Tlv:
    """
    Шаг A. ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT … }
    Возвращает SEQUENCE SignedData (внутренний).
    """
    root = parse_tlv(der, 0)
    if not (root.is_univ(Tag.SEQUENCE) and root.constructed):
        raise ValueError("ожидался ContentInfo SEQUENCE")

    kids = children(root, der)
    if len(kids) < 2:
        raise ValueError("ContentInfo слишком короткий")

    ct = kids[0]
    if not ct.is_univ(Tag.OBJECT_ID):
        raise ValueError("нет contentType OID")
    report.content_type = oid_name(ct.value)
    report.note(f"A. ContentInfo.contentType = {report.content_type}", trace)

    content = kids[1]
    if not (content.is_ctx(Tag.CTX_CONTENT) and content.constructed):
        raise ValueError("ожидался content [0] EXPLICIT")

    sd = parse_tlv(der, content.content_offset)
    report.note(
        f"A. SignedData SEQUENCE @ offset={sd.offset}, value_len={len(sd.value)}",
        trace,
    )
    return sd


def parse_digest_algorithms(
    fields: list[Tlv], idx: int, der: bytes, report: CmsReport, trace: bool
) -> int:
    """Шаг B. digestAlgorithms SET OF AlgorithmIdentifier."""
    if idx < len(fields) and fields[idx].is_univ(Tag.SET):
        for alg in iter_children(fields[idx], der):
            if alg.is_univ(Tag.SEQUENCE):
                name = algo_name(alg, der)
                report.digest_algorithms.append(name)
                report.note(f"B. digestAlgorithm = {name}", trace)
        return idx + 1
    return idx


def parse_encap_content_info(
    fields: list[Tlv], idx: int, der: bytes, report: CmsReport, trace: bool
) -> int:
    """
    Шаг C. EncapsulatedContentInfo — eContent = UTF-8 JSON TBOX.
      SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
    """
    if idx >= len(fields) or not fields[idx].is_univ(Tag.SEQUENCE):
        return idx

    eci = children(fields[idx], der)
    if eci and eci[0].is_univ(Tag.OBJECT_ID):
        eci_type = oid_name(eci[0].value)
        report.note(f"C. eContentType = {eci_type}", trace)
        if eci_type != "pkcs7-data":
            report.warnings.append(f"eContent type: {eci_type}")

    if len(eci) >= 2 and eci[1].is_ctx(0):
        inner = parse_tlv(der, eci[1].content_offset)
        report.econtent = inner.value
        if not inner.is_univ(Tag.OCTET_STRING):
            report.warnings.append("eContent not OCTET STRING")
        preview = report.econtent[:60].decode("utf-8", errors="replace")
        report.note(
            f"C. eContent = {len(report.econtent)} bytes, starts with: {preview!r}…",
            trace,
        )
    return idx + 1


def parse_certificates(
    fields: list[Tlv], idx: int, der: bytes, report: CmsReport, trace: bool
) -> int:
    """
    Шаг D. certificates [0] OPTIONAL.

    Стандарт: SET OF Certificate (SEQUENCE).
    sgw-registry: часто SET { OCTET STRING(cert DER) } — OpenSSL cms ломается.
    """
    if idx >= len(fields) or not fields[idx].is_ctx(Tag.CTX_CERTIFICATES):
        report.note("D. certificates — отсутствуют", trace)
        return idx

    node = fields[idx]
    if node.value and node.value[0] == 0x31:  # явный SET внутри
        items = children(parse_tlv(der, node.content_offset), der)
    else:
        items = children(node, der) if node.constructed else []

    for item in items:
        if item.is_univ(Tag.OCTET_STRING):
            report.certificates_der.append(item.value)
            report.warnings.append(
                "certificate encoded as OCTET STRING (non-standard; OpenSSL cms may fail)"
            )
            report.note(
                f"D. cert[{len(report.certificates_der)-1}] из OCTET STRING, "
                f"{len(item.value)} bytes",
                trace,
            )
        elif item.is_univ(Tag.SEQUENCE):
            report.certificates_der.append(der[item.offset : item.end])
            report.note(
                f"D. cert[{len(report.certificates_der)-1}] SEQUENCE, "
                f"{item.end - item.offset} bytes",
                trace,
            )
        else:
            report.warnings.append(
                f"skip certificate choice tag={item.tag_class}:{item.tag}"
            )
    return idx + 1


def parse_signer_identifier(sid: Tlv, der: bytes) -> str:
    """SignerIdentifier → строка для отчёта."""
    if sid.is_ctx(Tag.CTX_SKID):
        return f"subjectKeyIdentifier={sid.value.hex()}"

    # SEQUENCE (стандарт) или [1] EXPLICIT (вариант библиотеки)
    if sid.is_univ(Tag.SEQUENCE) or sid.is_ctx(Tag.CTX_ISSUER_SERIAL_ALT):
        node = parse_tlv(der, sid.content_offset) if sid.tag_class == Tag.CLASS_CONTEXT else sid
        parts = children(node, der)
        serial = ""
        cn = ""
        if len(parts) >= 2 and parts[1].is_univ(Tag.INTEGER):
            serial = parts[1].value.hex().upper()
        if parts:
            for t in walk(der, parts[0]):
                if t.is_univ(Tag.UTF8_STRING) and len(t.value) < 80:
                    try:
                        cn = t.value.decode("utf-8")
                    except UnicodeDecodeError:
                        pass
        return f"issuerAndSerial CN={cn!r} serial={serial}"

    return f"sid tag={sid.tag_class}:{sid.tag}"


def parse_signed_attributes(
    attrs_set: Tlv, der: bytes, report: CmsReport, trace: bool
) -> None:
    """signedAttrs [0] → contentType / signingTime / messageDigest / …"""
    if attrs_set.value and attrs_set.value[0] == 0x31:
        attr_items = children(parse_tlv(der, attrs_set.content_offset), der)
    else:
        attr_items = children(attrs_set, der)

    for attr in attr_items:
        if not attr.is_univ(Tag.SEQUENCE):
            continue
        ac = children(attr, der)
        if not ac or not ac[0].is_univ(Tag.OBJECT_ID):
            continue
        name = oid_name(ac[0].value)
        val: Any = None
        if len(ac) >= 2 and ac[1].is_univ(Tag.SET):
            vals = children(ac[1], der)
            if vals:
                v0 = vals[0]
                if name == "signingTime" and v0.tag in (Tag.UTC_TIME, Tag.GENERALIZED_TIME):
                    val = v0.value.decode("ascii", errors="replace")
                elif name == "messageDigest" and v0.is_univ(Tag.OCTET_STRING):
                    val = v0.value.hex()
                elif name == "contentType" and v0.is_univ(Tag.OBJECT_ID):
                    val = oid_name(v0.value)
                else:
                    val = f"tag={v0.tag} len={len(v0.value)}"
        report.authenticated_attributes.append((name, val))
        report.note(f"E. signedAttr {name} = {val}", trace)


def parse_signer_info(si: Tlv, der: bytes, report: CmsReport, trace: bool) -> None:
    """
    Шаг E. Один SignerInfo:
      version, sid, digestAlgorithm, signedAttrs?,
      signatureAlgorithm, signature
    """
    fields = children(si, der)
    fi = 0

    if fi < len(fields) and fields[fi].is_univ(Tag.INTEGER):
        fi += 1  # version

    if fi < len(fields):
        report.signer_sid = parse_signer_identifier(fields[fi], der)
        report.note(f"E. signer = {report.signer_sid}", trace)
        fi += 1

    if fi < len(fields) and fields[fi].is_univ(Tag.SEQUENCE):
        dig = algo_name(fields[fi], der)
        report.digest_algorithms.append(f"signerDigest={dig}")
        report.note(f"E. signerDigest = {dig}", trace)
        fi += 1

    if fi < len(fields) and fields[fi].is_ctx(Tag.CTX_SIGNED_ATTRS):
        parse_signed_attributes(fields[fi], der, report, trace)
        fi += 1

    if fi < len(fields) and fields[fi].is_univ(Tag.SEQUENCE):
        report.signature_algorithm = algo_name(fields[fi], der)
        report.note(f"E. signatureAlgorithm = {report.signature_algorithm}", trace)
        fi += 1

    if fi < len(fields) and fields[fi].is_univ(Tag.OCTET_STRING):
        report.signature_der = fields[fi].value
        report.note(f"E. signature = {len(report.signature_der)} bytes", trace)


def parse_signer_infos(
    fields: list[Tlv], idx: int, der: bytes, report: CmsReport, trace: bool
) -> int:
    """Шаг E. signerInfos SET — берём первого подписанта."""
    if idx >= len(fields) or not fields[idx].is_univ(Tag.SET):
        report.note("E. signerInfos — отсутствуют", trace)
        return idx

    for si in iter_children(fields[idx], der):
        if si.is_univ(Tag.SEQUENCE):
            parse_signer_info(si, der, report, trace)
            break
    return idx + 1


def parse_cms_signed_data(der: bytes, *, trace: bool = False) -> CmsReport:
    """
    Конвейер разбора ContentInfo → SignedData.

    Порядок полей SignedData (RFC 5652):
      version → digestAlgorithms → encapContentInfo
      → certificates[0]? → crls[1]? → signerInfos
    """
    report = CmsReport()
    sd = parse_content_info(der, report, trace)
    fields = children(sd, der)
    idx = 0

    # version INTEGER
    if idx < len(fields) and fields[idx].is_univ(Tag.INTEGER):
        report.note(f"B. version INTEGER @ field[{idx}]", trace)
        idx += 1

    idx = parse_digest_algorithms(fields, idx, der, report, trace)
    idx = parse_encap_content_info(fields, idx, der, report, trace)
    idx = parse_certificates(fields, idx, der, report, trace)

    # crls [1] — пропускаем
    if idx < len(fields) and fields[idx].is_ctx(Tag.CTX_CRLS):
        report.note("D'. crls — пропущены", trace)
        idx += 1

    parse_signer_infos(fields, idx, der, report, trace)
    return report


# =============================================================================
# 5. X.509 — краткая сводка сертификата (без внешних пакетов)
# =============================================================================

def _decode_asn1_string(tlv: Tlv) -> str:
    if tlv.tag in (Tag.UTF8_STRING, Tag.PRINTABLE_STRING, Tag.IA5_STRING):
        return tlv.value.decode("utf-8", errors="replace")
    if tlv.tag == Tag.BMP_STRING:
        return tlv.value.decode("utf-16-be", errors="replace")
    return tlv.value.hex()


def name_to_string(buf: bytes, name: Tlv) -> str:
    """Name (RDNSequence) → CN=…,O=…"""
    parts: list[str] = []
    for node in walk(buf, name):
        if not (node.is_univ(Tag.SEQUENCE) and node.constructed):
            continue
        kids = children(node, buf)
        if len(kids) < 2 or not kids[0].is_univ(Tag.OBJECT_ID):
            continue
        oid = oid_to_str(kids[0].value)
        val_tlv = kids[1]
        if val_tlv.constructed:
            nested = children(val_tlv, buf)
            val_tlv = nested[0] if nested else val_tlv
        if val_tlv.tag in (
            Tag.UTF8_STRING,
            Tag.PRINTABLE_STRING,
            Tag.IA5_STRING,
            Tag.BMP_STRING,
            Tag.T61_STRING,
        ):
            label = DN_ATTR_NAMES.get(oid, oid)
            parts.append(f"{label}={_decode_asn1_string(val_tlv)}")

    seen: set[str] = set()
    ordered: list[str] = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ",".join(ordered) if ordered else "(empty)"


def parse_time(tlv: Tlv) -> str:
    s = tlv.value.decode("ascii", errors="replace")
    if tlv.tag == Tag.UTC_TIME and len(s) >= 13:
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        return f"{year:04d}-{s[2:4]}-{s[4:6]}T{s[6:8]}:{s[8:10]}:{s[10:12]}+00:00"
    if tlv.tag == Tag.GENERALIZED_TIME and len(s) >= 15:
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}T{s[8:10]}:{s[10:12]}:{s[12:14]}+00:00"
    return s


def format_cert(der: bytes) -> str:
    """Certificate SEQUENCE { tbs, alg, sig } → текстовая сводка."""
    try:
        root = parse_tlv(der, 0)
        if not root.is_univ(Tag.SEQUENCE):
            return f"  (not a Certificate SEQUENCE; der={len(der)} bytes)"
        top = children(root, der)
        if not top:
            return "  (empty certificate)"

        fields = children(top[0], der)  # TBSCertificate
        fi = 0
        if fi < len(fields) and fields[fi].is_ctx(0):  # version [0]
            fi += 1

        serial = ""
        if fi < len(fields) and fields[fi].is_univ(Tag.INTEGER):
            serial = fields[fi].value.hex().upper().lstrip("0") or "0"
            fi += 1
        if fi < len(fields) and fields[fi].is_univ(Tag.SEQUENCE):  # signature alg
            fi += 1

        issuer = subject = ""
        not_before = not_after = ""
        if fi < len(fields) and fields[fi].is_univ(Tag.SEQUENCE):
            issuer = name_to_string(der, fields[fi])
            fi += 1
        if fi < len(fields) and fields[fi].is_univ(Tag.SEQUENCE):
            times = children(fields[fi], der)
            if times:
                not_before = parse_time(times[0])
            if len(times) >= 2:
                not_after = parse_time(times[1])
            fi += 1
        if fi < len(fields) and fields[fi].is_univ(Tag.SEQUENCE):
            subject = name_to_string(der, fields[fi])

        return "\n".join(
            [
                f"  subject: {subject}",
                f"  issuer:  {issuer}",
                f"  serial:  {serial}",
                f"  notBefore: {not_before}",
                f"  notAfter:  {not_after}",
            ]
        )
    except Exception as e:
        return f"  (cert parse failed: {e}; der={len(der)} bytes)"


# =============================================================================
# 6. Печать отчёта
# =============================================================================

def print_tbox_summary(obj: dict[str, Any]) -> None:
    ep = (obj.get("cloudBroker") or {}).get("endpoint") or {}
    print("--- summary ---")
    print(f"v: {obj.get('v')}")
    print(f"fqdnConstrAlg: {ep.get('fqdnConstrAlg')}")
    print(f"baseDomain: {ep.get('baseDomain')}")
    print(f"rootCAs: {len((obj.get('cloudBroker') or {}).get('rootCAs') or [])}")


def print_report(
    path: Path,
    report: CmsReport,
    *,
    raw_econtent: bool = False,
) -> int:
    """Печатает отчёт. 0 = OK, 1 = пустой eContent."""
    if report.trace:
        print("=== TRACE (шаги разбора) ===")
        for line in report.trace:
            print(f"  {line}")
        print()

    print(f"file: {path}")
    print(f"contentType: {report.content_type}")
    print(f"digestAlgorithms: {', '.join(report.digest_algorithms) or '-'}")
    print(f"signer: {report.signer_sid or '-'}")
    print(f"signatureAlgorithm: {report.signature_algorithm or '-'}")
    print(f"signature: {len(report.signature_der)} bytes")

    if report.authenticated_attributes:
        print("authenticatedAttributes:")
        for name, val in report.authenticated_attributes:
            print(f"  - {name}: {val}")

    print(f"certificates: {len(report.certificates_der)}")
    for i, cder in enumerate(report.certificates_der):
        print(f"[{i}]")
        print(format_cert(cder))

    if report.warnings:
        print("warnings:")
        for w in report.warnings:
            print(f"  - {w}")

    print("--- eContent ---")
    if not report.econtent:
        print("(empty)")
        return 1

    if raw_econtent:
        sys.stdout.buffer.write(report.econtent)
        if not report.econtent.endswith(b"\n"):
            print()
        return 0

    try:
        obj = json.loads(report.econtent.decode("utf-8"))
        print(json.dumps(obj, indent=2, ensure_ascii=False))
        if isinstance(obj, dict) and "cloudBroker" in obj:
            print_tbox_summary(obj)
    except json.JSONDecodeError:
        print(report.econtent.decode("utf-8", errors="replace")[:2000])
    return 0


def write_artifacts(
    report: CmsReport,
    json_out: Optional[Path],
    cert_out: Optional[Path],
) -> None:
    if json_out:
        json_out.write_bytes(report.econtent)
        print(f"wrote eContent → {json_out}")
    if cert_out and report.certificates_der:
        b64 = base64.encodebytes(report.certificates_der[0]).decode("ascii")
        cert_out.write_text(
            "-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n"
        )
        print(f"wrote signer cert → {cert_out}")


# =============================================================================
# 7. CLI
# =============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Разбор cloud_config CMS PEM/DER (TBOX / mob-dev cloud_config_pem)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Шаги разбора (--trace):
  A  ContentInfo / SignedData
  B  version + digestAlgorithms
  C  encapContentInfo (eContent JSON)
  D  certificates (+ предупреждение про OCTET STRING)
  E  signerInfos (sid, signedAttrs, signature)
""",
    )
    p.add_argument("path", type=Path, help="путь к .pem или .der")
    p.add_argument("--trace", action="store_true", help="пошаговый лог разбора")
    p.add_argument("--json-out", type=Path, help="записать eContent JSON")
    p.add_argument("--cert-out", type=Path, help="записать сертификат подписанта PEM")
    p.add_argument("--raw-econtent", action="store_true", help="eContent без pretty JSON")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    """
    Точка входа — короткий конвейер:

      load_der → parse_cms_signed_data → print_report → write_artifacts
    """
    args = build_arg_parser().parse_args(argv)

    der = load_der(args.path)
    report = parse_cms_signed_data(der, trace=args.trace)
    rc = print_report(args.path, report, raw_econtent=args.raw_econtent)
    write_artifacts(report, args.json_out, args.cert_out)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
