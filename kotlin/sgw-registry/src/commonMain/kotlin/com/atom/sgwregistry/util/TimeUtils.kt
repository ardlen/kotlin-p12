package com.atom.sgwregistry.util

import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import kotlinx.datetime.toLocalDateTime

/** Epoch sentinel — поле не кодируется в CMS при сборке. */
val EPOCH_INSTANT: Instant = Instant.fromEpochSeconds(0)

fun isEpoch(instant: Instant): Boolean = instant == EPOCH_INSTANT

fun formatVerTimestamp(instant: Instant): String {
    val ldt = instant.toLocalDateTime(TimeZone.UTC)
    return buildString {
        append(ldt.year.toString().padStart(4, '0'))
        append('-')
        append(ldt.monthNumber.toString().padStart(2, '0'))
        append('-')
        append(ldt.dayOfMonth.toString().padStart(2, '0'))
        append(' ')
        append(ldt.hour.toString().padStart(2, '0'))
        append(':')
        append(ldt.minute.toString().padStart(2, '0'))
        append(':')
        append(ldt.second.toString().padStart(2, '0'))
    }
}

fun parseVerTimestamp(text: String): Instant {
    val parts = text.trim().split(' ', '-', ':')
    require(parts.size >= 6) { "Invalid timestamp: $text" }
    val year = parts[0].toInt()
    val month = parts[1].toInt()
    val day = parts[2].toInt()
    val hour = parts[3].toInt()
    val minute = parts[4].toInt()
    val second = parts[5].toInt()
    return LocalDateTime(year, month, day, hour, minute, second)
        .toInstant(TimeZone.UTC)
}

fun formatGeneralizedTimeUtc(instant: Instant): String {
    val ldt = instant.toLocalDateTime(TimeZone.UTC)
    return buildString {
        append(ldt.year.toString().padStart(4, '0'))
        append(ldt.monthNumber.toString().padStart(2, '0'))
        append(ldt.dayOfMonth.toString().padStart(2, '0'))
        append(ldt.hour.toString().padStart(2, '0'))
        append(ldt.minute.toString().padStart(2, '0'))
        append(ldt.second.toString().padStart(2, '0'))
        append('Z')
    }
}

/** ASN.1 UTCTime (tag 0x17): YYMMDDHHMMSSZ. */
fun formatUtcTimeUtc(instant: Instant): String {
    val ldt = instant.toLocalDateTime(TimeZone.UTC)
    val yy = (ldt.year % 100).toString().padStart(2, '0')
    return buildString {
        append(yy)
        append(ldt.monthNumber.toString().padStart(2, '0'))
        append(ldt.dayOfMonth.toString().padStart(2, '0'))
        append(ldt.hour.toString().padStart(2, '0'))
        append(ldt.minute.toString().padStart(2, '0'))
        append(ldt.second.toString().padStart(2, '0'))
        append('Z')
    }
}

fun parseGeneralizedTimeUtc(s: String): Instant {
    val normalized = s.trim().let { if (it.endsWith('Z')) it else "${it}Z" }
    require(normalized.length >= 15) { "Invalid GeneralizedTime: $s" }
    val year = normalized.substring(0, 4).toInt()
    val month = normalized.substring(4, 6).toInt()
    val day = normalized.substring(6, 8).toInt()
    val hour = normalized.substring(8, 10).toInt()
    val minute = normalized.substring(10, 12).toInt()
    val second = normalized.substring(12, 14).toInt()
    return LocalDateTime(year, month, day, hour, minute, second)
        .toInstant(TimeZone.UTC)
}

/** ASN.1 UTCTime (tag 0x17): YYMMDDHHMMSS[Z], year 00–49 → 2000–2049, 50–99 → 1950–1999. */
fun parseUtcTimeUtc(s: String): Instant {
    val normalized = s.trim().removeSuffix("Z")
    require(normalized.length == 12) { "Invalid UTCTime: $s" }
    val yy = normalized.substring(0, 2).toInt()
    val year = if (yy >= 50) 1900 + yy else 2000 + yy
    val month = normalized.substring(2, 4).toInt()
    val day = normalized.substring(4, 6).toInt()
    val hour = normalized.substring(6, 8).toInt()
    val minute = normalized.substring(8, 10).toInt()
    val second = normalized.substring(10, 12).toInt()
    return LocalDateTime(year, month, day, hour, minute, second)
        .toInstant(TimeZone.UTC)
}

fun parseRfc3339Instant(s: String?): Instant {
    if (s.isNullOrBlank()) return EPOCH_INSTANT
    return Instant.parse(s.trim())
}

fun instantToIsoString(instant: Instant): String = instant.toString()
