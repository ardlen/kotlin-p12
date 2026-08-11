package com.atom.sgwregistry.examples

import com.atom.sgwregistry.csr.OwnershipCsr
import com.atom.sgwregistry.csr.OwnershipCsrRequest
import java.nio.file.Files
import java.nio.file.Path

/**
 * Генерация PKCS#10 Ownership CSR (SAN + EKU Email Protection) без BouncyCastle.
 *
 * ## Запуск
 *
 * ```bash
 * cd kotlin
 * ./gradlew :samples:registry-examples:runGen-ownership-csr
 *
 * # свои пути:
 * ./gradlew :samples:registry-examples:run --args="gen-ownership-csr \
 *   d231b684-82b4-4fdc-83dd-fc9a1861c293 certs/signer-key.pem kotlin-out/ownership.csr.pem"
 * ```
 *
 * SEC1 `EC PRIVATE KEY` должен содержать `publicKey [1]` (как у OpenSSL `-param_enc named_curve`).
 * После выдачи leaf CA проверьте `requireSignerEkuForCms` / `requireOwnerIdBinding`.
 */
object GenOwnershipCsrExample {
    fun run(
        ownerId: String,
        ecPrivateKeyPath: Path,
        outputCsrPemPath: Path,
        alsoIncludeClientAuth: Boolean = false,
    ) {
        SampleSupport.section("gen-ownership-csr — PKCS#10 Ownership")
        println("ownerId:  $ownerId")
        println("key:      $ecPrivateKeyPath")
        println("out:      $outputCsrPemPath")

        val keyBytes = SampleSupport.readBytes(
            SampleSupport.requireExists(ecPrivateKeyPath, "EC private key"),
        )
        val result = OwnershipCsr.buildFromEcPrivateKeyPem(
            OwnershipCsrRequest(
                ownerId = ownerId,
                includeEmailProtectionEku = true,
                includeClientAuthEku = alsoIncludeClientAuth,
            ),
            keyBytes,
        )

        Files.createDirectories(outputCsrPemPath.parent)
        Files.writeString(outputCsrPemPath, result.csrPem)
        val derPath = Path.of(outputCsrPemPath.toString().removeSuffix(".pem") + ".der")
            .let { if (it == outputCsrPemPath) outputCsrPemPath.resolveSibling("ownership.csr.der") else it }
        Files.write(derPath, result.csrDer)

        println("SAN:      ${result.sanUri}")
        println("CSR PEM:  $outputCsrPemPath (${result.csrPem.length} chars)")
        println("CSR DER:  $derPath (${result.csrDer.size} bytes)")
        println()
        println("Проверка:")
        println("  openssl req -in $outputCsrPemPath -noout -text -verify")
        println("  # ожидайте: Email Protection + URI:${result.sanUri}")
    }
}
