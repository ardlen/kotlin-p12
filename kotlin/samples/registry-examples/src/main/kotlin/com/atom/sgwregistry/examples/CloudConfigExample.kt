package com.atom.sgwregistry.examples

import com.atom.sgwregistry.cloudconfig.CloudConfigCms
import com.atom.sgwregistry.config.ConfigLoader
import com.atom.sgwregistry.model.CloudConfigResignRequest
import com.atom.sgwregistry.model.MobDevCloudConfigJson
import java.nio.file.Files
import java.nio.file.Path

/**
 * Пример: mob-dev `cloud_configuration` — parse / verify / resign `cloud_config_pem`.
 */
object CloudConfigExample {
    fun run(
        mobDevJsonPath: Path,
        configPath: Path? = null,
        outputJsonPath: Path? = null,
    ) {
        SampleSupport.section("CloudConfigCms — mob-dev cloud_configuration")

        val bytes = SampleSupport.readBytes(mobDevJsonPath)
        val response = MobDevCloudConfigJson.parse(bytes)
        val dto = response.cloudConfiguration

        println("id:       ${dto.id}")
        println("vin:      ${dto.vin}")
        println("owner_id: ${dto.ownerId}")
        println()
        println(CloudConfigCms.toText(dto))

        println("=== verify cloud_configuration ===")
        CloudConfigCms.verifyCloudConfiguration(dto)
        println("verifyCloudConfiguration: OK")

        if (configPath != null && Files.exists(configPath)) {
            val configDir = configPath.parent?.toString() ?: "."
            val buildCfg = ConfigLoader.toBuildConfig(ConfigLoader.readConfig(configPath.toString()), configDir)
            val resigned = CloudConfigCms.resignConfigurationOnly(
                dto = dto,
                signerCertDer = buildCfg.signerCertDer,
                signerKey = buildCfg.signerKey,
            )
            val resignedContainer = CloudConfigCms.parsePem(resigned.cloudConfigPem)
            CloudConfigCms.verify(resignedContainer)
            println("resign with config signer: OK (resignConfigurationOnly)")

            if (outputJsonPath != null) {
                Files.createDirectories(outputJsonPath.parent)
                val outJson = buildString {
                    append("{\n  \"cloud_configuration\": ")
                    append(
                        kotlinx.serialization.json.Json {
                            prettyPrint = true
                        }.encodeToString(
                            com.atom.sgwregistry.model.CloudConfigurationDto.serializer(),
                            resigned,
                        ),
                    )
                    append("\n}\n")
                }
                Files.writeString(outputJsonPath, outJson)
                println("written: $outputJsonPath")
            }
        } else {
            println("(resign skipped — no config.json for test signer)")
        }
    }
}
