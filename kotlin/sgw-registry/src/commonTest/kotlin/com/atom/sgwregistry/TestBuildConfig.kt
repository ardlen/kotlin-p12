package com.atom.sgwregistry

import com.atom.sgwregistry.config.BuildConfigFactory
import com.atom.sgwregistry.model.BuildConfig

internal object TestBuildConfig {
    fun exists(): Boolean = TestFixtures.exists("config.json")

    fun load(): BuildConfig {
        val cfg = BuildConfigFactory.parseConfig(
            TestFixtures.readBytes("config.json").decodeToString(),
        )
        return BuildConfigFactory.toBuildConfig(cfg) { path ->
            TestFixtures.readBytes(path)
        }
    }
}
