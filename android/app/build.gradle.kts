plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.github.fstrx.commx"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.fstrx.commx"
        minSdk = 26 // AAudio
        targetSdk = 36
        versionCode = 4
        versionName = "0.3.1"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    // Release signing from the environment (CI secrets); falls back to the
    // debug key so local builds still install. A stable key matters: Android
    // refuses updates signed with a different key.
    val ks = System.getenv("COMMX_KEYSTORE")?.let { file(it) }?.takeIf { it.exists() }
    signingConfigs {
        if (ks != null) create("release") {
            storeFile = ks
            storePassword = System.getenv("COMMX_KEYSTORE_PASSWORD")
            keyAlias = System.getenv("COMMX_KEY_ALIAS")
            keyPassword = System.getenv("COMMX_KEY_PASSWORD")
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }
    buildFeatures { compose = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging { jniLibs { useLegacyPackaging = false } }
}

// The Rust core (daemon + voice + JNI bridge) is built by cargo-ndk.
val buildRust by tasks.registering(Exec::class) {
    description = "Build libcommx_android.so for all ABIs"
    workingDir = rootProject.projectDir
    commandLine("./build-rust.sh", "release")
}
tasks.named("preBuild") { dependsOn(buildRust) }

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.06.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.activity:activity-compose:1.12.4")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
