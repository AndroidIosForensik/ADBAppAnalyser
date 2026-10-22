import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Serverdaten aus chat.properties (nicht im Git). Vorlage: chat.properties.example.
val chatProps = Properties().apply {
    val f = rootProject.file("app/chat.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun chat(key: String, default: String) = (chatProps.getProperty(key) ?: default)

// Optionaler Release-Keystore aus keystore.properties (von build.cmd erzeugt).
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "de.rechenhilfe.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "de.rechenhilfe.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        buildConfigField("String", "SERVER_URL", "\"${chat("serverUrl", "wss://10.0.2.2:8443")}\"")
        buildConfigField("String", "RELAY_PIN", "\"${chat("pin", "")}\"")
        buildConfigField("String", "RELAY_TOKEN", "\"${chat("token", "testtoken")}\"")
        buildConfigField("String", "UNLOCK_CODE", "\"${chat("unlockCode", "737373")}\"")
    }

    signingConfigs {
        if (keystoreProps.getProperty("storeFile") != null) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Eigener Keystore, falls vorhanden; sonst Debug-Signatur als Rueckfall.
            signingConfig = if (keystoreProps.getProperty("storeFile") != null)
                signingConfigs.getByName("release") else signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.material3)
    implementation(libs.okhttp)
}
