plugins {
    alias(libs.plugins.android.app) apply false
}

val moduleId by extra("nbdrift")
val moduleName by extra("NB Drift")
val verName by extra("v1")
val abiList by extra(listOf("arm64-v8a"))

val androidMinSdkVersion by extra(29)
val androidTargetSdkVersion by extra(35)
val androidCompileSdkVersion by extra(35)
val androidBuildToolsVersion by extra("35.0.0")
val androidCompileNdkVersion by extra("29.0.13113456")
val androidSourceCompatibility by extra(JavaVersion.VERSION_21)
val androidTargetCompatibility by extra(JavaVersion.VERSION_21)
val cmakeVer by extra("3.31.6")
val androidNamespace by extra("io.github.truetoastedcode.nbdrift")

tasks.register<Delete>("Delete") {
    delete(layout.buildDirectory)
}
