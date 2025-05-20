import org.apache.tools.ant.filters.FixCrLfFilter
import org.apache.tools.ant.filters.ReplaceTokens
import java.security.MessageDigest
import java.util.Locale
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.core.type.TypeReference
import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Provider
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*;
import org.gradle.process.ExecOperations
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import java.time.LocalDateTime
import java.io.Serializable
import org.gradle.api.logging.Logger
import org.gradle.api.provider.MapProperty
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.ZipFile
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import java.util.zip.ZipException
import java.util.zip.CRC32
import java.io.InputStream
import java.io.OutputStream

fun String.capitalizeUS() = replaceFirstChar { 
    if (it.isLowerCase()) it.titlecase(Locale.US) else it.toString() 
}

plugins {
    alias(libs.plugins.android.app)
}

val moduleId: String by rootProject.extra
val moduleName: String by rootProject.extra
val verName: String by rootProject.extra
val abiList: List<String> by rootProject.extra
val androidMinSdkVersion: Int by rootProject.extra
val androidCompileSdkVersion: Int by rootProject.extra
val androidBuildToolsVersion: String by rootProject.extra
val cmakeVer: String by rootProject.extra
val androidSourceCompatibility: JavaVersion by rootProject.extra
val androidTargetCompatibility: JavaVersion by rootProject.extra
val androidNamespace: String by rootProject.extra
val androidCompileNdkVersion: String by rootProject.extra

val abiMap = mapOf(
    "arm64-v8a" to "arm64",
    "armeabi-v7a" to "arm",
    "x86" to "x86",
    "x86_64" to "x64"
)

abstract class ComputeCmd @Inject constructor(
    private val execOperations: ExecOperations
): DefaultTask() {
    @get:OutputDirectory
    internal abstract val outDir: DirectoryProperty
    
    @get:Input
    abstract val cmd: ListProperty<String>

    @get:Input
    abstract val outputProcessor: Property<OutputProcessor>

    init {
        outDir.convention(project.layout.buildDirectory)
    }

    @TaskAction
    fun compute() {
        runCatching {
            ByteArrayOutputStream().use { output ->
                execOperations.exec {
                    commandLine(cmd.get())
                    isIgnoreExitValue = false
                    standardOutput = output
                    errorOutput = System.err
                }
                outputProcessor.get().process(output.toString(), null, logger)
            }
        }.onFailure { ex ->
            outputProcessor.get().process(null, ex, logger)
        }
    }
}

interface OutputProcessor : Serializable {
    fun process(res: String?, ex: Throwable?, logger: Logger)
}

// Singleton object to store outputs in memory
object OutputStore : Serializable {
    private val outputs = ConcurrentHashMap<String, String>()

    fun storeOutput(key: String, output: String) {
        outputs[key] = output
    }

    fun getOutput(key: String): String {
        return outputs[key] ?: throw IllegalStateException("No output found for key: $key")
    }

    fun clearOutput(key: String) {
        outputs.remove(key)
    }
}

// Serializable OutputProcessor
class StoringOutputProcessor(
    private val key: String
) : OutputProcessor, Serializable {
    override fun process(res: String?, ex: Throwable?, logger: Logger) {
        ex?.let { throw ex }
        OutputStore.storeOutput(
            key, res
                ?.trim()
                ?.also { if (it.isEmpty()) throw IllegalArgumentException("Result must not be empty") }
                ?: throw IllegalArgumentException("Result must not be null")
        )
    }
}

class ValidatingOutputProcessor : OutputProcessor, Serializable {
    override fun process(res: String?, ex: Throwable?, logger: Logger) {
        ex?.let { throw ex }
    }
}

object ZipUtils {
    // Helper function to calculate CRC32 for uncompressed files
    fun calculateCrc32(input: InputStream): Long {
        val crc = CRC32()
        val buffer = ByteArray(8192)
        var bytesRead: Int
        while (input.read(buffer).also { bytesRead = it } != -1) {
            crc.update(buffer, 0, bytesRead)
        }
        return crc.value
    }
}

android {
    namespace = androidNamespace
    compileSdk = androidCompileSdkVersion
    buildToolsVersion = androidBuildToolsVersion
    ndkVersion = androidCompileNdkVersion
    ndkPath = System.getenv("ANDROID_SDK_ROOT")?.let { "$it/ndk/$androidCompileNdkVersion" }
        ?: throw RuntimeException("ANDROID_SDK_ROOT is not set")

    buildFeatures {
        prefab = true
    }

    defaultConfig {
        ndk {
            abiFilters.addAll(abiList)
        }
        externalNativeBuild {
            cmake {
                cppFlags("-std=c++23")
                arguments(
                    "-DANDROID_STL=c++_static",
                    "-DMODULE_NAME=$moduleId"
                )
                version = cmakeVer
            }
        }
    }

    externalNativeBuild {
        cmake {
            version = cmakeVer
            path("src/main/cpp/CMakeLists.txt")
        }
    }
    
    buildTypes {
        debug {
            isMinifyEnabled = true
            isShrinkResources = true
            multiDexEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    defaultConfig {
        minSdk = androidMinSdkVersion
    }

    compileOptions {
        sourceCompatibility = androidSourceCompatibility
        targetCompatibility = androidTargetCompatibility
    }
}

androidComponents.onVariants { variant ->
    afterEvaluate {
        val variantLowered = variant.name.lowercase()
        val variantCapped = variant.name.capitalizeUS()

        val apkPathsToCopy = listOf(
            "config.en.apk",
            "com.ninebot.segway.apk",
            "config.xxhdpi.apk"
        )

        val apkPathsToExtract = mapOf(
            "config.arm64_v8a.apk" to listOf(
                "lib/arm64-v8a/libnesec.so"
            )
        )

        val apkPathsToImport = mapOf(
            "config.arm64_v8a.apk" to listOf(
                "lib/arm64-v8a/libnesec.so",
                "lib/arm64-v8a/lipc.so"
            )
        )

        val apksIntermediatesDir = layout.buildDirectory.dir("intermediates/components/$variantLowered")

        val providedApks = layout.projectDirectory.file("template").asFile.listFiles()
            ?.filter {
                it.isFile
                && it.name.endsWith(".apk")
                && (apkPathsToExtract.keys.contains(it.name) || apkPathsToCopy.contains(it.name))
            }
            ?.also { files -> 
                if (files.isEmpty())
                {
                    throw GradleException("No APK files for zipping found at all!")
                }

                if (
                    !apkPathsToExtract.keys.all { name -> files.any { file -> file.name == name } }
                    || !apkPathsToCopy.all { name -> files.any { file -> file.name == name } }
                ) {
                    throw GradleException("At least one APK file is missing!")
                }
            }
            ?: throw GradleException("No APK files for zipping found at all!")

        val copyApksTask = tasks.register<Copy>("copyApks${variantCapped}") {
            group = "build"
            from(providedApks)
            into(apksIntermediatesDir)
        }
     
        val dumpApkFilesTask = tasks.register("dumpApkFiles${variantCapped}") {
            group = "build"
            dependsOn(copyApksTask)
            doLast {
                apkPathsToExtract.forEach { (apkFileName, paths) ->
                    val apkFile = File(apksIntermediatesDir.get().asFile, apkFileName)
                    val outputDir = File(apksIntermediatesDir.get().asFile, apkFileName.removeSuffix(".apk"))
                    outputDir.mkdirs()

                    if (!apkFile.exists()) {
                        throw GradleException("APK file ${apkFile.absolutePath} does not exist")
                    }

                    ZipFile(apkFile).use { zip ->
                        paths.forEach { path ->
                            // Handle both files and directories
                            val entries = zip.entries().asSequence().filter {
                                it.name == path || it.name.startsWith("$path/")
                            }.toList()

                            if (entries.isEmpty()) {
                                throw GradleException("No entries found for path '$path' in ${apkFile.name}")
                            }

                            entries.forEach { entry ->
                                // Skip directories themselves, only process their contents
                                if (entry.isDirectory) return@forEach

                                zip.getInputStream(entry).use { input ->
                                    val outputFile = File(outputDir, entry.name)
                                    outputFile.parentFile?.mkdirs()
                                    outputFile.outputStream().use { output ->
                                        input.copyTo(output)
                                    }
                                    logger.lifecycle("Extracted ${entry.name} to ${outputFile.absolutePath}")
                                }
                            }
                        }
                    }
                }
            }
        }

        val copyNewAssets1TaskId = "copyNewAssets1${variantCapped}"

        val copyNewAssets1Task = tasks.register<Copy>(copyNewAssets1TaskId) {
            group = "build"
            dependsOn("assemble$variantCapped", dumpApkFilesTask)
            from(layout.buildDirectory.dir("intermediates/stripped_native_libs/$variantLowered/strip${variantCapped}DebugSymbols/out/lib/arm64-v8a")) {
                include("libnbdrift.so")
                rename("libnbdrift.so", "lipc.so")
            }
            into(File(apksIntermediatesDir.get().asFile, "config.arm64_v8a/lib/arm64-v8a"))
        }

        val patchElfTask1Id = "patchElf1_config.arm64_v8a_${variantCapped}"

        val patchElfTask1 = tasks.register<ComputeCmd>(patchElfTask1Id) {
            group = "build"
            dependsOn(copyNewAssets1Task)
            cmd.set(listOf(
                rootProject.layout.projectDirectory.file("elf_add_needed").asFile.absolutePath,
                File(apksIntermediatesDir.get().asFile, "config.arm64_v8a/lib/arm64-v8a/libnesec.so").absolutePath,
                "libc.so",
                "lipc.so"
            ))
            outputProcessor.set(ValidatingOutputProcessor())
        }

        val patchElfTask2Id = "patchElf2_config.arm64_v8a_${variantCapped}"

        val patchElfTask2 = tasks.register<ComputeCmd>(patchElfTask2Id) {
            group = "build"
            dependsOn(copyNewAssets1Task)
            cmd.set(listOf(
                "python3",
                rootProject.layout.projectDirectory.file("replace_data.py").asFile.absolutePath,
                File(apksIntermediatesDir.get().asFile, "config.arm64_v8a/lib/arm64-v8a/lipc.so").absolutePath,
                File(apksIntermediatesDir.get().asFile, "config.arm64_v8a/lib/arm64-v8a/lipc.so").absolutePath,
                layout.buildDirectory.file("intermediates/dex/${variantLowered}/minify${variantCapped}WithR8/classes.dex").get().asFile.absolutePath,
                "classes_dex_data"
            ))
            outputProcessor.set(ValidatingOutputProcessor())
        }
        
        val zipApkFilesTask = tasks.register("zipApkFiles${variantCapped}") {
            group = "build"
            dependsOn(patchElfTask1, patchElfTask2)
            doLast {
                apkPathsToImport.forEach { (apkFileName, paths) ->
                    val apkFile = File(apksIntermediatesDir.get().asFile, apkFileName)
                    var outputApk = File(apksIntermediatesDir.get().asFile, apkFileName.removeSuffix(".apk") + "_patched.apk")
                    val inputDir = File(apksIntermediatesDir.get().asFile, apkFileName.removeSuffix(".apk"))

                    if (!apkFile.exists()) {
                        throw GradleException("APK file ${apkFile.absolutePath} does not exist")
                    }

                    ZipFile(apkFile).use { zip ->
                        ZipOutputStream(outputApk.outputStream()).use { zos ->
                            // Add new files/directories
                            paths.forEach { zipPath ->
                                var sourceFile = File(inputDir, zipPath)
                                if (sourceFile.isDirectory) {
                                    // Handle directories recursively
                                    sourceFile.walk().forEach { file ->
                                        if (file.isFile) {
                                            val relativePath = file.relativeTo(sourceFile).path
                                            val entryPath = "$zipPath/$relativePath".replace(File.separator, "/")
                                            // zos.putNextEntry(ZipEntry(entryPath))
                                            // file.inputStream().use { it.copyTo(zos) }
                                            // zos.closeEntry()
                                            val entry = ZipEntry(entryPath)
                                            entry.method = ZipEntry.STORED
                                            entry.size = file.length()
                                            entry.crc = file.inputStream().use { ZipUtils.calculateCrc32(it) }
                                            zos.putNextEntry(entry)
                                            file.inputStream().use { it.copyTo(zos) }
                                            zos.closeEntry()
                                            logger.lifecycle("Added $entryPath to APK")
                                        }
                                    }
                                } else if (sourceFile.isFile) {
                                    // Handle single files
                                    val entryPath = zipPath.replace(File.separator, "/")
                                    // zos.putNextEntry(ZipEntry(entryPath))
                                    // sourceFile.inputStream().use { it.copyTo(zos) }
                                    // zos.closeEntry()
                                    val entry = ZipEntry(entryPath)
                                    entry.method = ZipEntry.STORED
                                    entry.size = sourceFile.length()
                                    entry.crc = sourceFile.inputStream().use { ZipUtils.calculateCrc32(it) }
                                    zos.putNextEntry(entry)
                                    sourceFile.inputStream().use { it.copyTo(zos) }
                                    zos.closeEntry()
                                    logger.lifecycle("Added $entryPath to APK")
                                } else {
                                    throw GradleException("Source file/directory ${sourceFile.absolutePath} does not exist")
                                }
                            }

                            // Copy existing entries from the input APK
                            zip.entries().asSequence().forEach { entry ->
                                try {
                                    // zos.putNextEntry(ZipEntry(entry.name))
                                    // if (!entry.isDirectory) {
                                    //     zip.getInputStream(entry).use { it.copyTo(zos) }
                                    // }
                                    val newEntry = ZipEntry(entry.name)
                                    // Preserve compression method for existing entries
                                    newEntry.method = entry.method
                                    if (entry.method == ZipEntry.STORED) {
                                        newEntry.size = entry.size
                                        newEntry.crc = entry.crc
                                    }
                                    zos.putNextEntry(newEntry)
                                    if (!entry.isDirectory) {
                                        zip.getInputStream(entry).use { it.copyTo(zos) }
                                    }
                                    zos.closeEntry()
                                } catch (e: java.util.zip.ZipException) {
                                    when {
                                        e.message?.contains("duplicate entry", ignoreCase = true) == true -> {
                                            // Ignore duplicate entry error
                                        }
                                        else -> throw e // Re-throw other exceptions
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        val providedApksForSigning = providedApks.map { File(
            apksIntermediatesDir.get().asFile,
            if (apkPathsToImport.keys.contains(it.name)) "${it.nameWithoutExtension}_patched.${it.extension}" else it.name
        ) }

        val apkSigningTasks = providedApksForSigning.map { src ->
            tasks.register<ComputeCmd>("sign_${src.nameWithoutExtension}_${variantCapped}") {
                group = "build"
                dependsOn(zipApkFilesTask)
                cmd.set(listOf(
                    "apksigner",
                    "sign",
                    "--verbose",
                    "--ks",
                    rootProject.layout.projectDirectory.file("trueToastedCode-release-key.jks").asFile.absolutePath,
                    "--ks-key-alias",
                    "trueToastedCode-key",
                    "--ks-pass",
                    "pass:StrongPass123!",
                    "--out",
                    File(src.parent, "${src.nameWithoutExtension}_signed.${src.extension}").absolutePath,
                    src.absolutePath
                ))
                outputProcessor.set(ValidatingOutputProcessor())
            }
        }

        // val apkZipAligningTasks = providedApksForSigning.map { src ->
        //     tasks.register<ComputeCmd>("zipalign_${src.nameWithoutExtension}_${variantCapped}") {
        //         group = "build"
        //         dependsOn("sign_${src.nameWithoutExtension}_${variantCapped}")
        //         cmd.set(listOf(
        //             "zipalign", "-v", "4",
        //             File(src.parent, "${src.nameWithoutExtension}_signed.${src.extension}").absolutePath,
        //             File(src.parent, "${src.nameWithoutExtension}_signed_aligned.${src.extension}").absolutePath
        //         ))
        //         outputProcessor.set(ValidatingOutputProcessor())
        //     }
        // }

        tasks.register("modApks${variantCapped}") {
            group = "build"
            dependsOn(apkSigningTasks)
        }

        // Fix for task dependency issue
        tasks.matching { it.name == "create${variantCapped}ApkListingFileRedirect" }.configureEach {
            dependsOn("modApks${variantCapped}")
        }
    }
}

dependencies {}

buildscript {
    dependencies {
        classpath(libs.jackson.databind)
    }
}
