#include <android/log.h>
#include <dlfcn.h>         // For dl-related functions (implicit for some link.h functions)
#include <link.h>          // For dl_iterate_phdr and dl_phdr_info
#include <sys/auxv.h>      // For getauxval and AT_BASE
#include <string.h>        // For strstr()
#include <cstdio>          // snprintf
#include <stdlib.h>
#include <unistd.h>        // For syscall()
#include <sys/syscall.h>   // For SYS_*/__NR_* macros
#include <linux/memfd.h>   // For MFD_CLOEXEC
#include <android/dlext.h>
#include <sys/system_properties.h>
#include <sys/mman.h>
#include <jni.h>
#include <dobby.h>         // Third-party library for function hooking
#include <lsplant.hpp>     // Third-party library for Java method hooking
#include "find_init_array/find_init_array.h"  // Custom utility to find .init_array section
#include "elf_img/elf_img.h"                  // Custom ELF image utility
#include "resourceguard.hpp"                  // Custom RAII resource cleanup utility

// External references to embedded DEX data
// These symbols are defined elsewhere, likely in a linker script
extern "C" {
    extern uint8_t classes_dex_data_start[];  // Start address of embedded DEX
    extern uint8_t classes_dex_data_end[];    // End address of embedded DEX
    extern uint8_t classes_dex_data_size[];   // Size of embedded DEX
}

// Define log macros for Android logging
#define LOG_TAG "nbdrift"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Macros to check conditions and return early on failure
#define TEST_EXPR_RET(expr, log) if (!(expr)) { log; return; }
#define TEST_EXPR_ENV_RET(expr, log, env) if (!(expr) || (env->ExceptionCheck())) { log; return; }
#define TEST_ENV_RET(expr, log, env) \
    do { \
        expr; \
        if ((env)->ExceptionCheck()) { log; return; } \
    } while (0)

// Macros for memory alignment to page boundaries
#define ALIGN_DOWN(addr, page_size)         ((addr) & -(page_size))
#define ALIGN_UP(addr, page_size)           (((addr) + ((page_size) - 1)) & ~((page_size) - 1))

// Global variables
static void *init_array_offset_3_addr;  // Address of the third initialization function
static void *jni_onload_addr;           // Address of JNI_OnLoad function
static void *libc_handle = NULL;        // Handle to libc.so
static void *libnesec_base = NULL;      // Base address of target library (libnesec.so)
static JNIEnv *env = NULL;              // Java environment pointer
static size_t page_size_;               // System page size
static pine::ElfImg elf_img;            // ELF image utility for symbol resolution

/**
 * Makes memory at the given address writable and executable
 * 
 * @param addr Address to unprotect
 * @return true if successful, false otherwise
 */
static bool Unprotect(void *addr) {
    // Calculate page-aligned address
    auto addr_uint = reinterpret_cast<uintptr_t>(addr);
    auto page_aligned_prt = reinterpret_cast<void *>(ALIGN_DOWN(addr_uint, page_size_));
    
    // Calculate how many pages need to be unprotected
    size_t size = page_size_;
    if (ALIGN_UP(addr_uint + page_size_, page_size_) != ALIGN_UP(addr_uint, page_size_)) {
        size += page_size_;
    }

    // Change memory protection to allow writing and execution
    int result = mprotect(page_aligned_prt, size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (result == -1) {
        LOGE("mprotect failed for %p: %s (%d)", addr, strerror(errno), errno);
        return false;
    }
    return true;
}

/**
 * Hook a function using Dobby hooking library
 * 
 * @param address Address of function to hook
 * @param replacement Replacement function
 * @return Pointer to original function or nullptr on failure
 */
void *inlineHooker(void *address, void *replacement) {
    // Make memory writable before hooking
    if (!Unprotect(address)) {
        return nullptr;
    }

    void *origin_call;
    if (DobbyHook(address, replacement, &origin_call) == 0) {
        return origin_call;  // Return original function pointer
    } else {
        return nullptr;      // Hook failed
    }
}

/**
 * Remove a hook placed with Dobby
 * 
 * @param originalFunc Function to unhook
 * @return true if successful, false otherwise
 */
static bool inlineUnHooker(void *originalFunc) {
    return DobbyDestroy(originalFunc) == 0;
}

/**
 * JNI bridge for LSPlant's Hook function
 * Allows Java code to hook Java methods
 */
jobject doHook(JNIEnv* env, jobject thiz, jobject target, jobject callback) {
    return lsplant::Hook(env, target, thiz, callback);
}

/**
 * JNI bridge for LSPlant's UnHook function
 * Allows Java code to remove hooks from Java methods
 */
jboolean doUnhook(JNIEnv* env, jobject, jobject target) {
    return lsplant::UnHook(env, target);
}

/**
 * Extract embedded data from binary using a simple format:
 * - "EMBD" magic marker
 * - 8-byte size
 * - Data content
 * 
 * @param start Start address of embedded data
 * @param end End address of embedded data
 * @param size Output parameter for data size
 * @return Pointer to the data or nullptr on failure
 */
static void *get_embedded_data(void *start, void *end, size_t *size) {
    // valdiate there is a start and end
    if (!start || !end) {
        return nullptr;
    }

    // validate end is not before start
    if (reinterpret_cast<uintptr_t>(end) < reinterpret_cast<uintptr_t>(start)) {
        return nullptr;
    }

    // calulate real available space
    size_t max_size = static_cast<size_t>(
        reinterpret_cast<uintptr_t>(end) - reinterpret_cast<uintptr_t>(start));

    // validate there is any size
    if (!max_size) {
        return nullptr;
    }

    // Magic marker to identify embedded data
    constexpr const char *magic = "EMBD";

    // validate magic
    if (memcmp(reinterpret_cast<char*>(start), magic, strlen(magic)) != 0) {
        return nullptr;
    }

    // read embedded file size
    auto size_ptr = reinterpret_cast<uint64_t*>(
        reinterpret_cast<uintptr_t>(start) + strlen(magic));

    // validate the given size
    if (!size_ptr || (*size_ptr + strlen(magic) + sizeof(uint64_t)) > max_size) {
        return nullptr;
    }

    // populate the given size pointer
    *size = static_cast<size_t>(*size_ptr);
    
    // return pointer to data (after the header)
    return reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(size_ptr) + sizeof(uint64_t));
}

/**
 * Get Android SDK version from system properties
 * 
 * @return SDK version as integer or 0 on failure
 */
static int get_sdk_version() {
    char version_str[PROP_VALUE_MAX];
    if (!__system_property_get("ro.build.version.sdk", version_str)) {
        return 0;
    }
    return static_cast<int>(
        std::strtol(version_str, nullptr, 10));
}

/**
 * Function to replace integrity check
 * Always returns true to bypass security checks
 */
static bool get_true() {
    return true;
}

/**
 * Debug utility to log binary data as hex
 * 
 * @param addr Address of data to log
 * @param count Number of bytes to log
 */
static void log_bytes(void *addr, size_t count) {
    if (!addr || !count) {
        return;
    }
    size_t str_size = count * 3 + 1;
    char *str = reinterpret_cast<char*>(malloc(str_size));
    if (!str) {
        return;
    }
    str[0] = 0;
    char *dst = str;
    uint8_t *byte = reinterpret_cast<uint8_t*>(addr);
    for (size_t i = 0; i < count; i++, dst += 3, byte++) {
        snprintf(dst, 4, "%02x ", *byte);
    }
    str[str_size - 2] = 0;
    LOGD("%s", str);
    free(str);
}

/**
 * Inject embedded DEX file into the application's class loader
 * This allows custom Java code to run within the target app
 */
static void injectDex() {
    if (!env) {
        LOGE("injectDex(): env not set");
        return;
    }

    // Extract embedded DEX data
    size_t classes_dex_data_size = 0;
    auto classes_dex_data_ptr = get_embedded_data(
        reinterpret_cast<void*>(classes_dex_data_start),
        reinterpret_cast<void*>(classes_dex_data_end),
        &classes_dex_data_size);
    if (!classes_dex_data_size || !classes_dex_data_ptr) {
        LOGE("injectDex(): failure getting embedded classes.dex");
        return;
    }

    // Variables to hold Java objects and methods
    jclass classLoaderClass = nullptr;
    jmethodID getSystemClassLoaderMeth = 0;
    jobject systemClassLoader = nullptr;
    jclass inMemoryDexClassLoaderClass = nullptr;
    jmethodID inMemoryDexClassLoaderClassInitMeth = 0;
    jobject dexBuffer = nullptr;
    jobject inMemoryDexClassLoader = nullptr;
    jmethodID loadClassMeth = 0;
    jstring entryClassName = nullptr;
    jobject entryClass = nullptr;
    jstring hookerClassName = nullptr;
    jobject hookerClass = nullptr;
    jmethodID entryClassInitMeth = 0;

    // Setup RAII resource guard to clean up Java references on exit
    resourceguard::make_resource_guard(
        [](
            jclass *classLoaderClass,
            jobject* systemClassLoader,
            jclass* inMemoryDexClassLoaderClass,
            jobject* dexBuffer,
            jobject* inMemoryDexClassLoader,
            jstring* entryClassName,
            jobject* entryClass,
            jstring* hookerClassName,
            jobject* hookerClass,
            JNIEnv *env
        ) {
            if (!env) {
                LOGE("injectDex(): env not provided, ressources can't be released");
                return;
            }
            // Clear any pending exceptions
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            // Clean up Java references
            if (*classLoaderClass) env->DeleteLocalRef(*classLoaderClass);
            if (*systemClassLoader) env->DeleteLocalRef(*systemClassLoader);
            if (*inMemoryDexClassLoaderClass) env->DeleteLocalRef(*inMemoryDexClassLoaderClass);
            if (*dexBuffer) env->DeleteLocalRef(*dexBuffer);
            if (*inMemoryDexClassLoader) env->DeleteLocalRef(*inMemoryDexClassLoader);
            if (*entryClassName) env->DeleteLocalRef(*entryClassName);
            if (*entryClass) env->DeleteLocalRef(*entryClass);
            if (*hookerClassName) env->DeleteLocalRef(*hookerClassName);
            if (*hookerClass) env->DeleteLocalRef(*hookerClass);
            LOGD("injectDex(): ressources released");
        },
        &classLoaderClass,
        &systemClassLoader,
        &inMemoryDexClassLoaderClass,
        &dexBuffer,
        &inMemoryDexClassLoader,
        &entryClassName,
        &entryClass,
        &hookerClassName,
        &hookerClass,
        env
    );

    // Get ClassLoader class
    TEST_EXPR_RET(classLoaderClass = env->FindClass("java/lang/ClassLoader"),
        LOGE("injectDex(): failure getting ClassLoader class"));

    // Get getSystemClassLoader method
    TEST_EXPR_RET(getSystemClassLoaderMeth = env->GetStaticMethodID(
        classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;"),
        LOGE("injectDex(): failure getting getSystemClassLoader meth"));

    // Get system class loader instance
    TEST_EXPR_ENV_RET(systemClassLoader = env->CallStaticObjectMethod(classLoaderClass, getSystemClassLoaderMeth),
        LOGE("injectDex(): failure getting getSystemClassLoader"), env);

    // Get InMemoryDexClassLoader class
    TEST_EXPR_RET(inMemoryDexClassLoaderClass = env->FindClass("dalvik/system/InMemoryDexClassLoader"),
        LOGE("injectDex(): failure getting InMemoryDexClassLoader class"));
    
    // Get InMemoryDexClassLoader constructor
    TEST_EXPR_RET(inMemoryDexClassLoaderClassInitMeth = env->GetMethodID(
        inMemoryDexClassLoaderClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V"),
        LOGE("injectDex(): failure getting init meth"));

    // Create ByteBuffer from DEX data
    TEST_EXPR_RET(dexBuffer = env->NewDirectByteBuffer(classes_dex_data_ptr, classes_dex_data_size),
        LOGE("injectDex(): failure making NewDirectByteBuffer"));

    // Create InMemoryDexClassLoader with DEX ByteBuffer
    TEST_EXPR_ENV_RET(inMemoryDexClassLoader = env->NewObject(
        inMemoryDexClassLoaderClass, inMemoryDexClassLoaderClassInitMeth, dexBuffer, systemClassLoader),
        LOGE("injectDex(): failure making inMemoryDexClassLoaderClass"), env);

    // Get loadClass method from ClassLoader
    TEST_EXPR_RET(loadClassMeth = env->GetMethodID(
        classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;"),
        LOGE("injectDex(): failure getting loadClass meth"));

    // Create string for EntryPoint class name
    TEST_EXPR_RET(entryClassName = env->NewStringUTF("de.truetoastedcode.nbdrift.EntryPoint"),
        LOGE("injectDex(): failure making entry class name"));
    
    // Load EntryPoint class
    TEST_EXPR_ENV_RET(entryClass = env->CallObjectMethod(
        inMemoryDexClassLoader, loadClassMeth, entryClassName),
        LOGE("injectDex(): failure loading EntryPoint"), env);
    
    // Create string for Hooker class name
    TEST_EXPR_RET(hookerClassName = env->NewStringUTF("de.truetoastedcode.nbdrift.Hooker"),
        LOGE("injectDex(): failure making hooker class name"));

    // Load Hooker class
    TEST_EXPR_ENV_RET(hookerClass = env->CallObjectMethod(
        inMemoryDexClassLoader, loadClassMeth, hookerClassName),
        LOGE("injectDex(): failure loading Hooker"), env);

    // Define native methods to register with Hooker class
    static const JNINativeMethod methods[] = {
        {"doHook", "(Ljava/lang/reflect/Member;Ljava/lang/reflect/Method;)Ljava/lang/reflect/Method;", (void *)doHook},
        {"doUnhook", "(Ljava/lang/reflect/Member;)Z", (void *)doUnhook}
    };

    // Register native methods with Hooker class
    TEST_EXPR_RET(!env->RegisterNatives(
        static_cast<jclass>(hookerClass), methods, sizeof(methods)/sizeof(methods[0])),
        LOGE("injectDex(): failure registering native methods"));

    // Get EntryPoint.init() method
    TEST_EXPR_RET(entryClassInitMeth = env->GetStaticMethodID(
        static_cast<jclass>(entryClass), "init", "()V"),
        LOGE("injectDex(): failure getting init meth"));

    // Call EntryPoint.init() to initialize the injected code
    TEST_ENV_RET(env->CallStaticVoidMethod(
        static_cast<jclass>(entryClass), entryClassInitMeth),
        LOGE("injectDex(): failure invoking init"), env);

    LOGD("DEX injection completed sucessfully!");
}

/**
 * Set up the environment for Java method hooking with LSPlant
 * 
 * @return 0 on success, 1 on failure
 */
static int prepareHookingEnv() {
    // Get Android SDK version
    int sdk_ver = get_sdk_version();
    if (sdk_ver == 0) {
        LOGE("Failed to get sdk version");
        return 1;
    }

    // Get system page size for memory alignment
    page_size_ = static_cast<const size_t>(sysconf(_SC_PAGESIZE));

    // Initialize ELF image for libart.so to resolve ART symbols
    pine::ElfImg local_elf_img;
    local_elf_img.Init("libart.so", sdk_ver);
    elf_img = std::move(local_elf_img);

    // Configure LSPlant with custom hooking functions and symbol resolvers
    lsplant::InitInfo init_info{
        .inline_hooker = inlineHooker,
        .inline_unhooker = inlineUnHooker,
        .art_symbol_resolver = [](std::string_view symbol) -> void * {
            return elf_img.GetSymbolAddress(symbol, false, false);
        },
        .art_symbol_prefix_resolver = [](std::string_view symbol) -> void * {
            return elf_img.GetSymbolAddress(symbol, false, true);
        },
    };
    
    // Initialize LSPlant
    if (!lsplant::Init(env, init_info)) {
        LOGE("Failed to init lsplant");
        return 1;
    }

    LOGD("hooking env initialized!");

    return 0;
}

// Original JNI_OnLoad function pointer
static jint (*orig_JNI_OnLoad)(JavaVM*, void*);

/**
 * Replacement for JNI_OnLoad - called when the library is loaded by Java
 * 
 * @param vm Java VM instance
 * @param reserved Reserved parameter
 * @return JNI version
 */
static jint my_JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGD("my_JNI_OnLoad() invoked!");

    // Call the original JNI_OnLoad
    auto onload_status = orig_JNI_OnLoad(vm, reserved);

    // Restore original JNI_OnLoad to avoid detection
    if (DobbyDestroy(jni_onload_addr) != 0) {
        LOGE("failed to restore original jni onload");
        return onload_status;
    }

    // Validate JNI version returned by original function
    if (
        onload_status != JNI_VERSION_1_1 &&
        onload_status != JNI_VERSION_1_2 &&
        onload_status != JNI_VERSION_1_4 &&
        onload_status != JNI_VERSION_1_6
    ) {
        LOGE("Original JNI_OnLoad failed: %d", static_cast<int>(onload_status));
        return onload_status;
    }

    LOGD("orig_JNI_OnLoad() finished!");

    // Get JNI environment
    if (vm->GetEnv((void **)&env, onload_status) != JNI_OK) {
        LOGE("Failed to get JNIEnv");
        return onload_status;
    }

    // Set up Java method hooking environment
    if (prepareHookingEnv()) {
        return onload_status;
    }

    // Inject custom DEX file
    injectDex();

    return onload_status;
}

// Original third initialization function pointer
static void (*ori_init_array_3)(void);

/**
 * Replacement for the third initialization function
 * This runs after the library has deobfuscated itself
 */
static void my_init_array_3(void) {
    LOGD("my_init_array_3() invoked!");
    
    // Call original function to let library initialize
    ori_init_array_3();
    LOGD("ori_init_array_3() finished!");

    // Restore original function to avoid detection
    if (DobbyDestroy(init_array_offset_3_addr) != 0) {
        LOGE("failed to restore original init array 3 func");
        return;
    }

    // Hook integrity check function to always return true
    // This bypasses security checks in the target library
    auto status = DobbyHook(
        reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(libnesec_base) + 0x90964),
        reinterpret_cast<void*>(&get_true),
        nullptr
    );

    if (status != 0) {
        LOGE("failed to hook integrity check func");
        return;
    }
    LOGD("hooked integrity check func");

    // Find JNI_OnLoad function to hook
    jni_onload_addr = DobbySymbolResolver(nullptr, "JNI_OnLoad");

    if (!jni_onload_addr) {
        LOGE("failed to find JNI_OnLoad");
        return;
    }
    LOGD("Found JNI_OnLoad at %p", jni_onload_addr);

    // Hook JNI_OnLoad to run custom code when loaded by Java
    status = DobbyHook(
        jni_onload_addr,
        reinterpret_cast<void*>(&my_JNI_OnLoad),
        reinterpret_cast<void**>(&orig_JNI_OnLoad)
    );

    if (status != 0) {
        LOGE("failed to hook JNI_OnLoad");
        return;
    }
    LOGD("hooked JNI_OnLoad");
}

/**
 * Library constructor - called when the library is loaded by the dynamic linker
 * This is the first entry point of the library
 */
__attribute__((constructor)) void init_lib() {
    // Load libc.so for system functions
    libc_handle = dlopen("libc.so", RTLD_NOW | RTLD_GLOBAL);
    if (!libc_handle) {
        LOGE("Failed to load libc.so: %s\n", dlerror());
        return;
    }
    
    LOGD("loaded real libc.so\n");

    // Find base address of libnesec.so in memory
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t sz, void* data) -> int {
        // Skip the Android linker (ld-android.so)
        auto linker_base = (uintptr_t) getauxval(AT_BASE);
        if (linker_base == info->dlpi_addr) {
            return 0; // Continue to next library
        }

        // Look for libnesec.so
        if (info->dlpi_name != nullptr && strstr(info->dlpi_name, "libnesec.so") != nullptr) {
            *reinterpret_cast<void**>(data) = (void*) info->dlpi_addr;
            return 1; // Stop searching
        }

        return 0; // Continue searching
    }, &libnesec_base);

    if (!libnesec_base) {
        LOGE("failed to find libnesec base base addr");
        return;
    }

    LOGD("found libnesec base at: %p", libnesec_base);

    // Find .init_array section offset in the target library
    auto init_array_offset = find_init_array::find_init_array(libnesec_base);

    if (!init_array_offset) {
        LOGD("init array offset not found");
        return;
    }

    LOGD("found init array offset: %#lx", *init_array_offset);

    // Get address of the third initialization function
    init_array_offset_3_addr = *(reinterpret_cast<void**>(
        reinterpret_cast<uintptr_t>(libnesec_base) + *init_array_offset + sizeof(void*) * 2));

    // Hook the third initialization function
    auto status = DobbyHook(
        init_array_offset_3_addr,
        reinterpret_cast<void*>(&my_init_array_3),
        reinterpret_cast<void**>(&ori_init_array_3)
    );
    
    if (status != 0) {
        LOGE("failed to hook third init array func");
        return;
    }

    LOGD("hooked third init array func");
}