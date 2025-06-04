/**
* @file elf_img.hpp
* @brief ELF Image Utility for Symbol Resolution with .gnu_debugdata support
* 
* Original work Copyright (c) Swift Gan (github user ganyao114)
* Modified work Copyright (c) canyie (github user canyie)
* Modified work Copyright (c) Aliucord (github.com/Aliucord)
* License: Anti 996 License Version 1.0
*/

#pragma once

#include <linux/elf.h>
#include <string_view>
#include <jni.h>
#include <cstdio>
#include <vector>
#include <cstdint>

// Platform-specific ELF type definitions
#if defined(__LP64__)
    typedef Elf64_Ehdr Elf_Ehdr;
    typedef Elf64_Shdr Elf_Shdr;
    typedef Elf64_Addr Elf_Addr;
    typedef Elf64_Dyn Elf_Dyn;
    typedef Elf64_Rela Elf_Rela;
    typedef Elf64_Sym Elf_Sym;
    typedef Elf64_Off Elf_Off;

    #define ELF_R_SYM(i) ELF64_R_SYM(i)
#else
    typedef Elf32_Ehdr Elf_Ehdr;
    typedef Elf32_Shdr Elf_Shdr;
    typedef Elf32_Addr Elf_Addr;
    typedef Elf32_Dyn Elf_Dyn;
    typedef Elf32_Rel Elf_Rela;
    typedef Elf32_Sym Elf_Sym;
    typedef Elf32_Off Elf_Off;

    #define ELF_R_SYM(i) ELF32_R_SYM(i)
#endif

namespace pine {
    class ElfImg {
    public:
        /**
        * Default constructor
        */
        ElfImg() = default;

        /**
        * Initialize the ELF image
        * @param elf Path to the ELF file
        * @param android_version Android OS version
        */
        void Init(const char* elf, jint android_version);

        /**
        * Get symbol offset
        * @param symbol Symbol name to find
        * @param warn_if_missing Whether to warn if symbol is not found
        * @param match_prefix Whether to do prefix matching
        * @return Symbol offset
        */
        Elf_Addr GetSymbolOffset(
            std::string_view symbol, 
            bool warn_if_missing = true,
            bool match_prefix = false
        ) const;

        /**
        * Get symbol address
        * @param symbol Symbol name to find
        * @param warn_if_missing Whether to warn if symbol is not found
        * @param match_prefix Whether to do prefix matching
        * @return Pointer to symbol address
        */
        void* GetSymbolAddress(
            std::string_view symbol, 
            bool warn_if_missing = true,
            bool match_prefix = false
        ) const;

        /**
        * Destructor
        */
        ~ElfImg();

        // Prevent copying
        ElfImg(const ElfImg&) = delete;
        ElfImg& operator=(const ElfImg&) = delete;

        // Allow moving
        ElfImg(ElfImg&& other) noexcept = default;
        ElfImg& operator=(ElfImg&& other) noexcept = default;

    private:
        /**
        * Open ELF file
        * @param path Path to the file
        * @param warn_if_symtab_not_found Whether to warn if symbol table is not found
        */
        void Open(const char* path, bool warn_if_symtab_not_found);

        /**
        * Open ELF file relatively
        * @param elf Relative path
        * @param warn_if_symtab_not_found Whether to warn if symbol table is not found
        */
        void RelativeOpen(const char* elf, bool warn_if_symtab_not_found);

        /**
        * Get module base address
        * @param name Module name
        * @return Base address of the module
        */
        void* GetModuleBase(const char* name);

        /**
        * Process .gnu_debugdata section (compressed debug symbols)
        * @param debug_data Pointer to compressed debug data
        * @param debug_size Size of compressed debug data
        */
        void ProcessGnuDebugData(const uint8_t* debug_data, size_t debug_size);

        // Library directories for different architectures
#ifdef __LP64__
        static constexpr const char* kSystemLibDir = "/system/lib64/";
        static constexpr const char* kApexRuntimeLibDir = "/apex/com.android.runtime/lib64/";
        static constexpr const char* kApexArtLibDir = "/apex/com.android.art/lib64/";
#else
        static constexpr const char* kSystemLibDir = "/system/lib/";
        static constexpr const char* kApexRuntimeLibDir = "/apex/com.android.runtime/lib/";
        static constexpr const char* kApexArtLibDir = "/apex/com.android.art/lib/";
#endif

        // Original member variables
        const char* elf = nullptr;
        jint android_version = 0;
        void* base = nullptr;
        char* buffer = nullptr;
        off_t size = 0;
        off_t bias = -4396;
        Elf_Ehdr* header = nullptr;
        Elf_Shdr* section_header = nullptr;
        Elf_Shdr* symtab = nullptr;
        Elf_Shdr* strtab = nullptr;
        Elf_Shdr* dynsym = nullptr;
        Elf_Off dynsym_count = 0;
        Elf_Sym* symtab_start = nullptr;
        Elf_Sym* dynsym_start = nullptr;
        Elf_Sym* strtab_start = nullptr;
        Elf_Off symtab_count = 0;
        Elf_Off symstr_offset = 0;
        Elf_Off symstr_offset_for_symtab = 0;
        Elf_Off symtab_offset = 0;
        Elf_Off dynsym_offset = 0;
        Elf_Off symtab_size = 0;
        Elf_Off dynsym_size = 0;

        // New member variables for .gnu_debugdata support
        std::vector<uint8_t> debug_data_buffer;
        Elf_Ehdr* debug_header_ptr = nullptr;
        Elf_Shdr* debug_symtab = nullptr;
        Elf_Sym* debug_symtab_start = nullptr;
        Elf_Off debug_symtab_count = 0;
        Elf_Off debug_symtab_offset = 0;
        Elf_Off debug_symtab_size = 0;
        Elf_Off debug_symstr_offset = 0;
    };
} // namespace pine