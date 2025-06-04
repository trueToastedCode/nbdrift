// Enhanced ELF Image Parser with .gnu_debugdata support for Android 16+
// Handles compressed symbol tables in .gnu_debugdata sections

#include "elf_img.h"
#include <malloc.h>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <string_view>
#include <string>
#include "ulog.h"
#include <fcntl.h>
#include <errno.h>
#include <algorithm>
#include <lzma.h>  // For XZ decompression
#include <memory>
#include <vector>

using namespace pine;

inline bool CanRead(const char *file) {
    return access(file, R_OK) == 0;
}

// Helper function to decompress XZ data
std::vector<uint8_t> DecompressXZ(const uint8_t* compressed_data, size_t compressed_size) {
    lzma_stream strm = LZMA_STREAM_INIT;
    std::vector<uint8_t> decompressed;
    
    lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED);
    if (ret != LZMA_OK) {
        ULOGE("Failed to initialize XZ decoder: %d", ret);
        return decompressed;
    }
    
    strm.next_in = compressed_data;
    strm.avail_in = compressed_size;
    
    const size_t chunk_size = 4096;
    decompressed.resize(chunk_size);
    size_t total_out = 0;
    
    do {
        if (total_out + chunk_size > decompressed.size()) {
            decompressed.resize(decompressed.size() * 2);
        }
        
        strm.next_out = decompressed.data() + total_out;
        strm.avail_out = decompressed.size() - total_out;
        
        ret = lzma_code(&strm, LZMA_FINISH);
        total_out = strm.total_out;
        
    } while (ret == LZMA_OK);
    
    lzma_end(&strm);
    
    if (ret != LZMA_STREAM_END) {
        ULOGE("XZ decompression failed: %d", ret);
        return std::vector<uint8_t>();
    }
    
    decompressed.resize(total_out);
    ULOGD("XZ decompression successful: %zu -> %zu bytes", compressed_size, total_out);
    return decompressed;
}

void ElfImg::Init(const char *elf, jint android_version) {
    this->elf = elf;
    this->android_version = android_version;

    if (elf[0] == '/') {
        Open(elf, true);
    } else {
        RelativeOpen(elf, true);
    }
}

void ElfImg::ProcessGnuDebugData(const uint8_t* debug_data, size_t debug_size) {
    // Decompress the .gnu_debugdata section
    std::vector<uint8_t> decompressed = DecompressXZ(debug_data, debug_size);
    if (decompressed.empty()) {
        ULOGW("Failed to decompress .gnu_debugdata section");
        return;
    }
    
    // Treat decompressed data as an ELF file
    auto* debug_header = reinterpret_cast<Elf_Ehdr*>(decompressed.data());
    
    // Verify ELF magic
    if (decompressed.size() < sizeof(Elf_Ehdr) || 
        memcmp(debug_header->e_ident, ELFMAG, SELFMAG) != 0) {
        ULOGW("Invalid ELF magic in decompressed .gnu_debugdata");
        return;
    }
    
    // Store decompressed data so it stays valid
    debug_data_buffer = std::move(decompressed);
    debug_header_ptr = reinterpret_cast<Elf_Ehdr*>(debug_data_buffer.data());
    
    auto* debug_sections = reinterpret_cast<Elf_Shdr*>(
        debug_data_buffer.data() + debug_header_ptr->e_shoff);
    
    // Get section string table for debug ELF
    char* debug_section_str = nullptr;
    if (debug_header_ptr->e_shstrndx != SHN_UNDEF && 
        debug_header_ptr->e_shstrndx < debug_header_ptr->e_shnum) {
        debug_section_str = reinterpret_cast<char*>(
            debug_data_buffer.data() + debug_sections[debug_header_ptr->e_shstrndx].sh_offset);
    }
    
    // Process sections in the debug ELF
    for (int i = 0; i < debug_header_ptr->e_shnum; i++) {
        auto* section_h = &debug_sections[i];
        char* sname = debug_section_str ? (section_h->sh_name + debug_section_str) : nullptr;
        Elf_Off entsize = section_h->sh_entsize;
        
        if (section_h->sh_type == SHT_SYMTAB && sname && strcmp(sname, ".symtab") == 0) {
            // Found debug symbol table
            debug_symtab = section_h;
            debug_symtab_offset = section_h->sh_offset;
            debug_symtab_size = section_h->sh_size;
            if (entsize > 0) {
                debug_symtab_count = debug_symtab_size / entsize;
                debug_symtab_start = reinterpret_cast<Elf_Sym*>(
                    debug_data_buffer.data() + debug_symtab_offset);
            }
            ULOGD("Found debug .symtab with %lld symbols", (long long)debug_symtab_count);
        } else if (section_h->sh_type == SHT_STRTAB && sname && strcmp(sname, ".strtab") == 0) {
            // Found debug string table
            debug_symstr_offset = section_h->sh_offset;
            ULOGD("Found debug .strtab section");
        }
    }
}

void ElfImg::Open(const char *path, bool warn_if_symtab_not_found) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        ULOGE("failed to open %s", path);
        return;
    }

    size = lseek(fd, 0, SEEK_END);
    if (size <= 0) {
        ULOGE("lseek() failed for %s: errno %d (%s)", path, errno, strerror(errno));
        close(fd);
        return;
    }

    header = reinterpret_cast<Elf_Ehdr *>(mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0));
    close(fd);

    if (header == MAP_FAILED) {
        ULOGE("mmap() failed for %s: errno %d (%s)", path, errno, strerror(errno));
        header = nullptr;
        return;
    }

    // Verify ELF magic
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        ULOGE("Invalid ELF magic in %s", path);
        munmap(header, size);
        header = nullptr;
        return;
    }

    section_header = reinterpret_cast<Elf_Shdr *>(((uintptr_t) header) + header->e_shoff);
    auto shoff = reinterpret_cast<uintptr_t>(section_header);
    
    // Get section string table
    char *section_str = nullptr;
    if (header->e_shstrndx != SHN_UNDEF && header->e_shstrndx < header->e_shnum) {
        section_str = reinterpret_cast<char *>(
            section_header[header->e_shstrndx].sh_offset + ((uintptr_t) header));
    }

    // Counters for debugging
    int dynsym_sections = 0;
    int symtab_sections = 0;
    int strtab_sections = 0;
    bool found_gnu_debugdata = false;

    for (int i = 0; i < header->e_shnum; i++, shoff += header->e_shentsize) {
        auto *section_h = (Elf_Shdr *) shoff;
        char *sname = section_str ? (section_h->sh_name + section_str) : nullptr;
        Elf_Off entsize = section_h->sh_entsize;
        
        switch (section_h->sh_type) {
            case SHT_DYNSYM:
                dynsym_sections++;
                if (dynsym == nullptr) {
                    dynsym = section_h;
                    dynsym_offset = section_h->sh_offset;
                    dynsym_size = section_h->sh_size;
                    if (entsize > 0) {
                        dynsym_count = dynsym_size / entsize;
                        dynsym_start = reinterpret_cast<Elf_Sym *>(((uintptr_t) header) + dynsym_offset);
                    }
                    ULOGD("Found .dynsym section with %lld symbols", (long long)dynsym_count);
                }
                break;
                
            case SHT_SYMTAB:
                symtab_sections++;
                if (sname && strcmp(sname, ".symtab") == 0 && symtab == nullptr) {
                    symtab = section_h;
                    symtab_offset = section_h->sh_offset;
                    symtab_size = section_h->sh_size;
                    if (entsize > 0) {
                        symtab_count = symtab_size / entsize;
                        symtab_start = reinterpret_cast<Elf_Sym *>(((uintptr_t) header) + symtab_offset);
                    }
                    ULOGD("Found .symtab section with %lld symbols", (long long)symtab_count);
                }
                break;
                
            case SHT_STRTAB:
                strtab_sections++;
                if (sname) {
                    if (strcmp(sname, ".dynstr") == 0 && strtab == nullptr) {
                        strtab = section_h;
                        symstr_offset = section_h->sh_offset;
                        strtab_start = reinterpret_cast<Elf_Sym *>(((uintptr_t) header) + symstr_offset);
                        ULOGD("Found .dynstr section");
                    } else if (strcmp(sname, ".strtab") == 0) {
                        symstr_offset_for_symtab = section_h->sh_offset;
                        ULOGD("Found .strtab section");
                    }
                }
                break;
                
            case SHT_PROGBITS:
                // Check for .gnu_debugdata section
                if (sname && strcmp(sname, ".gnu_debugdata") == 0) {
                    found_gnu_debugdata = true;
                    ULOGD("Found .gnu_debugdata section, size: %lld", (long long)section_h->sh_size);
                    
                    // Process the compressed debug data
                    const uint8_t* debug_data = reinterpret_cast<const uint8_t*>(
                        ((uintptr_t) header) + section_h->sh_offset);
                    ProcessGnuDebugData(debug_data, section_h->sh_size);
                }
                
                // Calculate bias
                if (bias == -4396 && (dynsym != nullptr || symtab != nullptr)) {
                    bias = (off_t) section_h->sh_addr - (off_t) section_h->sh_offset;
                    ULOGD("Calculated bias: 0x%lx", bias);
                }
                break;
        }
    }

    // Enhanced logging for debugging
    ULOGD("ELF analysis for %s:", path);
    ULOGD("  DYNSYM sections: %d", dynsym_sections);
    ULOGD("  SYMTAB sections: %d", symtab_sections);
    ULOGD("  STRTAB sections: %d", strtab_sections);
    ULOGD("  GNU_DEBUGDATA: %s", found_gnu_debugdata ? "yes" : "no");
    ULOGD("  Dynamic symbols: %lld", (long long)dynsym_count);
    ULOGD("  Static symbols: %lld", (long long)symtab_count);
    ULOGD("  Debug symbols: %lld", (long long)debug_symtab_count);

    // Android 15+ specific handling
    if (android_version >= 35) {
        if (!symtab_offset && dynsym_count == 0 && debug_symtab_count == 0) {
            ULOGW("No usable symbol tables found in %s (Android %d)", path, android_version);
        } else if (!symtab_offset && debug_symtab_count == 0) {
            ULOGD("Only dynamic symbols available in %s (expected for Android %d+)", 
                  path, android_version);
        } else if (debug_symtab_count > 0) {
            ULOGD("Using debug symbols from .gnu_debugdata in %s", path);
        }
    } else {
        if (!symtab_offset && warn_if_symtab_not_found && debug_symtab_count == 0) {
            ULOGW("can't find symtab from sections in %s", path);
        }
    }

    // Load module base
    base = GetModuleBase(path);
}

void ElfImg::RelativeOpen(const char *elf, bool warn_if_symtab_not_found) {
    char buffer[128] = {0};
    
    if (android_version >= 29) {
        const char* apex_paths[] = {
            kApexArtLibDir,
            kApexRuntimeLibDir,
            nullptr
        };
        
        for (int i = 0; apex_paths[i] != nullptr; i++) {
            memset(buffer, 0, sizeof(buffer));
            strncpy(buffer, apex_paths[i], sizeof(buffer) - strlen(elf) - 1);
            strncat(buffer, elf, sizeof(buffer) - strlen(buffer) - 1);
            
            if (CanRead(buffer)) {
                ULOGD("Opening ELF from APEX: %s", buffer);
                Open(buffer, warn_if_symtab_not_found);
                return;
            }
        }
    }
    
    memset(buffer, 0, sizeof(buffer));
    strncpy(buffer, kSystemLibDir, sizeof(buffer) - strlen(elf) - 1);
    strncat(buffer, elf, sizeof(buffer) - strlen(buffer) - 1);
    ULOGD("Opening ELF from system: %s", buffer);
    Open(buffer, warn_if_symtab_not_found);
}

ElfImg::~ElfImg() {
    if (buffer) {
        free(buffer);
        buffer = nullptr;
    }
    if (header) {
        munmap(header, size);
        header = nullptr;
    }
    // debug_data_buffer will be automatically cleaned up by vector destructor
}

Elf_Addr ElfImg::GetSymbolOffset(std::string_view name, bool warn_if_missing, bool match_prefix) const {
    Elf_Addr _offset = 0;

    // First try debug symbols from .gnu_debugdata (most comprehensive for Android 15+)
    if (debug_symtab_start != nullptr && debug_symstr_offset != 0 && debug_symtab_count > 0) {
        for (Elf_Off i = 0; i < debug_symtab_count; i++) {
            unsigned int st_type = ELF_ST_TYPE(debug_symtab_start[i].st_info);
            
            if (debug_symstr_offset + debug_symtab_start[i].st_name >= debug_data_buffer.size()) {
                continue;
            }
            
            const char *st_name = reinterpret_cast<const char *>(
                debug_data_buffer.data() + debug_symstr_offset + debug_symtab_start[i].st_name);
            
            if (st_type == STT_FUNC && debug_symtab_start[i].st_size) {
                auto s = std::string_view(st_name);
                if (name.compare(s) == 0 || (match_prefix && s.starts_with(name))) {
                    _offset = debug_symtab_start[i].st_value;
                    ULOGD("Found symbol '%s' in debug symtab: 0x%lx", std::string(name).c_str(), _offset);
                    return _offset;
                }
            }
        }
    }

    // Search dynamic symbol table
    if (dynsym_start != nullptr && strtab_start != nullptr && dynsym_count > 0) {
        Elf_Sym *sym = dynsym_start;
        char *strings = (char *) strtab_start;
        
        for (Elf_Off k = 0; k < dynsym_count; k++, sym++) {
            if (sym->st_name >= (symstr_offset + size - ((uintptr_t)header - (uintptr_t)strings))) {
                continue;
            }
            
            auto s = std::string_view(strings + sym->st_name);
            if (name.compare(s) == 0 || (match_prefix && s.starts_with(name))) {
                _offset = sym->st_value;
                ULOGD("Found symbol '%s' in dynsym: 0x%lx", std::string(name).c_str(), _offset);
                return _offset;
            }
        }
    }

    // Fallback to static symbol table
    if (symtab_start != nullptr && symstr_offset_for_symtab != 0 && symtab_count > 0) {
        for (Elf_Off i = 0; i < symtab_count; i++) {
            unsigned int st_type = ELF_ST_TYPE(symtab_start[i].st_info);
            
            if (symstr_offset_for_symtab + symtab_start[i].st_name >= size) {
                continue;
            }
            
            char *st_name = reinterpret_cast<char *>(((uintptr_t) header) +
                                                   symstr_offset_for_symtab +
                                                   symtab_start[i].st_name);
            
            if (st_type == STT_FUNC && symtab_start[i].st_size) {
                auto s = std::string_view(st_name);
                if (name.compare(s) == 0 || (match_prefix && s.starts_with(name))) {
                    _offset = symtab_start[i].st_value;
                    ULOGD("Found symbol '%s' in symtab: 0x%lx", std::string(name).c_str(), _offset);
                    return _offset;
                }
            }
        }
    }
    
    if (warn_if_missing) {
        if (android_version >= 35) {
            ULOGE("Symbol '%s' not found in %s (Android %d - checked %lld debug, %lld dynamic, %lld static symbols)", 
                  std::string(name).c_str(), elf, android_version, 
                  (long long)debug_symtab_count, (long long)dynsym_count, (long long)symtab_count);
        } else {
            ULOGE("Symbol '%s' not found in elf %s", std::string(name).c_str(), elf);
        }
    }
    return 0;
}

void *ElfImg::GetSymbolAddress(std::string_view name, bool warn_if_missing, bool match_prefix) const {
    Elf_Addr offset = GetSymbolOffset(name, warn_if_missing, match_prefix);
    if (offset > 0 && base != nullptr) {
        return reinterpret_cast<void *>((uintptr_t) base + offset - bias);
    } else {
        return nullptr;
    }
}

void *ElfImg::GetModuleBase(const char *name) {
    FILE *maps;
    char buff[512];
    off_t load_addr;
    bool found = false;
    
    maps = fopen("/proc/self/maps", "re");
    if (!maps) {
        ULOGE("failed to open /proc/self/maps");
        return nullptr;
    }
    
    while (fgets(buff, sizeof(buff), maps)) {
        if (strstr(buff, name) && (strstr(buff, "r-xp") || strstr(buff, "r--p"))) {
            found = true;
            break;
        }
    }

    if (!found) {
        ULOGE("failed to read load address for %s", name);
        fclose(maps);
        return nullptr;
    }

    if (sscanf(buff, "%lx", &load_addr) != 1) {
        ULOGE("failed to parse load address for %s", name);
        fclose(maps);
        return nullptr;
    }

    fclose(maps);
    return reinterpret_cast<void *>(load_addr);
}