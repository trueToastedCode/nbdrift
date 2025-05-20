#include "find_init_array.h"
#include <elf.h>
#include <cstring>
#include <android/log.h>

namespace find_init_array {

std::optional<uint64_t> find_init_array(const void* elf_ptr) {
    LOGI("find_init_array called with elf_ptr: %p", elf_ptr);
    
    if (!elf_ptr) {
        LOGE("elf_ptr is null");
        return std::nullopt;
    }

    // Check ELF header magic number
    const Elf64_Ehdr* ehdr = static_cast<const Elf64_Ehdr*>(elf_ptr);
    LOGI("ELF header at %p, checking magic number", ehdr);
    
    // Dump the first few bytes to verify what we're looking at
    LOGI("ELF magic bytes: %02X %02X %02X %02X", 
         ehdr->e_ident[0], ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
    
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("Not an ELF file - invalid magic number");
        return std::nullopt; // Not an ELF file
    }

    // Verify this is a 64-bit ELF file
    LOGI("ELF class: %d (1=32-bit, 2=64-bit)", ehdr->e_ident[EI_CLASS]);
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        LOGE("Not a 64-bit ELF file (class=%d)", ehdr->e_ident[EI_CLASS]);
        return std::nullopt; // Not a 64-bit ELF file
    }

    // Log all important ELF header information
    LOGI("ELF type: %d, machine: %d, version: %d", ehdr->e_type, ehdr->e_machine, ehdr->e_version);
    LOGI("Entry point: 0x%lx", ehdr->e_entry);
    LOGI("Program header offset: 0x%lx, size: %d, count: %d", ehdr->e_phoff, ehdr->e_phentsize, ehdr->e_phnum);
    LOGI("Section header offset: 0x%lx, size: %d, count: %d", ehdr->e_shoff, ehdr->e_shentsize, ehdr->e_shnum);

    // Get program headers
    const Elf64_Phdr* phdr = reinterpret_cast<const Elf64_Phdr*>(
        reinterpret_cast<const uint8_t*>(elf_ptr) + ehdr->e_phoff);
    
    LOGI("Program headers at offset 0x%lx (%p)", ehdr->e_phoff, phdr);
    
    // Log all program headers
    LOGI("Scanning %d program headers:", ehdr->e_phnum);
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        LOGI("  Program header %d: type=%d, offset=0x%lx, vaddr=0x%lx, paddr=0x%lx, filesz=%lu, memsz=%lu",
             i, phdr[i].p_type, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, 
             phdr[i].p_filesz, phdr[i].p_memsz);
    }
    
    // Find the dynamic segment
    const Elf64_Phdr* dyn_phdr = nullptr;
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn_phdr = &phdr[i];
            LOGI("Found PT_DYNAMIC segment at program header %d", i);
            break;
        }
    }

    if (!dyn_phdr) {
        LOGE("No dynamic segment found");
        return std::nullopt; // No dynamic segment found
    }

    LOGI("Dynamic segment: offset=0x%lx, vaddr=0x%lx, size=%lu", 
         dyn_phdr->p_offset, dyn_phdr->p_vaddr, dyn_phdr->p_filesz);

    // Check if we might be dealing with load address vs file offset issue
    const uint8_t* base_addr = reinterpret_cast<const uint8_t*>(elf_ptr);
    LOGI("Base address of memory map: %p", base_addr);
    
    // Try both absolute and relative addressing for the dynamic section
    const Elf64_Dyn* dyn_absolute = reinterpret_cast<const Elf64_Dyn*>(dyn_phdr->p_vaddr);
    const Elf64_Dyn* dyn_relative = reinterpret_cast<const Elf64_Dyn*>(base_addr + dyn_phdr->p_offset);
    const Elf64_Dyn* dyn_direct_vaddr = reinterpret_cast<const Elf64_Dyn*>(base_addr + dyn_phdr->p_vaddr);
    
    LOGI("Dynamic section address calculations:");
    LOGI("  From offset: %p (base + p_offset = %p + 0x%lx)", dyn_relative, base_addr, dyn_phdr->p_offset);
    LOGI("  From vaddr: %p (direct vaddr = 0x%lx)", dyn_absolute, dyn_phdr->p_vaddr);
    LOGI("  From base+vaddr: %p (base + p_vaddr = %p + 0x%lx)", dyn_direct_vaddr, base_addr, dyn_phdr->p_vaddr);
    
    // Use the offset-based calculation for standard file mapping
    const Elf64_Dyn* dyn = dyn_direct_vaddr; // Use va offset-based by default
    
    // Log dynamic entries
    LOGI("Scanning dynamic entries:");
    int dynamic_count = 0;
    bool init_array_found = false;
    uint64_t init_array_addr = 0;
    
    // First, dump the raw memory to check if there's anything there
    const uint64_t* raw_mem = reinterpret_cast<const uint64_t*>(dyn);
    LOGI("First 64 bytes of dynamic section:");
    for (int i = 0; i < 8; i++) {
        LOGI("  Bytes %d-%d: 0x%016lx", i*8, (i+1)*8-1, raw_mem[i]);
    }
    
    // Try a different approach to scanning dynamic entries
    // Check at least the first 56 entries (448 bytes / 8 bytes per entry)
    int max_entries = dyn_phdr->p_filesz / sizeof(Elf64_Dyn);
    LOGI("Maximum possible dynamic entries based on size: %d", max_entries);
    
    // Safety check - don't scan more than 100 entries to prevent infinite loops
    if (max_entries > 100) max_entries = 100;
    
    for (int i = 0; i < max_entries; i++) {
        dynamic_count++;
        LOGI("  Dynamic entry %d: tag=0x%lx (%ld), value=0x%lx", 
             i, dyn[i].d_tag, dyn[i].d_tag, dyn[i].d_un.d_ptr);
        
        if (dyn[i].d_tag == DT_INIT_ARRAY) {
            init_array_addr = dyn[i].d_un.d_ptr;
            LOGI("  Found DT_INIT_ARRAY at entry %d, address: 0x%lx", i, init_array_addr);
            init_array_found = true;
        }
        
        // Check for NULL terminator (but don't break the loop yet to show all entries)
        if (dyn[i].d_tag == DT_NULL) {
            LOGI("  Found DT_NULL terminator at entry %d", i);
            if (i == 0) {
                LOGE("  First dynamic entry is NULL - possible memory alignment issue");
            }
        }
    }
    
    LOGI("Total dynamic entries: %d", dynamic_count);
    
    if (init_array_found) {
        LOGI("Returning INIT_ARRAY address: 0x%lx", init_array_addr);
        return init_array_addr;
    } else {
        LOGE("DT_INIT_ARRAY not found in dynamic section");
        return std::nullopt;
    }
}

} // namespace find_init_array