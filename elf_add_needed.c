#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

int is_elf_file(const unsigned char *e_ident) {
    return (e_ident[EI_MAG0] == ELFMAG0 &&
            e_ident[EI_MAG1] == ELFMAG1 &&
            e_ident[EI_MAG2] == ELFMAG2 &&
            e_ident[EI_MAG3] == ELFMAG3);
}

void overwrite_needed_entry(const char *filename, const char *old_lib, const char *new_lib) {
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        perror("Error opening file");
        exit(1);
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("Error getting file size");
        close(fd);
        exit(1);
    }

    void *file_data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (file_data == MAP_FAILED) {
        perror("Error mapping file");
        close(fd);
        exit(1);
    }

    if (!is_elf_file(file_data)) {
        fprintf(stderr, "Not a valid ELF file\n");
        munmap(file_data, st.st_size);
        close(fd);
        exit(1);
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file_data;
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)file_data + ehdr->e_shoff);
    char *shstrtab = (char *)file_data + shdr[ehdr->e_shstrndx].sh_offset;

    // Find .dynamic and .dynstr sections
    int dynamic_idx = -1, dynstr_idx = -1;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *name = shstrtab + shdr[i].sh_name;
        if (strcmp(name, ".dynamic") == 0) dynamic_idx = i;
        if (strcmp(name, ".dynstr") == 0) dynstr_idx = i;
    }

    if (dynamic_idx == -1 || dynstr_idx == -1) {
        fprintf(stderr, "Missing .dynamic or .dynstr section\n");
        munmap(file_data, st.st_size);
        close(fd);
        exit(1);
    }

    Elf64_Dyn *dyn = (Elf64_Dyn *)((char *)file_data + shdr[dynamic_idx].sh_offset);
    char *dynstr = (char *)file_data + shdr[dynstr_idx].sh_offset;

    // Find the DT_NEEDED entry for `old_lib`
    int target_idx = -1;
    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        if (dyn[i].d_tag == DT_NEEDED) {
            char *lib = dynstr + dyn[i].d_un.d_val;
            if (strcmp(lib, old_lib) == 0) {
                target_idx = i;
                break;
            }
        }
    }

    if (target_idx == -1) {
        fprintf(stderr, "Could not find DT_NEEDED entry for '%s'\n", old_lib);
        munmap(file_data, st.st_size);
        close(fd);
        exit(1);
    }

    // Check if new_lib fits in the existing space
    size_t old_len = strlen(old_lib) + 1; // Include null terminator
    size_t new_len = strlen(new_lib) + 1;
    if (new_len > old_len) {
        fprintf(stderr, "New library name is too long (max %zu bytes)\n", old_len);
        munmap(file_data, st.st_size);
        close(fd);
        exit(1);
    }

    // Overwrite the old library name in .dynstr
    char *target_str = dynstr + dyn[target_idx].d_un.d_val;
    strncpy(target_str, new_lib, old_len); // Ensure null termination
    target_str[old_len - 1] = '\0'; // Safety in case new_lib is shorter

    printf("Replaced '%s' with '%s' in DT_NEEDED\n", old_lib, new_lib);

    munmap(file_data, st.st_size);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <elf_file> <old_library> <new_library>\n", argv[0]);
        fprintf(stderr, "Example: %s lib.so olddep.so libfoo.so\n", argv[0]);
        return 1;
    }
    overwrite_needed_entry(argv[1], argv[2], argv[3]);
    return 0;
}