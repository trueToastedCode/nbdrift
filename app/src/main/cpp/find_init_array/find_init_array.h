#ifndef ELF_INIT_ARRAY_H
#define ELF_INIT_ARRAY_H

#include <cstdint>
#include <optional>

namespace find_init_array {

#define LOG_TAG "find_init_array"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/**
 * @brief Find the INIT_ARRAY address in a 64-bit ELF image loaded in memory
 * 
 * @param elf_ptr Pointer to the in-memory ELF image
 * @return std::optional<uint64_t> INIT_ARRAY address if found, empty optional otherwise
 */
std::optional<uint64_t> find_init_array(const void* elf_ptr);

} // namespace elf_utils

#endif // ELF_INIT_ARRAY_H