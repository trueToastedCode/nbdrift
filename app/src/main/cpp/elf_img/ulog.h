#ifndef XPOSED_LOG_H
#define XPOSED_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <android/log.h>

enum uLogType {
    UDEBUG = 3,
    UERROR = 6,
    UINFO  = 4,
    UWARN  = 5
};

#define UTAG "elfimg"

#define ULOGD(...) ((void) __android_log_print(UDEBUG, UTAG, __VA_ARGS__))
#define ULOGE(...) ((void) __android_log_print(UERROR, UTAG, __VA_ARGS__))
#define ULOGI(...) ((void) __android_log_print(UINFO,  UTAG, __VA_ARGS__))
#define ULOGW(...) ((void) __android_log_print(UWARN,  UTAG, __VA_ARGS__))

#ifdef __cplusplus
}
#endif

#endif //XPOSED_LOG_H