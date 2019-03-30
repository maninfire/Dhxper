//
// Created by 邓维佳 on 2018/3/13.
//

#ifndef XPOSEDDEMO_COMMON_H
#define XPOSEDDEMO_COMMON_H

#include <stdint.h>
#include <assert.h>
#include <android/log.h>

#define TAG "libunshellnativea"
#ifdef __cplusplus
extern "C" {
#endif
typedef uint8_t byte;
typedef uint8_t u1;
typedef uint16_t u2;
typedef uint32_t u4;
typedef uint64_t u8;
typedef int8_t s1;
typedef int16_t s2;
typedef int32_t s4;
typedef int64_t s8;

#define  ALOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))
#define  ALOGV(...) ((void)__android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__))
#define  ALOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__))
#define  ALOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define  ALOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#define LOGVV ALOGV


#ifdef __cplusplus
}
#endif
#endif //XPOSEDDEMO_COMMON_H
