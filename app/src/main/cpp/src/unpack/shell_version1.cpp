//
// Created by 袁东明 on 2017/7/1.
//
//http://blog.csdn.net/QQ1084283172/article/details/78092365?locationNum=3&fps=1

extern "C" {
#include "inlinehook/inlineHook.h"
#include "inlinehook/dlopen.h"
}

#include "DvmFunctionTable.h"

#include <unistd.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <string>
#include <dlfcn.h>
#include "init.h"


static char pname[256];


void dumpFileName(char *name, int len, const char *pname, int dexlen, u_int8_t *data) {
    time_t now;
    time(&now);
    memset(name, 0, len);

    //读取签名位
    char signature_str[41];
    char dexName[] = {(char) -23, (char) 4, (char) -56, (char) 34, (char) 94};
    int dexNameLength = sizeof(dexName);
    for (int i = 0; i < 20; i++) {
        dexName[i % dexNameLength] ^= *(data + 0x0c + i);
    }
    //第12个字节后，为apk签名段，其长度为20个字节
    toHex(signature_str, (const char *) dexName, dexNameLength);
    signature_str[dexNameLength] = '\0';

    sprintf(name, "/data/data/%s/files/dumpSmali/dump_version1/dump_size_%u_%s.dex", pname, dexlen,
            signature_str);
}

void writeToFile(const char *pname, u_int8_t *data, size_t length) {
    char dname[1024];
    dumpFileName(dname, sizeof(dname), pname, length, data);
    __android_log_print(ANDROID_LOG_ERROR, TAG, "dump dex file name is : %s", dname);
    __android_log_print(ANDROID_LOG_ERROR, TAG, "start dump");
    int dex = open(dname, O_CREAT | O_WRONLY, 0644);
    if (dex < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "open or create file error");
        return;
    }
    int ret = write(dex, data, length);
    if (ret < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "write file error");
    } else {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "dump dex file success `%s`", dname);
    }
    close(dex);
}

art::DexFile *(*old_openmemory)(const byte *base, size_t size, const std::string &location,
                                uint32_t location_checksum, art::MemMap *mem_map,
                                const art::OatDexFile *oat_dex_file, std::string *error_msg) = NULL;

art::DexFile *new_openmemory(const byte *base, size_t size, const std::string &location,
                             uint32_t location_checksum, art::MemMap *mem_map,
                             const art::OatDexFile *oat_dex_file, std::string *error_msg) {
    __android_log_print(ANDROID_LOG_ERROR, TAG, "art::DexFile::OpenMemory is called");
    writeToFile(pname, (uint8_t *) base, size);
    return (*old_openmemory)(base, size, location, location_checksum, mem_map, oat_dex_file,
                             error_msg);
}


art::DexFile *(*old_openmemory_23)(void *DexFile_thiz, char *base, int size, void *location,
                                   void *location_checksum, void *mem_map, void *oat_dex_file,
                                   void *error_meessage) = NULL;

art::DexFile *new_openmemory_23(void *DexFile_thiz, char *base, int size, void *location,
                                void *location_checksum, void *mem_map, void *oat_dex_file,
                                void *error_meessage) {
    writeToFile(pname, (u_int8_t *) base, size);
    return (*old_openmemory_23)(DexFile_thiz, base, size, location, location_checksum, mem_map,
                                oat_dex_file, error_meessage);
}

DexFile *(*old_dexFileParse)(const u1 *data, size_t length, int flags) = NULL;

DexFile *new_dexFileParse(const u1 *data, size_t length, int flags) {
    writeToFile(pname, (u_int8_t *) data, length);
    return (*old_dexFileParse)(data, length, flags);
}

DvmDex *(*old_dvmDexFileOpenPartial)(const void *addr, int len, DvmDex **ppDvmDex) = NULL;

DvmDex *new_dvmDexFileOpenPartial(const void *addr, int len, DvmDex **ppDvmDex) {
    writeToFile(pname, (u_int8_t *) addr, len);
    return (*old_dvmDexFileOpenPartial)(addr, len, ppDvmDex);
}

void hook_dvm() {

    void *libVMhandle = dlopen("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);
    void *addr = findFunction("_Z12dexFileParsePKhji", libVMhandle);
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Unable find symbol _Z12dexFileParsePKhji");
        return;
    }
    if (registerInlineHook((uint32_t) addr, (uint32_t) new_dexFileParse,
                           (uint32_t **) &old_dexFileParse) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    if (inlineHook((uint32_t) addr) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    addr = findFunction("_Z21dvmDexFileOpenPartialPKviPP6DvmDex", libVMhandle);
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "Unable find symbol _Z21dvmDexFileOpenPartialPKviPP6DvmDex");
        return;
    }
    if (registerInlineHook((uint32_t) addr, (uint32_t) new_dvmDexFileOpenPartial,
                           (uint32_t **) &old_dvmDexFileOpenPartial) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    if (inlineHook((uint32_t) addr) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    dlclose(libVMhandle);
}

void hook_21_22() {
    void *handle = dlopen("libart.so", RTLD_GLOBAL | RTLD_LAZY);
    if (handle == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Error: unable to find the SO : libart.so");
        return;
    }
    void *addr = dlsym(handle,
                       "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "Error: unable to find the Symbol : _ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");
        return;
    }

    if (registerInlineHook((uint32_t) addr, (uint32_t) new_openmemory,
                           (uint32_t **) &old_openmemory) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    if (inlineHook((uint32_t) addr) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "register hook success");
}

void hook_23_plus() {
    void *handle = ndk_dlopen("libart.so", RTLD_GLOBAL | RTLD_LAZY);
    if (handle == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Error: unable to find the SO : libart.so");
        return;
    }
    void *addr = ndk_dlsym(handle,
                           "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "Error: unable to find the Symbol : _ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");
        return;
    }

    if (registerInlineHook((uint32_t) addr, (uint32_t) new_openmemory_23,
                           (uint32_t **) &old_openmemory_23) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    if (inlineHook((uint32_t) addr) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "register hook success");
}


extern "C"
JNIEXPORT void JNICALL
Java_com_virjar_ucrack_plugin_unpack_Dumper_dumpVersion1(JNIEnv *env, jclass clazz) {
    getProcessName(getpid(), pname, sizeof(pname));
    int api = apiLevel();
    if (api < 21) {
        hook_dvm();
    } else if (api < 23) {
        hook_21_22();
    } else {
        ndk_init(env);
        hook_23_plus();
    }
}
extern "C"
JNIEXPORT void JNICALL
Java_com_virjar_ucrack_plugin_unpack_Dumper_dumpVersion3(JNIEnv *env, jclass clazz) {
    getProcessName(getpid(), pname, sizeof(pname));
    int api = apiLevel();
    if (api < 21) {
    hook_dvm();
    } else if (api < 23) {
    hook_21_22();
    } else {
    ndk_init(env);
    hook_23_plus();
    }
}
