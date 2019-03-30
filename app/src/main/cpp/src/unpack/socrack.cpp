//
// Created by 邓维佳 on 2018/5/17.
// so相关破解功能的native层逻辑

#include <jni.h>
#include "oo/Object.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "elf.h"
#include <dlfcn.h>
#include "DvmFunctionTable.h"
#include "init.h"
#include "unpack/NativeStackTrace.h"
#include "linker.h"


extern "C" {
#include "inlinehook/inlineHook.h"
}

//对so信息做一些必要的修复
jobject repairSoInfo(soinfo *, JNIEnv *);

//打印指定方法对应的native函数信息
void printTargetMethodSymbol(soinfo *lib, void *methodAddr);

//寻找so的链表，由于该链表在linker的内部变量中，无法直接通过dlsym拿到，我们通过获取链表头部数据的方式，拿到他的引用
soinfo *findSoLinkHeader() {
    return (soinfo *) dlopen("libc.so", RTLD_GLOBAL | RTLD_LAZY);
}


extern "C"
JNIEXPORT jobject JNICALL
Java_com_virjar_ucrack_plugin_socrack_SoInfoHelper_allLoadLibs(JNIEnv *env, jclass type) {

    //方案1：读取 /proc/self/maps文件，并且解析
    //方案2：寻找dvm的DvmGlobals.nativeLibs属性，该属性是一个SharedLib结构，SharedLib中包含pathName，是一个so的绝对路径
    //第二个方案更加优秀，但是难度更大
    //方案三，通过获取libc.so，加载第一个so链表头部so资源
    jobject arrayList = createArrayList(env);

    soinfo *next = findSoLinkHeader();
    while (next != NULL) {
        addToArrayList(env, arrayList, env->NewStringUTF(next->name));
        next = next->next;
    }
    return arrayList;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_virjar_ucrack_plugin_socrack_SoInfoHelper_soLocationNative(JNIEnv *env, jclass type,
                                                                    jobject declaringClass,
                                                                    jstring MethodName_,
                                                                    jstring Signature_) {

    const char *Signature = env->GetStringUTFChars(Signature_, 0);
    const char *MethodName = env->GetStringUTFChars(MethodName_, 0);

    FILE *fp;
    char line[1024];
    char line2[1024];
    uint32_t start;
    uint32_t end;
    uint32_t addr;

    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            declaringClass);

    Method *method = dvmFindDirectMethodByDescriptor(clazz, MethodName, Signature);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, MethodName, Signature);
    }
    strcpy(line2, "not fond method!!");
    if (method == NULL) {
        goto bail;
    }

    addr = (uint32_t) method->insns;
    if (addr == NULL) {
        strcpy(line2, "please call native method first");
        goto bail;
    }

    ALOGE("the method address:%x", method->insns);
    fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        strcpy(line2, "failed  to read /proc/self/maps");
        goto bail;
    }

    while (fgets(line, sizeof(line), fp)) {

        if (strstr(line, "r-xp")) {
            strcpy(line2, line);
            start = strtoul(strtok(line, "-"), NULL, 16);
            end = strtoul(strtok(NULL, " "), NULL, 16);
            if (addr >= start && addr <= end) {
                fclose(fp);
                goto bail;
            }
        }
    }
    strcpy(line2, "not fond!!");
    fclose(fp);

    bail:
    env->ReleaseStringUTFChars(MethodName_, MethodName);
    env->ReleaseStringUTFChars(Signature_, Signature);
    return env->NewStringUTF(line2);
}

void (*oldDvmUseJNIBridge)(Method *method, void *func);

void newDvmUseJNIBridge(Method *method, void *func) {
    const char *descriptor = method->clazz->descriptor;
    const char *name = method->name;
    const char *shorty = method->shorty;

    ALOGE("register native function for class:%s for method:%s with methodSignature:%s ,function Address:%x",
          descriptor,
          name,
          shorty,
          func);
    if (strcmp(name, "getmRegistrationId") == 0) {
        //这里非常适合拦截堆栈，比jni_onload 容易拦截
        printNativeStackTrace();
    }
    oldDvmUseJNIBridge(method, func);
}

static bool RegisterNativesMethodHooked = false;

extern "C"
JNIEXPORT void JNICALL
Java_com_virjar_ucrack_plugin_socrack_SoInfoHelper_monitorRegisterNativesNative(JNIEnv *env,
                                                                                jclass type) {
    if (RegisterNativesMethodHooked) {
        return;
    }
    RegisterNativesMethodHooked = true;


    //_Z15dvmUseJNIBridgeP6MethodPv

    void *libVMhandle = dlopen("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);
    void *addr = findFunction("_Z15dvmUseJNIBridgeP6MethodPv", libVMhandle);
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "Unable find symbol _Z15dvmUseJNIBridgeP6MethodPv");
        return;
    }
    if (registerInlineHook((uint32_t) addr, (uint32_t) newDvmUseJNIBridge,
                           (uint32_t **) &oldDvmUseJNIBridge) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }

    if (inlineHook((uint32_t) addr) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }
    dlclose(libVMhandle);
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_virjar_ucrack_plugin_socrack_SoInfoHelper_dumpSoNative(JNIEnv *env, jclass type,
                                                                jobject declaringClass,
                                                                jstring MethodName_,
                                                                jstring Signature_) {
    const char *Signature = env->GetStringUTFChars(Signature_, 0);
    const char *MethodName = env->GetStringUTFChars(MethodName_, 0);

    uint32_t addr;
    jobject ret = NULL;
    soinfo *next;

    //首先，寻找到method对应的native代码的地址
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            declaringClass);

    Method *method = dvmFindDirectMethodByDescriptor(clazz, MethodName, Signature);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, MethodName, Signature);
    }

    if (method == NULL) {
        threwIllegalStateException(env, "can not find the method");
        goto bail;
    }

    addr = (uint32_t) method->insns;
    if (addr == NULL) {
        threwIllegalStateException(env, "please call native method first");
        goto bail;
    }

    //然后遍历so的链表
    next = findSoLinkHeader();
    while (next != NULL) {
        if ((next->base <= addr) && (addr <= next->base + next->size)) {
            //hinted
            ALOGE("hint so:%s", next->name);
            break;
        }
        next = next->next;
    }
    if (next == NULL) {
        threwIllegalStateException(env, "can not located the so node");
        goto bail;
    }
    ALOGE("find so:%s", next->name);
    /* 修改整个映射为可读属性 */
    mprotect((void *) next->base,
             next->size,
             7);/* 全部权限打开 */



    ret = repairSoInfo(next, env);
    printTargetMethodSymbol(next, (void *) method->insns);
    bail:
    env->ReleaseStringUTFChars(MethodName_, MethodName);
    env->ReleaseStringUTFChars(Signature_, Signature);
    return ret;
}

void fix_entry(unsigned char *buf, soinfo *lib) {
    unsigned *d = (unsigned int *) lib->dynamic;
    while (*d) {
        if (*d == DT_INIT) {
            unsigned offset = (unsigned) (d + 1) - lib->base;
            *(unsigned *) (void *) (buf + offset) = 0;
            break;
        }
        d += 2;
    }
}

/**
 * 检查PT_DYNAMIC程序头，这里面有大量so的数据定位信息
 */
void checkDynamicProgramHeader(unsigned char *buf, soinfo *lib, Elf32_Dyn *d) {

    soinfo *si = (soinfo *) malloc(sizeof(soinfo));
    strcpy(si->name, lib->name);
    //读取so内存布局信息
    for (; d->d_tag != DT_NULL; ++d) {
        ALOGE("d = %p, d[0](tag) = 0x%08x d[1](val) = 0x%08x", d, d->d_tag, d->d_un.d_val);
        switch (d->d_tag) {
            case DT_HASH:
                si->nbucket = ((unsigned *) (lib->base + d->d_un.d_ptr))[0];
                si->nchain = ((unsigned *) (lib->base + d->d_un.d_ptr))[1];
                si->bucket = (unsigned *) (lib->base + d->d_un.d_ptr + 8);
                si->chain = (unsigned *) (lib->base + d->d_un.d_ptr + 8 + si->nbucket * 4);
                //check内存布局的数据，和lib中的数据是否一致
                if (si->nbucket != lib->nbucket || si->nchain != lib->nchain ||
                    si->bucket != lib->bucket ||
                    si->chain != lib->chain) {
                    ALOGE("soinfo中的hash节和内存布局不一致");
                    ALOGE("soinfo nbucket:%d nchain:%d bucket:%p  chain:%p", lib->nbucket,
                          lib->nchain,
                          lib->bucket, lib->chain);
                    ALOGE("memory nbucket:%d nchain:%d bucket:%p  chain:%p", si->nbucket,
                          si->nchain,
                          si->bucket, si->chain);
                    d->d_un.d_ptr = (unsigned char *) lib->bucket - 8 - (unsigned char *) lib->base;
                }
                break;
            case DT_STRTAB:
                si->strtab = (const char *) ((unsigned char *) lib->base + d->d_un.d_ptr);
                if (si->strtab != lib->strtab) {
                    ALOGE("soinfo中的strtab节和内存布局不一致,soinfo->strtab:%u memory->strtab:%u",
                          lib->strtab,
                          si->strtab);
                    d->d_un.d_ptr = (unsigned char *) lib->strtab - (unsigned char *) lib->base;
                }
                break;
            case DT_SYMTAB:
                si->symtab = (Elf32_Sym *) ((unsigned char *) lib->base + d->d_un.d_ptr);
                if (si->symtab != lib->symtab) {
                    ALOGE("soinfo中的symtab节和内存布局不一致,soinfo->symtab:%u memory->symtab:%u",
                          lib->symtab,
                          si->symtab);
                    d->d_un.d_ptr = (unsigned char *) lib->symtab - (unsigned char *) lib->base;
                }
                break;
            case DT_JMPREL:
                si->plt_rel = (Elf32_Rel *) ((unsigned char *) lib->base + d->d_un.d_ptr);
                if (si->plt_rel != lib->plt_rel) {
                    ALOGE("soinfo中的plt_rel节和内存布局不一致,soinfo->plt_rel:%u memory->plt_rel:%u",
                          lib->plt_rel,
                          si->plt_rel);
                    d->d_un.d_ptr = (unsigned char *) lib->plt_rel - (unsigned char *) lib->base;
                }
                break;
            case DT_PLTRELSZ:
                si->plt_rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                if (si->plt_rel_count != lib->plt_rel_count) {
                    ALOGE("soinfo中的plt_rel_count节和内存布局不一致,soinfo->plt_rel_count:%d memory->plt_rel_count:%d",
                          lib->plt_rel_count,
                          si->plt_rel_count);
                    d->d_un.d_val = lib->plt_rel_count * sizeof(Elf32_Rel);
                }
                break;
            case DT_REL:
                si->rel = (Elf32_Rel *) ((unsigned char *) lib->base + d->d_un.d_ptr);
                if (si->rel != lib->rel) {
                    ALOGE("soinfo中的rel节和内存布局不一致,soinfo->rel:%u memory->rel:%u",
                          lib->rel,
                          si->rel);
                    d->d_un.d_ptr = (unsigned char *) lib->rel - (unsigned char *) lib->base;
                }
                break;
            case DT_RELSZ:
                si->rel_count = d->d_un.d_val / sizeof(Elf32_Rel);
                if (si->rel_count != lib->rel_count) {
                    ALOGE("soinfo中的rel_count节和内存布局不一致,soinfo->rel_count:%d memory->rel_count:%d",
                          lib->rel_count,
                          si->rel_count);
                    d->d_un.d_val = lib->rel_count * sizeof(Elf32_Rel);
                }
                break;
            case DT_PLTGOT:
                /* Save this in case we decide to do lazy binding. We don't yet. */
                si->plt_got = (unsigned *) ((unsigned char *) lib->base + d->d_un.d_ptr);
                if (si->plt_got != lib->plt_got) {
                    ALOGE("soinfo中的plt_got节和内存布局不一致,soinfo->plt_got:%u memory->plt_got:%u",
                          lib->plt_got,
                          si->plt_got);
                    d->d_un.d_ptr = (unsigned char *) lib->plt_got - (unsigned char *) lib->base;
                }
                break;
            case DT_INIT:
                si->init_func = reinterpret_cast<linker_function_t> ((unsigned char *) lib->base +
                                                                     d->d_un.d_ptr);
                ALOGE("%s constructors (DT_INIT) found at %p", si->name, si->init_func);
                if (si->init_func != lib->init_func) {
                    ALOGE("soinfo中的init_func节和内存布局不一致,soinfo->init_func:%u memory->init_func:%u",
                          lib->init_func,
                          si->init_func);
                    d->d_un.d_ptr = (unsigned char *) lib->init_func - (unsigned char *) lib->base;
                }
                break;
            case DT_FINI:
                si->fini_func = reinterpret_cast<linker_function_t> ((unsigned char *) lib->base +
                                                                     d->d_un.d_ptr);
                ALOGE("%s destructors (DT_FINI) found at %p", si->name, si->fini_func);
                if (si->fini_func != lib->fini_func) {
                    ALOGE("soinfo中的fini_func节和内存布局不一致,soinfo->fini_func:%u memory->fini_func:%u",
                          lib->fini_func,
                          si->fini_func);
                    d->d_un.d_ptr = (unsigned char *) lib->fini_func - (unsigned char *) lib->base;
                }
                break;
            case DT_INIT_ARRAY:
                si->init_array = reinterpret_cast<linker_function_t> ((unsigned char *) lib->base +
                                                                      d->d_un.d_ptr);
                ALOGE("%s constructors (DT_INIT_ARRAY) found at %p", si->name, si->init_array);
                if (si->init_array != lib->init_array) {
                    ALOGE("soinfo中的init_array节和内存布局不一致,soinfo->init_array:%u memory->init_array:%u",
                          lib->init_array,
                          si->init_array);
                    d->d_un.d_ptr = (unsigned char *) lib->init_array - (unsigned char *) lib->base;
                }
                break;
            case DT_INIT_ARRAYSZ:
                si->init_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
                if (si->init_array_count != lib->init_array_count) {
                    ALOGE("soinfo中的init_array_count节和内存布局不一致,soinfo->init_array_count:%d memory->init_array_count:%d",
                          lib->init_array_count,
                          si->init_array_count);
                    d->d_un.d_val = lib->init_array_count * sizeof(Elf32_Addr);
                }
                break;
            case DT_FINI_ARRAY:
                si->fini_array = reinterpret_cast<linker_function_t> ((unsigned char *) lib->base +
                                                                      d->d_un.d_ptr);
                ALOGE("%s destructors (DT_FINI_ARRAY) found at %p", si->name, si->fini_array);
                if (si->fini_array != lib->fini_array) {
                    ALOGE("soinfo中的fini_array节和内存布局不一致,soinfo->fini_array:%u memory->fini_array:%u",
                          lib->fini_array,
                          si->fini_array);
                    d->d_un.d_ptr = (unsigned char *) lib->fini_array - (unsigned char *) lib->base;
                }
                break;
            case DT_FINI_ARRAYSZ:
                si->fini_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
                if (si->fini_array_count != lib->fini_array_count) {
                    ALOGE("soinfo中的fini_array_count节和内存布局不一致,soinfo->fini_array_count:%d memory->fini_array_count:%d",
                          lib->fini_array_count,
                          si->fini_array_count);
                    d->d_un.d_val = lib->fini_array_count * sizeof(Elf32_Addr);
                }
                break;
            case DT_PREINIT_ARRAY:
                si->preinit_array = reinterpret_cast<linker_function_t> (
                        (unsigned char *) lib->base + d->d_un.d_ptr);
                ALOGE("%s constructors (DT_PREINIT_ARRAY) found at %p", si->name,
                      si->preinit_array);
                if (si->preinit_array != lib->preinit_array) {
                    ALOGE("soinfo中的preinit_array节和内存布局不一致,soinfo->preinit_array:%u memory->preinit_array:%u",
                          lib->preinit_array,
                          si->preinit_array);
                    d->d_un.d_ptr =
                            (unsigned char *) lib->preinit_array - (unsigned char *) lib->base;
                }
                break;
            case DT_PREINIT_ARRAYSZ:
                si->preinit_array_count = ((unsigned) d->d_un.d_val) / sizeof(Elf32_Addr);
                if (si->preinit_array_count != lib->preinit_array_count) {
                    ALOGE("soinfo中的preinit_array_count节和内存布局不一致,soinfo->preinit_array_count:%d memory->preinit_array_count:%d",
                          lib->preinit_array_count,
                          si->preinit_array_count);
                    d->d_un.d_val = lib->preinit_array_count * sizeof(Elf32_Addr);
                }
                break;
            default:
                break;
        }
    }
    free(si);
}

//检查so的格式
void checkSo(unsigned char *buf, soinfo *lib) {
    Elf32_Ehdr *elfhdr = (Elf32_Ehdr *) (void *) buf;
    unsigned soInfoPhoff = (unsigned char *) lib->phdr - (unsigned char *) lib->base;
    Elf32_Phdr *phdr = (Elf32_Phdr *) (void *) (buf + elfhdr->e_phoff);
    void *dynamicAddress;
//    size_t dynamic_count;
//    Elf32_Word dynamic_flags;

    if (elfhdr->e_phoff != soInfoPhoff) {
        ALOGE("soinfo中的phdr和内存映射中的soinfo不一致,soinfo:%u  内存：%u", soInfoPhoff, elfhdr->e_phoff);
        //刷新内存中的phdr
        elfhdr->e_phoff = soInfoPhoff;
        elfhdr->e_phnum = lib->phnum;
        elfhdr->e_entry = 0;
        phdr = lib->phdr;
        ALOGE("修复so中的phdr为：%u", soInfoPhoff);

    }
    //check phdr pointer
    for (int i = 0; i < lib->phnum; i++, phdr++) {
        //寻找load头，里面有soinfo的信息
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }
        dynamicAddress = (void *) (lib->base + phdr->p_offset);
        if (dynamicAddress != lib->dynamic) {
            ALOGE("soinfo中的dynamic和内存映射中的dynamic不一致,soinfo :%p 内存:%p", lib->dynamic,
                  dynamicAddress);
            //计算新的头部地址或者更新偏移量
            // char *newBase = (char *) ((unsigned) lib->dynamic - phdr->p_offset);
            // ALOGE("%x %x %x %x", newBase[0], newBase[1], newBase[2], newBase[3]);
            //0 d5 46 e7
            //以上代码证明，没有出现一个新的so文件头，因为将该地址反算到数据偏移开始的话，应该命中so文件头的magic，elf文件magic
            //应该为：0x7F 0x45 0x4C 0x46,现在为：0 d5 46 e7，所以我们的工作是进一步使用soinfo结构体中的参数修复到memory中
            unsigned int newOffset = (unsigned char *) lib->dynamic - (unsigned char *) lib->base;
            phdr->p_offset = newOffset;
            ALOGE("修复dynamic的偏移值");
            //return;
        }
//        dynamic_count = phdr->p_memsz / 8;
//        dynamic_flags = phdr->p_flags;
        checkDynamicProgramHeader(buf, lib, (Elf32_Dyn *) (buf + phdr->p_offset));
        // ALOGE("二次check");
        // checkDynamicProgramHeader(buf, lib, (Elf32_Dyn *) (buf + phdr->p_offset));
        break;
    }
}


jobject repairSoInfo(soinfo *soinfo, JNIEnv *env) {
    ALOGE("--------------------------------------------------\n");
    ALOGE("base = 0x%x\n", soinfo->base);
    ALOGE("size = 0x%x\n", soinfo->size);
    ALOGE("entry = 0x%x\n", soinfo->entry);
    ALOGE("program header count = %d\n", soinfo->phnum);
    ALOGE("--------------------------------------------------\n");

    jobject ret = NULL;
    unsigned dump_size = soinfo->size;
    unsigned buf_size = dump_size + 0x10;
    unsigned char *buf = new unsigned char[buf_size];
    if (NULL == buf) {
        threwIllegalStateException(env, "内存分配失败");
        return NULL;
    }
    memcpy(buf, (void *) soinfo->base, soinfo->size);
    /* 定位到程序头,将所有程序段的内存地址修订 */
    //清除段表数据，对于ida7.0来说，已经不重要了。ida7.0能够自动忽略这部分数据，如果段表数据存在问题
    Elf32_Ehdr *elfhdr = (Elf32_Ehdr *) (void *) buf;
    //这三个不要改，否则无法和原so混合
//    elfhdr->e_shnum = 0;
//    elfhdr->e_shoff = 0;
//    elfhdr->e_shstrndx = 0;

    unsigned phoff = elfhdr->e_phoff;
    Elf32_Phdr *phdr = (Elf32_Phdr *) (void *) (buf + phoff);
    for (int i = 0; i < soinfo->phnum; i++, phdr++) {
        unsigned v = phdr->p_vaddr;
        phdr->p_offset = v;
        unsigned s = phdr->p_memsz;
        phdr->p_filesz = s;
    }
    fix_entry(buf, soinfo);

    checkSo(buf, soinfo);


    ret = createByteBuffer(env, buf, dump_size);
    delete buf;
    return ret;
}

//static unsigned elfhash(const char *_name) {
//    const unsigned char *name = (const unsigned char *) _name;
//    unsigned h = 0, g;
//
//    while (*name) {
//        h = (h << 4) + *name++;
//        g = h & 0xf0000000;
//        h ^= g;
//        h ^= g >> 24;
//    }
//    return h;
//}

Elf32_Sym *dladdr_find_symbol(soinfo *si, const void *addr) {
    Elf32_Addr soaddr = reinterpret_cast<Elf32_Addr>(addr) - si->base;

    // Search the library's symbol table for any defined symbol which
    // contains this address.
    for (size_t i = 0; i < si->nchain; ++i) {
        Elf32_Sym *sym = &si->symtab[i];
        ALOGE("test symbol ->  sym_name:%s  sym_st_value:%d  sym_st_size:%d sym_section_index:%d",
              si->strtab + sym->st_name,
              sym->st_value,
              sym->st_size, sym->st_shndx);
        if (sym->st_shndx != SHN_UNDEF &&
            soaddr >= sym->st_value &&
            soaddr < sym->st_value + sym->st_size) {
            return sym;
        }
    }

    return NULL;
}

void printTargetMethodSymbol(soinfo *lib, void *methodAddr) {
    Dl_info dl_info;
    //字符串常量表
    // const char *strtab = lib->strtab;
    if (dladdr(methodAddr, &dl_info)) {
        //通过api获取的函数地址符号信息
        ALOGE("dli_fname:%s  dli_fbase:%p  dli_sname:%s dli_saddr:%p", dl_info.dli_fname,
              dl_info.dli_fbase, dl_info.dli_sname, dl_info.dli_saddr);
    }

    //直接在符号表中查找的函数地址符号信息
    Elf32_Sym *sym = dladdr_find_symbol(lib, methodAddr);
    if (sym != NULL) {
        ALOGE("sym_name:%s  sym_st_value:%d  sym_st_size:%d sym_section_index:%d",
              lib->strtab + sym->st_name,
              sym->st_value,
              sym->st_size, sym->st_shndx);
    }

}


