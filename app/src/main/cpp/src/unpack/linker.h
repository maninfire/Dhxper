//
// Created by 邓维佳 on 2018/5/30.
//

#ifndef XPOSEDDEMO_LINKER_H
#define XPOSEDDEMO_LINKER_H

#ifdef __cplusplus
extern "C" {

#endif

#define FLAG_LINKED     0x00000001 /* 已经进行链接 */
#define FLAG_ERROR      0x00000002 /* 打印出错信息 */
#define FLAG_EXE        0x00000004 /* 可执行文件 */
#define FLAG_LINKER     0x00000010 /* 链接器自身 */

#define SOINFO_NAME_LEN 128

#include <elf.h>
#include <stdint.h>

struct link_map {
    uintptr_t l_addr;             /* 内存加载地址 */
    char *l_name;                /* 名称 */
    uintptr_t l_ld;               /* 动态段内存地址 */
    struct link_map *l_next;
    struct link_map *l_prev;
};

typedef void (*linker_function_t)();

/* so信息结构 */
struct soinfo {
    char name[SOINFO_NAME_LEN];       /* SO名称 */
    Elf32_Phdr *phdr;           /* 指向程序段头表 */
    Elf32_Half phnum;
    Elf32_Addr entry;
    Elf32_Addr base;
    unsigned size;                    /* 所有可加载段的长度 */

    int unused;  // DO NOT USE, maintained for compatibility.

    Elf32_Dyn *dynamic;

    unsigned unused2; // DO NOT USE, maintained for compatibility
    unsigned unused3; // DO NOT USE, maintained for compatibility

    soinfo *next;
    unsigned flags;

    const char *strtab;
    Elf32_Sym *symtab;

    size_t nbucket;
    size_t nchain;
    unsigned *bucket;
    unsigned *chain;

    unsigned *plt_got;

    Elf32_Rel *plt_rel;
    size_t plt_rel_count;

    Elf32_Rel *rel;
    size_t rel_count;

    linker_function_t preinit_array;
    size_t preinit_array_count;

    linker_function_t init_array;
    size_t init_array_count;
    linker_function_t fini_array;
    size_t fini_array_count;

    linker_function_t init_func;

    linker_function_t fini_func;

#if defined(ANDROID_ARM_LINKER)
    /* ARM EABI section used for stack unwinding. */
    unsigned *ARM_exidx;
    unsigned ARM_exidx_count;
#elif defined(ANDROID_MIPS_LINKER)
#if 0
    /* not yet */
    unsigned *mips_pltgot
#endif
    unsigned mips_symtabno;
    unsigned mips_local_gotno;
    unsigned mips_gotsym;
#endif /* ANDROID_*_LINKER */

    unsigned refcount;
    struct link_map linkmap;

    int constructors_called;                   /* 构造函数已经被调用 */

    /* When you read a virtual address from the ELF file, add this
     * value to get the corresponding address in the process' address space */
    Elf32_Addr load_bias;
    int has_text_relocations;

    /* 表明是否是从主程序中调用 */
    //int loader_is_main;
};

#ifdef __cplusplus
}
#endif

#endif //XPOSEDDEMO_LINKER_H
