#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include "libdex/DexFile.h"
#include "libdex/ZipArchive.h"

#ifndef DEXHEADER_H
#define DEXHEADER_H

class Object;

#ifdef __cplusplus
extern "C" {
#endif

namespace art {

    class OatFile;

    class DexFile;

    class OatDexFile;

    class MemMap;
}


struct DvmDex {
    /* pointer to the DexFile we're associated with */
    DexFile *pDexFile;

    /* clone of pDexFile->pHeader (it's used frequently enough) */
    const DexHeader *pHeader;

    /* interned strings; parallel to "stringIds" */
    struct StringObject **pResStrings;

    /* resolved classes; parallel to "typeIds" */
    struct ClassObject **pResClasses;

    /* resolved methods; parallel to "methodIds" */
    struct Method **pResMethods;

    /* resolved instance fields; parallel to "fieldIds" */
    /* (this holds both InstField and StaticField) */
    struct Field **pResFields;

    /* interface method lookup cache */
    struct AtomicCache *pInterfaceCache;

    /* shared memory region with file contents */
    bool isMappedReadOnly;
    MemMapping memMap;

    jobject dex_object;

    /* lock ensuring mutual exclusion during updates */
    pthread_mutex_t modLock;
};

/**
 * JValue按照小端的方式定义数据，非常不建议直接使用它，因为无跨平台能力，此处只是mock
 */
union JValue {
    //默认走小端，避免语法错误
    u1 z;
    s1 b;
    u2 c;
    s2 s;
    s4 i;
    s8 j;
    float f;
    double d;
    Object *l;
};

#ifdef __cplusplus
}
#endif

#endif //DEXDUMP_DUMP_H