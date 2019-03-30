//
// Created by zhangzhenguo on 2019/3/19.
//

#include <jni.h>
#include <oo/Object.h>
#include <inlinehook/dlopen.h>
#include <include/DvmFunctionTable.h>
#include <vm/JarFile.h>
#include <vm/RawDexFile.h>
#include <vm/Dalvik.h>
#include <vm/native/InternalNativePriv.h>
#include "init.h"
#include <vm/Hash.h>
#include <zconf.h>

/*
 * Internal struct for managing DexFile.
 */
struct DexOrJar {
    char*       fileName;
    bool        isDex;
    bool        okayToFree;
    RawDexFile* pRawDexFile;
    JarFile*    pJarFile;
    u1*         pDexMemory; // malloc()ed memory, if any
};


uint32_t accessFlagsMask=0x3ffff;
uint8_t* codeitem_end(const u1** pData)
{
    uint32_t num_of_list = readUnsignedLeb128(pData);
    for (;num_of_list>0;num_of_list--) {
        int32_t num_of_handlers=readSignedLeb128(pData);
        int num=num_of_handlers;
        if (num_of_handlers<=0) {
            num=-num_of_handlers;
        }
        for (; num > 0; num--) {
            readUnsignedLeb128(pData);
            readUnsignedLeb128(pData);
        }
        if (num_of_handlers<=0) {
            readUnsignedLeb128(pData);
        }
    }
    return (uint8_t*)(*pData);
}

/**
 * 函数名称表根据4.4的Android版本设置的，不同Android版本映射可能存在差异，可以直接用ida查看维护
 */
//void initDvmFunctionTables() {
//    void *libVMhandle = dlopen("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);
//
//    initDvmFunctionItem("_Z20dvmDecodeIndirectRefP6ThreadP8_jobject",
//                        (void **) (&dvmFunctionTables.dvmDecodeIndirectRef), libVMhandle);
//    initDvmFunctionItem("_Z13dvmThreadSelfv", (void **) (&dvmFunctionTables.dvmThreadSelf),
//                        libVMhandle);
//
//
//    dlclose(libVMhandle);
//}
extern "C"
JNIEXPORT jobject JNICALL
Java_com_tsz_lier_dhxper_Dumper_methodDataWithDescriptor(JNIEnv *env, jclass type,
                                                                       jstring methodDescriptor_,
                                                                       jstring methodName_,
                                                                       jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {
        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return ret;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    if (method->insns == NULL || ac & ACC_NATIVE) {
        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return ret;
    }

    //why 16
    // 2 byte for registersSize
    // 2 byte for insSize
    // 2 byte for outsSize
    // 2 byte for triesSize
    // 4 byte for debugInfoOff
    // 4 byte for insnsSize
    // and then ,the insns address
    DexCode *code = (DexCode *) ((const u1 *) method->insns - 16);
    uint8_t *item = (uint8_t *) code;
    int code_item_len = 0;
    if (code->triesSize) {
        const u1 *handler_data = dexGetCatchHandlerData(code);
        const u1 **phandler = &handler_data;
        uint8_t *tail = codeitem_end(phandler);
        code_item_len = (int) (tail - item);
    } else {
        //正确的DexCode的大小
        code_item_len = 16 + code->insnsSize * 2;
    }

    ret = env->NewDirectByteBuffer(item, code_item_len);

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    return ret;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_tsz_lier_dhxper_Dumper_getMethodAccessFlagsWithDescriptor(JNIEnv *env, jclass type,
                                                                       jstring methodDescriptor_,
                                                                       jstring methodName_,
                                                                       jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {

        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return 0;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    jint retac =ac;

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    return retac;
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_tsz_lier_dhxper_Dumper_getType(JNIEnv *env, jclass type,
                                                                                 jstring methodDescriptor_,
                                                                                 jstring methodName_,
                                                                                 jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    //jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {

        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return 0;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    jstring ret =NULL;//"   ";//ac;

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    return ret;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_tsz_lier_dhxper_Dumper_getSuperclass(JNIEnv *env, jclass type,
                                                                                 jstring methodDescriptor_,
                                                                                 jstring methodName_,
                                                                                 jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {

        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return 0;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    jstring retac =NULL;

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    return retac;
}

extern "C"
JNIEXPORT jstring* JNICALL
Java_com_tsz_lier_dhxper_Dumper_getInterfaces(JNIEnv *env, jclass type,
                                                                                 jstring methodDescriptor_,
                                                                                 jstring methodName_,
                                                                                 jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {

        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return 0;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    jstring* retac =NULL;

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    return retac;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_tsz_lier_dhxper_Dumper_getSourceFile(JNIEnv *env, jclass type,
                                                                                 jstring methodDescriptor_,
                                                                                 jstring methodName_,
                                                                                 jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {

        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return 0;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    jstring retac =NULL;

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    return retac;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tsz_lier_dhxper_Dumper_getAnnotation(JNIEnv *env, jclass type,
                                                                                 jstring methodDescriptor_,
                                                                                 jstring methodName_,
                                                                                 jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {

        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return 0;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    jint retac =ac;

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    // Set<? extends Annotation> annotations = classDef.getAnnotations();
    return retac;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tsz_lier_dhxper_Dumper_getFields(JNIEnv *env, jclass type,
                                                            jstring methodDescriptor_,
                                                            jstring methodName_,
                                                            jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {

        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return 0;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    jint retac =ac;

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    //Iterable<? extends BuilderField> fields = ( Iterable<? extends BuilderField>)classDef.getFields();
    return retac;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_tsz_lier_dhxper_Dumper_getDirectMethods(JNIEnv *env, jclass type,
                                                        jstring methodDescriptor_,
                                                        jstring methodName_,
                                                        jclass searchClass) {
    const char *methodDescriptor = env->GetStringUTFChars(methodDescriptor_, 0);
    const char *methodName = env->GetStringUTFChars(methodName_, 0);
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            searchClass);

    jobject ret = NULL;
    Method *method = dvmFindDirectMethodByDescriptor(clazz, methodName, methodDescriptor);
    if (method == NULL) {
        method = dvmFindVirtualMethodByDescriptor(clazz, methodName, methodDescriptor);
    }
    if (method == NULL) {

        env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
        env->ReleaseStringUTFChars(methodName_, methodName);
        return 0;
    }

    //check for native
    uint32_t ac = (method->accessFlags) & accessFlagsMask;
    jint retac =ac;

    tail:
    env->ReleaseStringUTFChars(methodDescriptor_, methodDescriptor);
    env->ReleaseStringUTFChars(methodName_, methodName);
    //Iterable<? extends BuilderMethod> methods=(Iterable<? extends BuilderMethod>)classDef.getDirectMethods();
    return retac;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_tsz_lier_dhxper_Dumper_originDex(JNIEnv *env, jclass type,
                                                        jclass loader) {
    //TODO check & throw exception
    ClassObject *clazz = (ClassObject *) dvmFunctionTables.dvmDecodeIndirectRef(
            dvmFunctionTables.dvmThreadSelf(),
            loader);
    DvmDex *dvm_dex = clazz->pDvmDex;
    return env->NewDirectByteBuffer(dvm_dex->memMap.addr, dvm_dex->memMap.length);
}

static int num=0;
static pthread_mutex_t mutex;
static bool flagn=true;
struct timeval now;
struct timespec outtime;
pthread_cond_t cond;

void LTSleep(int nHm) {
    gettimeofday(&now, NULL);
    now.tv_usec += 1000*nHm;
    if (now.tv_usec > 1000000) {
        now.tv_sec += now.tv_usec / 1000000;
        now.tv_usec %= 1000000;
    }

    outtime.tv_sec = now.tv_sec;
    outtime.tv_nsec = now.tv_usec * 1000;

    pthread_cond_timedwait(&cond, &mutex, &outtime);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_tsz_lier_dhxper_Dumper_test(JNIEnv *env, jclass type
        ) {
//TODO check & throw exception
    //LOGV("test into");
    pthread_mutex_lock(&mutex);
    if(flagn){
        flagn= false;
        pthread_mutex_unlock(&mutex);
        ALOGI("......num is:%d",num);
        num++;
        //LTSleep(1);
        flagn= true;
    }else{
        pthread_mutex_unlock(&mutex);
    }

    //LOGV("test out");
}


#include "vm/Hash.cpp"

/*
 * (This is a dvmHashTableLookup compare func.)
 *
 * Args are DexOrJar*.
 */
static int hashcmpDexOrJar(const void* tableVal, const void* newVal)
{
    return (int) newVal - (int) tableVal;
}

/*
 * Verify that the "cookie" is a DEX file we opened.
 *
 * Expects that the hash table will be *unlocked* here.
 *
 * If the cookie is invalid, we throw an exception and return "false".
 */
static bool validateCookie(int cookie)
{
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;

    LOGVV("+++ dex verifying cookie %p", pDexOrJar);

    if (pDexOrJar == NULL)
        return false;

    u4 hash = cookie;
    dvmHashTableLock(gDvm.userDexFiles);
    void* result = dvmHashTableLookup(gDvm.userDexFiles, hash, pDexOrJar,
                                      hashcmpDexOrJar, false);
    dvmHashTableUnlock(gDvm.userDexFiles);
    if (result == NULL) {
        dvmThrowRuntimeException("invalid DexFile cookie");
        return false;
    }

    return true;
}




/*
 * private static Class defineClassNative(String name, ClassLoader loader,
 *      int cookie)
 *
 * Load a class from a DEX file.  This is roughly equivalent to defineClass()
 * in a regular VM -- it's invoked by the class loader to cause the
 * creation of a specific class.  The difference is that the search for and
 * reading of the bytes is done within the VM.
 *
 * The class name is a "binary name", e.g. "java.lang.String".
 *
 * Returns a null pointer with no exception if the class was not found.
 * Throws an exception on other failures.
 */

//------------------------added begin----------------------//

#include <asm/siginfo.h>
#include "libdex/DexClass.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

static char dexname[100]={0};

static char dumppath[100]={0};

static bool readable=true;

static pthread_mutex_t read_mutex;

//static bool flagn=true;



static bool timer_flag=true;

static timer_t timerId;

struct arg{
    DvmDex* pDvmDex;
    Object * loader;
}param;

void timer_thread(sigval_t)
{
    timer_flag=false;
    timer_delete(timerId);
    ALOGI("GOT IT time up");
}

void* ReadThread(void *arg){
    FILE *fp = NULL;
    while (dexname[0]==0||dumppath[0]==0) {
        fp=fopen("/data/dexname", "r");
        if (fp==NULL) {
            sleep(1);
            continue;
        }
        fgets(dexname,99,fp);
        dexname[strlen(dexname)-1]=0;
        fgets(dumppath,99,fp);
        dumppath[strlen(dumppath)-1]=0;
        fclose(fp);
        fp=NULL;
    }

    struct sigevent sev;

    sev.sigev_notify=SIGEV_THREAD;
    sev.sigev_value.sival_ptr=&timerId;
    sev.sigev_notify_function=timer_thread;
    sev.sigev_notify_attributes = NULL;

    timer_create(CLOCK_REALTIME,&sev,&timerId);

    struct itimerspec ts;
    ts.it_value.tv_sec=5;
    ts.it_value.tv_nsec=0;
    ts.it_interval.tv_sec=0;
    ts.it_interval.tv_nsec=0;

    timer_settime(timerId,0,&ts,NULL);

    return NULL;
}

void ReadClassDataHeader(const uint8_t** pData,
                         DexClassDataHeader *pHeader) {
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}

void ReadClassDataField(const uint8_t** pData, DexField* pField) {
    pField->fieldIdx = readUnsignedLeb128(pData);
    pField->accessFlags = readUnsignedLeb128(pData);
}

void ReadClassDataMethod(const uint8_t** pData, DexMethod* pMethod) {
    pMethod->methodIdx = readUnsignedLeb128(pData);
    pMethod->accessFlags = readUnsignedLeb128(pData);
    pMethod->codeOff = readUnsignedLeb128(pData);
}

DexClassData* ReadClassData(const uint8_t** pData) {

    DexClassDataHeader header;

    if (*pData == NULL) {
        return NULL;
    }

    ReadClassDataHeader(pData,&header);

    size_t resultSize = sizeof(DexClassData) + (header.staticFieldsSize * sizeof(DexField)) + (header.instanceFieldsSize * sizeof(DexField)) + (header.directMethodsSize * sizeof(DexMethod)) + (header.virtualMethodsSize * sizeof(DexMethod));

    DexClassData* result = (DexClassData*) malloc(resultSize);

    if (result == NULL) {
        return NULL;
    }

    uint8_t* ptr = ((uint8_t*) result) + sizeof(DexClassData);

    result->header = header;

    if (header.staticFieldsSize != 0) {
        result->staticFields = (DexField*) ptr;
        ptr += header.staticFieldsSize * sizeof(DexField);
    } else {
        result->staticFields = NULL;
    }

    if (header.instanceFieldsSize != 0) {
        result->instanceFields = (DexField*) ptr;
        ptr += header.instanceFieldsSize * sizeof(DexField);
    } else {
        result->instanceFields = NULL;
    }

    if (header.directMethodsSize != 0) {
        result->directMethods = (DexMethod*) ptr;
        ptr += header.directMethodsSize * sizeof(DexMethod);
    } else {
        result->directMethods = NULL;
    }

    if (header.virtualMethodsSize != 0) {
        result->virtualMethods = (DexMethod*) ptr;
    } else {
        result->virtualMethods = NULL;
    }

    for (uint32_t i = 0; i < header.staticFieldsSize; i++) {
        ReadClassDataField(pData, &result->staticFields[i]);
    }

    for (uint32_t i = 0; i < header.instanceFieldsSize; i++) {
        ReadClassDataField(pData, &result->instanceFields[i]);
    }

    for (uint32_t i = 0; i < header.directMethodsSize; i++) {
        ReadClassDataMethod(pData, &result->directMethods[i]);
    }

    for (uint32_t i = 0; i < header.virtualMethodsSize; i++) {
        ReadClassDataMethod(pData, &result->virtualMethods[i]);
    }

    return result;
}

void writeLeb128(uint8_t ** ptr, uint32_t data)
{
    while (true) {
        uint8_t out = data & 0x7f;
        if (out != data) {
            *(*ptr)++ = out | 0x80;
            data >>= 7;
        } else {
            *(*ptr)++ = out;
            break;
        }
    }
}
/*
    此函数读取class_data_item，并将内容用writeLeb128转码后返回
*/
uint8_t* EncodeClassData(DexClassData *pData, int& len)
{
    len=0;

    len+=unsignedLeb128Size(pData->header.staticFieldsSize);
    len+=unsignedLeb128Size(pData->header.instanceFieldsSize);
    len+=unsignedLeb128Size(pData->header.directMethodsSize);
    len+=unsignedLeb128Size(pData->header.virtualMethodsSize);

    if (pData->staticFields) {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++) {
            len+=unsignedLeb128Size(pData->staticFields[i].fieldIdx);
            len+=unsignedLeb128Size(pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields) {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++) {
            len+=unsignedLeb128Size(pData->instanceFields[i].fieldIdx);
            len+=unsignedLeb128Size(pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods) {
        for (uint32_t i=0; i<pData->header.directMethodsSize; i++) {
            len+=unsignedLeb128Size(pData->directMethods[i].methodIdx);
            len+=unsignedLeb128Size(pData->directMethods[i].accessFlags);
            len+=unsignedLeb128Size(pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods) {
        for (uint32_t i=0; i<pData->header.virtualMethodsSize; i++) {
            len+=unsignedLeb128Size(pData->virtualMethods[i].methodIdx);
            len+=unsignedLeb128Size(pData->virtualMethods[i].accessFlags);
            len+=unsignedLeb128Size(pData->virtualMethods[i].codeOff);
        }
    }

    uint8_t * store = (uint8_t *) malloc(len);

    if (!store) {
        return NULL;
    }

    uint8_t * result=store;

    writeLeb128(&store,pData->header.staticFieldsSize);
    writeLeb128(&store,pData->header.instanceFieldsSize);
    writeLeb128(&store,pData->header.directMethodsSize);
    writeLeb128(&store,pData->header.virtualMethodsSize);

    if (pData->staticFields) {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++) {
            writeLeb128(&store,pData->staticFields[i].fieldIdx);
            writeLeb128(&store,pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields) {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++) {
            writeLeb128(&store,pData->instanceFields[i].fieldIdx);
            writeLeb128(&store,pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods) {
        for (uint32_t i=0; i<pData->header.directMethodsSize; i++) {
            writeLeb128(&store,pData->directMethods[i].methodIdx);
            writeLeb128(&store,pData->directMethods[i].accessFlags);
            writeLeb128(&store,pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods) {
        for (uint32_t i=0; i<pData->header.virtualMethodsSize; i++) {
            writeLeb128(&store,pData->virtualMethods[i].methodIdx);
            writeLeb128(&store,pData->virtualMethods[i].accessFlags);
            writeLeb128(&store,pData->virtualMethods[i].codeOff);
        }
    }

    free(pData);
    return result;
}

void* DumpClass(void *parament)
{
    while (timer_flag) {
        sleep(5);
    }

    DvmDex* pDvmDex=((struct arg*)parament)->pDvmDex;
    Object *loader=((struct arg*)parament)->loader;
    DexFile* pDexFile=pDvmDex->pDexFile;
    MemMapping * mem=&pDvmDex->memMap;

    u4 time=dvmGetRelativeTimeMsec();
    ALOGI("GOT IT begin: %d ms",time);

    char *path = new char[100];
    strcpy(path,dumppath);
    strcat(path,"classdef");
    FILE *cdffp = fopen(path, "wb+");

    strcpy(path,dumppath);
    strcat(path,"extra");
    FILE *exfp = fopen(path,"wb+");

    uint32_t mask=0x3ffff;
    char padding=0;
    const char* header="Landroid";
    unsigned int num_class_defs=pDexFile->pHeader->classDefsSize;//类结构个数
    uint32_t total_pointer = mem->length-uint32_t(pDexFile->baseAddr-(const u1*)mem->addr);
    //需要写入数据区域的需要增加代码的位置

    uint32_t rec=total_pointer;

    while (total_pointer&3) {//地址最低两位为0,与3结果为False
        total_pointer++;
    }

    int inc=total_pointer-rec;
    uint32_t start = pDexFile->pHeader->classDefsOff+sizeof(DexClassDef)*num_class_defs;
    //dex文件的末尾位置，应该是修复数据写入的位置
    uint32_t end = (uint32_t)((const u1*)mem->addr+mem->length-pDexFile->baseAddr);
    //新分配的内存地址开始+新分配的内存长度-dex结构开始的位置
    //这是个啥？？？？

    for (size_t i=0;i<num_class_defs;i++)
    {
        bool need_extra=false;
        ClassObject * clazz=NULL;
        const u1* data=NULL;
        DexClassData* pData = NULL;
        bool pass=false;
        //获取dex文件的第i个DexClassDef的结构体
        const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
        //获取类的描述符信息及类类型字符串：Landroid/xxx/yyy;
        const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile,pClassDef);
        //判断该类是够是Landroid开头的系统类，是否是一个有效的类
        if(!strncmp(header,descriptor,8)||!pClassDef->classDataOff)
        {
            //设置跳过过滤标签
            pass=true;

            //*******是系统类或者当前不是有效的类，直接跳过**********
            goto classdef;
        }

        clazz = dvmDefineClass(pDvmDex, descriptor, loader);

        //############加载类描述符指定的类#######################
        if (!clazz) {
            continue;
        }
        //########################################
        //判断加载的类描述符信息
        ALOGI("GOT IT class: %s",descriptor);

        //判断加载的指定的类是否已经初始化完成

        if (!dvmIsClassInitialized(clazz)) {
            if(dvmInitClass(clazz)){
                ALOGI("GOT IT init: %s",descriptor);
            }
        }

        if(pClassDef->classDataOff<start || pClassDef->classDataOff>end)
        {
            need_extra=true;
        }

        data=dexGetClassData(pDexFile,pClassDef);
        pData = ReadClassData(&data);

        if (!pData) {
            continue;
        }

        if (pData->directMethods) {
            for (uint32_t i=0; i<pData->header.directMethodsSize; i++) {
                Method *method = &(clazz->directMethods[i]);
                uint32_t ac = (method->accessFlags) & mask;

                ALOGI("GOT IT direct method name %s.%s",descriptor,method->name);

                if (!method->insns||ac&ACC_NATIVE) {
                    if (pData->directMethods[i].codeOff) {
                        need_extra = true;
                        pData->directMethods[i].accessFlags=ac;
                        pData->directMethods[i].codeOff=0;
                    }
                    continue;
                }

                u4 codeitem_off = u4((const u1*)method->insns-16-pDexFile->baseAddr);
                //指令偏移

                if (ac != pData->directMethods[i].accessFlags)
                {
                    ALOGI("GOT IT method ac");
                    need_extra=true;
                    pData->directMethods[i].accessFlags=ac;
                }

                if (codeitem_off!=pData->directMethods[i].codeOff&&((codeitem_off>=start&&codeitem_off<=end)||codeitem_off==0)) {
                    //指令偏移不在dex文件末尾分配区域
                    ALOGI("GOT IT method code");
                    need_extra=true;
                    pData->directMethods[i].codeOff=codeitem_off;
                }

                if ((codeitem_off<start || codeitem_off>end) && codeitem_off!=0) {
                    //代码偏移位于dex文件末尾
                    need_extra=true;
                    pData->directMethods[i].codeOff = total_pointer;
                    DexCode *code = (DexCode*)((const u1*)method->insns-16);
                    uint8_t *item=(uint8_t *) code;
                    int code_item_len = 0;
                    if (code->triesSize) {
                        const u1 * handler_data = dexGetCatchHandlerData(code);
                        const u1** phandler=(const u1**)&handler_data;
                        uint8_t * tail=codeitem_end(phandler);
                        code_item_len = (int)(tail-item);
                    }else{
                        code_item_len = 16+code->insnsSize*2;
                    }

                    ALOGI("GOT IT method code changed");

                    fwrite(item,1,code_item_len,exfp);
                    fflush(exfp);
                    total_pointer+=code_item_len;
                    while (total_pointer&3) {
                        fwrite(&padding,1,1,exfp);
                        fflush(exfp);
                        total_pointer++;
                    }
                }
            }
        }

        if (pData->virtualMethods) {
            for (uint32_t i=0; i<pData->header.virtualMethodsSize; i++) {
                Method *method = &(clazz->virtualMethods[i]);
                uint32_t ac = (method->accessFlags) & mask;

                ALOGI("GOT IT virtual method name %s.%s",descriptor,method->name);

                if (!method->insns||ac&ACC_NATIVE) {
                    if (pData->virtualMethods[i].codeOff) {
                        need_extra = true;
                        pData->virtualMethods[i].accessFlags=ac;
                        pData->virtualMethods[i].codeOff=0;
                    }
                    continue;
                }

                u4 codeitem_off = u4((const u1 *)method->insns - 16 - pDexFile->baseAddr);

                if (ac != pData->virtualMethods[i].accessFlags)
                {
                    ALOGI("GOT IT method ac");
                    need_extra=true;
                    pData->virtualMethods[i].accessFlags=ac;
                }

                if (codeitem_off!=pData->virtualMethods[i].codeOff&&((codeitem_off>=start&&codeitem_off<=end)||codeitem_off==0)) {
                    ALOGI("GOT IT method code");
                    need_extra=true;
                    pData->virtualMethods[i].codeOff=codeitem_off;
                }

                if ((codeitem_off<start || codeitem_off>end)&&codeitem_off!=0) {
                    need_extra=true;
                    pData->virtualMethods[i].codeOff = total_pointer;
                    DexCode *code = (DexCode*)((const u1*)method->insns-16);
                    uint8_t *item=(uint8_t *) code;
                    int code_item_len = 0;
                    if (code->triesSize) {
                        const u1 *handler_data = dexGetCatchHandlerData(code);
                        const u1** phandler=(const u1**)&handler_data;
                        uint8_t * tail=codeitem_end(phandler);
                        code_item_len = (int)(tail-item);
                    }else{
                        code_item_len = 16+code->insnsSize*2;
                    }

                    ALOGI("GOT IT method code changed");

                    fwrite(item,1,code_item_len,exfp);
                    fflush(exfp);
                    total_pointer+=code_item_len;
                    while (total_pointer&3) {
                        fwrite(&padding,1,1,exfp);
                        fflush(exfp);
                        total_pointer++;
                    }
                }
            }
        }

        classdef:
        DexClassDef temp=*pClassDef;
        uint8_t *p = (uint8_t *)&temp;

        if (need_extra) {
            ALOGI("GOT IT classdata before");
            int class_data_len = 0;
            uint8_t *out = EncodeClassData(pData,class_data_len);
            if (!out) {
                continue;
            }
            temp.classDataOff = total_pointer;
            fwrite(out,1,class_data_len,exfp);
            fflush(exfp);
            total_pointer+=class_data_len;
            while (total_pointer&3) {
                fwrite(&padding,1,1,exfp);
                fflush(exfp);
                total_pointer++;
            }
            free(out);
            ALOGI("GOT IT classdata written");
        }else{
            if (pData) {
                free(pData);
            }
        }

        if (pass) {
            temp.classDataOff=0;
            temp.annotationsOff=0;
        }

        ALOGI("GOT IT classdef");
        fwrite(p, sizeof(DexClassDef), 1, cdffp);
        fflush(cdffp);
    }

    fclose(exfp);
    fclose(cdffp);

//将所有的dex文件组装到whole.dex文件当中。
    strcpy(path,dumppath);
    strcat(path,"whole.dex");
    FILE *wholefp = fopen(path,"wb+");
    rewind(wholefp);//将文件内部的位置指针重新指向一个流（数据流/文件）的开头

    int part1fd=-1;
    int r=-1;
    int len=0;
    char *addr=NULL;
    struct stat st;

    strcpy(path,dumppath);
    strcat(path,"part1");

    part1fd=open(path,O_RDONLY,0666);
    if (part1fd==-1) {
        return NULL;
    }

    r=fstat(part1fd,&st);  //由文件描述词取得文件状态
    if(r==-1){
        close(part1fd);
        return NULL;
    }

    len=st.st_size;
    addr=(char*)mmap(NULL,len,PROT_READ,MAP_PRIVATE,part1fd,0);
    fwrite(addr,1,len,wholefp);
    fflush(wholefp);
    munmap(addr,len);
    close(part1fd);

    strcpy(path,dumppath);
    strcat(path,"classdef");

    int classdeffd=open(path,O_RDONLY,0666);
    if (classdeffd==-1) {
        return NULL;
    }

    r=fstat(classdeffd,&st);
    if(r==-1){
        close(classdeffd);
        return NULL;
    }

    len=st.st_size;
    addr=(char*)mmap(NULL,len,PROT_READ,MAP_PRIVATE,classdeffd,0);
    fwrite(addr,1,len,wholefp);
    fflush(wholefp);
    munmap(addr,len);
    close(classdeffd);

    strcpy(path,dumppath);
    strcat(path,"data");

    int datafd=open(path,O_RDONLY,0666);
    if (datafd==-1) {
        return NULL;
    }

    r=fstat(datafd,&st);
    if(r==-1){
        close(datafd);
        return NULL;
    }

    len=st.st_size;
    addr=(char*)mmap(NULL,len,PROT_READ,MAP_PRIVATE,datafd,0);
    fwrite(addr,1,len,wholefp);
    fflush(wholefp);
    munmap(addr,len);
    close(datafd);

    while (inc>0) {
        fwrite(&padding,1,1,wholefp);
        fflush(wholefp);
        inc--;
    }

    strcpy(path,dumppath);
    strcat(path,"extra");

    int extrafd=open(path,O_RDONLY,0666);
    if (extrafd==-1) {
        return NULL;
    }

    r=fstat(extrafd,&st);
    if(r==-1){
        close(extrafd);
        return NULL;
    }

    len=st.st_size;
    addr=(char*)mmap(NULL,len,PROT_READ,MAP_PRIVATE,extrafd,0);
    fwrite(addr,1,len,wholefp);
    fflush(wholefp);
    munmap(addr,len);
    close(extrafd);

    fclose(wholefp);
    delete path;

    time=dvmGetRelativeTimeMsec();
    ALOGI("GOT IT end: %d ms",time);

    return NULL;
}
//------------------------added end----------------------//


extern "C"
JNIEXPORT void JNICALL
Java_com_tsz_lier_dhxper_Dumper_Dumperfromdefineclass(JNIEnv *env, jclass type
,jstring aname,jobject aloader,jint acookie) {


    StringObject* nameObj = (StringObject*)aname;
    Object* loader =(Object *) aloader;
    int cookie = acookie;
    ClassObject* clazz = NULL;
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;
    DvmDex* pDvmDex;
    char* name;
    char* descriptor;

    name = dvmCreateCstrFromString(nameObj);
    descriptor = dvmDotToDescriptor(name);
    ALOGV("--- Explicit class load '%s' l=%p c=0x%08x",
          descriptor, loader, cookie);
    free(name);

    if (!validateCookie(cookie))
        return;
        //RETURN_VOID();

    if (pDexOrJar->isDex)
        pDvmDex = dvmGetRawDexFileDex(pDexOrJar->pRawDexFile);
    else
        pDvmDex = dvmGetJarFileDex(pDexOrJar->pJarFile);

    /* once we load something, we can't unmap the storage */
    pDexOrJar->okayToFree = false;



    //----------------added begin---------------------------//
    int uid=getuid();
    char dexnameinti[]="";

    if (uid) {
        if (readable) {
            pthread_mutex_lock(&read_mutex);
            if (readable) {
                readable=false;
                pthread_mutex_unlock(&read_mutex);


                for(int i;i<size_t(dexnameinti);i++){
                    dexname[i]=dexnameinti[i];
                }
                //&dexname="sdfsaf";
                //pthread_t read_thread;
                //pthread_create(&read_thread, NULL, ReadThread, NULL);

            }else{
                pthread_mutex_unlock(&read_mutex);
            }
        }
    }


    if(uid&&strcmp(dexname,"")){
        char * res=strstr(pDexOrJar->fileName, dexname);
        if (res&&flagn) {
            pthread_mutex_lock(&mutex);
            if (flagn) {
                flagn = false;
                pthread_mutex_unlock(&mutex);

                DexFile* pDexFile=pDvmDex->pDexFile;
                MemMapping * mem=&pDvmDex->memMap;

                char * temp=new char[100];
                strcpy(temp,dumppath);
                strcat(temp,"part1");
                FILE *part1fp = fopen(temp, "wb+");
                const u1 *addr = (const u1*)mem->addr;
                int length=int(pDexFile->baseAddr+pDexFile->pHeader->classDefsOff-addr);
                fwrite(addr,1,length,part1fp);
                fflush(part1fp);
                fclose(part1fp);

                strcpy(temp,dumppath);
                strcat(temp,"data");
                FILE* datafp = fopen(temp, "wb+");
                addr = pDexFile->baseAddr+pDexFile->pHeader->classDefsOff+sizeof(DexClassDef)*pDexFile->pHeader->classDefsSize;
                length=int((const u1*)mem->addr+mem->length-addr);
                fwrite(addr,1,length,datafp);
                fflush(datafp);
                fclose(datafp);
                delete temp;

                param.loader=loader;
                param.pDvmDex=pDvmDex;

                pthread_t dumpthread;
                dvmCreateInternalThread(&dumpthread,"ClassDumper",DumpClass,(void*)&param);

            }else{
                pthread_mutex_unlock(&mutex);
            }
        }
    }


    //----------------added end----------------------------//


    //LOGV("test out");
}
