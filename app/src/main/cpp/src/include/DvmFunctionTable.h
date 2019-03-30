//
// Created by 邓维佳 on 2018/3/13.
// <br>存储dalvik内部的函数地址
//

#ifndef XPOSEDDEMO_DVMFUNCTIONTABLE_H
#define XPOSEDDEMO_DVMFUNCTIONTABLE_H


#include <oo/Object.h>
#include <oo/Class.h>
#include <libdex/DexClass.h>
#include <oo/Resolve.h>

#ifdef __cplusplus
extern "C" {
#endif

struct DvmFunctionTables {
    //从Array.cpp中迁移过来的函数指针
    ArrayObject *(*allocArray)(ClassObject *arrayClass, size_t length,
                               size_t elemWidth, int allocFlags);

    ArrayObject *(*dvmAllocPrimitiveArray)(char type, size_t length, int allocFlags);

    ArrayObject *(*dvmAllocMultiArray)(ClassObject *arrayClass, int curDim,
                                       const int *dimensions);

    ClassObject *(*createArrayClass)(const char *descriptor, Object *loader);


    bool (*dvmUnboxObjectArray)(ArrayObject *dstArray, const ArrayObject *srcArray,
                                ClassObject *dstElemClass);

    size_t (*dvmArrayClassElementWidth)(const ClassObject *arrayClass);


    //从Class.cpp迁移的函数指针
    ClassObject *(*dvmFindPrimitiveClass)(char type);

    bool (*createPrimitiveType)(PrimitiveType primitiveType, ClassObject **pClass);

    bool (*prepareCpe)(ClassPathEntry *cpe, bool isBootstrap);

    ClassPathEntry *(*processClassPath)(const char *pathStr, bool isBootstrap);

    DvmDex *(*searchBootPathForClass)(const char *descriptor,
                                      const DexClassDef **ppClassDef);

    void (*dvmSetBootPathExtraDex)(DvmDex *pDvmDex);

    int (*dvmGetBootPathSize)();

    StringObject *(*dvmGetBootPathResource)(const char *name, int idx);

    InitiatingLoaderList *(*dvmGetInitiatingLoaderList)(ClassObject *clazz);

    void (*dvmAddInitiatingLoader)(ClassObject *clazz, Object *loader);

    ClassObject *(*dvmLookupClass)(const char *descriptor, Object *loader,
                                   bool unprepOkay);

    bool (*dvmAddClassToHash)(ClassObject *clazz);

    void (*dvmSetClassSerialNumber)(ClassObject *clazz);

    ClassObject *(*dvmFindClass)(const char *descriptor, Object *loader);

    ClassObject *(*findClassFromLoaderNoInit)(const char *descriptor,
                                              Object *loader);

    ClassObject *(*findClassNoInit)(const char *descriptor, Object *loader,
                                    DvmDex *pDvmDex);

    ClassObject *(*loadClassFromDex)(DvmDex *pDvmDex,
                                     const DexClassDef *pClassDef, Object *classLoader);

    void (*dvmFreeClassInnards)(ClassObject *clazz);

    static void (*freeMethodInnards)(Method *meth);

    bool (*dvmLinkClass)(ClassObject *clazz);

    bool (*dvmInitClass)(ClassObject *clazz);

    ClassObject *(*dvmFindSystemClass)(const char *descriptor);

    int (*computeJniArgInfo)(const DexProto *proto);

    bool (*createVtable)(ClassObject *clazz);

    bool (*createIftable)(ClassObject *clazz);

    bool (*insertMethodStubs)(ClassObject *clazz);

    void (*dvmDumpLoaderStats)(const char *msg);

    int (*dvmGetNumLoadedClasses)();

    void (*dvmDumpAllClasses)(int flags);

    ClassObject *(*dvmFindLoadedClass)(const char *descriptor);

    Object *(*dvmGetSystemClassLoader)();

    void (*dvmSetNativeFunc)(Method *method, DalvikBridgeFunc func,
                             const u2 *insns);

    void (*dvmSetRegisterMap)(Method *method, const RegisterMap *pMap);

    bool (*dvmIsClassInitializing)(const ClassObject *clazz);

    void (*throwEarlierClassFailure)(ClassObject *clazz);

    bool (*computeFieldOffsets)(ClassObject *clazz);

    bool (*precacheReferenceOffsets)(ClassObject *clazz);

    void (*loadMethodFromDex)(ClassObject *clazz, const DexMethod *pDexMethod,
                              Method *meth);

    size_t (*classObjectSize)(size_t sfieldCount);

    void (*freeCpeArray)(ClassPathEntry *cpe);

    //从Objecct.cpp迁移的函数指针
    const Method *(*dvmGetVirtualizedMethod)(const ClassObject *clazz,
                                             const Method *meth);

    //TypeCheck.h
    int (*dvmInstanceof)(const ClassObject *instance, const ClassObject *clazz);

    //TypeCheck.cpp
    bool (*dvmInstanceofStartup)();

    void (*dvmInstanceofShutdown)();

    int (*dvmInstanceofNonTrivial)(const ClassObject *instance,
                                   const ClassObject *clazz);

    //Resolve.cpp
    ClassObject *(*dvmResolveClass)(const ClassObject *referrer, u4 classIdx,
                                    bool fromUnverifiedConstant);

    Method *(*dvmResolveMethod)(const ClassObject *referrer, u4 methodIdx,
                                MethodType methodType);

    Method *(*dvmResolveInterfaceMethod)(const ClassObject *referrer, u4 methodIdx);

    InstField *(*dvmResolveInstField)(const ClassObject *referrer, u4 ifieldIdx);

    StaticField *(*dvmResolveStaticField)(const ClassObject *referrer, u4 sfieldIdx);

    StringObject *(*dvmResolveString)(const ClassObject *referrer, u4 stringIdx);

    //ObjectInlines.h
    void (*dvmSetObjectArrayElement)(const ArrayObject *obj, int index,
                                     Object *val);

    //将java的jobect转化为dvm内部object对象
    Object *(*dvmDecodeIndirectRef)(void *self, jobject jobj);

    //Thread.cpp
    void *(*dvmThreadSelf)();

    //Jni.cpp 请注意，这个是内部符号，可能其名称粉粹特性特别大，每个小版本都可能不一样，甚至不同的dalvik机型也不一样
    jint (*RegisterNatives)(JNIEnv *env, jclass jclazz,
                            const JNINativeMethod *methods, jint nMethods);

    Object (*dvmInvokeMethod)(Object *obj, const Method *method,
                              ArrayObject *argList, ArrayObject *params, ClassObject *returnType,
                              bool noAccessCheck);

    void (*dvmInterpret)(void *self, const Method *method, JValue *pResult);
};

extern struct DvmFunctionTables dvmFunctionTables;


#ifdef __cplusplus
}
#endif
#endif //XPOSEDDEMO_DVMFUNCTIONTABLE_H
