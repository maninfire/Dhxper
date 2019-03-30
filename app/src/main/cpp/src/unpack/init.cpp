//
// Created by 邓维佳 on 2018/3/14.
//

extern "C" {
#include "inlinehook/inlineHook.h"
}

#include <sys/system_properties.h>
#include <fcntl.h>
#include <unistd.h>
#include "DvmFunctionTable.h"
#include "inlinehook/dlopen.h"
#include "init.h"


#include "dexheader.h"

//这里定义全局变量
struct DvmFunctionTables dvmFunctionTables;

void (*oldExit)(int status) = NULL;


void newExit(int status) {
    ALOGE(TAG, "call system exit");
    oldExit(status);
}

void (*oldAbort)() = NULL;

void newAbort(void) {
    ALOGE(TAG, "call system newAbort");
    oldAbort();
}

void *defaultDvmFunctionHandler(...) {
    //我们只是mock语法错误，不是所有的函数都会处理他
    __android_log_print(ANDROID_LOG_ERROR, TAG, "the function hook not implemented");
    return NULL;
}


void initDvmFunctionItem(const char *functionName, void **functionStoreAddr, void *libVMhandle) {
    void *functionAddress = findFunction(functionName, libVMhandle);
    if (functionAddress == NULL) {
        functionAddress = (void *) defaultDvmFunctionHandler;
    }
    (*functionStoreAddr) = functionAddress;
}

/**
 * 函数名称表根据4.4的Android版本设置的，不同Android版本映射可能存在差异，可以直接用ida查看维护
 */
void initDvmFunctionTables() {
    void *libVMhandle = dlopen("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);
    if (libVMhandle == NULL) {
        return;
    }

    initDvmFunctionItem("_Z20dvmDecodeIndirectRefP6ThreadP8_jobject",
                        (void **) (&dvmFunctionTables.dvmDecodeIndirectRef), libVMhandle);
    initDvmFunctionItem("_Z13dvmThreadSelfv", (void **) (&dvmFunctionTables.dvmThreadSelf),
                        libVMhandle);
    //这一句代码兼容性不好
    initDvmFunctionItem("sub_4E110", (void **) (&dvmFunctionTables.RegisterNatives),
                        libVMhandle);
    initDvmFunctionItem("_Z14dvmLookupClassPKcP6Objectb",
                        (void **) (&dvmFunctionTables.dvmLookupClass), libVMhandle);

//    initDvmFunctionItem("_Z12dvmInterpretP6ThreadPK6MethodP6JValue",
//                        (void **) (&dvmFunctionTables.dvmInterpret), libVMhandle);
//
//    initDvmFunctionItem("_Z15dvmInvokeMethodP6ObjectPK6MethodP11ArrayObjectS5_P11ClassObjectb",
//                        (void **) (&dvmFunctionTables.dvmInvokeMethod), libVMhandle);

    dlclose(libVMhandle);
}


void *findFunction(char const *functionName, void *libVMhandle) {
    if (libVMhandle == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Error: unable to find the SO : libdvm.so");
        return NULL;
    }
    return dlsym(libVMhandle, functionName);
}


int apiLevel() {
    char version[10];
    __system_property_get("ro.build.version.sdk", version);
    __android_log_print(ANDROID_LOG_INFO, TAG, "api level %s", version);
    int sdk = atoi(version);
    return sdk;
}

void getProcessName(int pid, char *name, int len) {
    int fp = open("/proc/self/cmdline", O_RDONLY);
    memset(name, 0, len);
    read(fp, name, len);
    close(fp);
}

static char charMap[16];
bool hasCharMapInit = false;

void initCharMap() {
    for (int i = 0; i <= 9; i++) {
        charMap[i] = (char) (i + '0');
    }
    for (int i = 10; i < 16; i++) {
        charMap[i] = (char) (i - 10 + 'A');
    }
    hasCharMapInit = true;
}

void toHex(char *destination, const char *source, int sourceLength) {
    //memset(destination, sourceLength * 2, 0);
    if (!hasCharMapInit) {
        initCharMap();
    }
    for (int i = 0; i < sourceLength; i++) {
        destination[i * 2] = charMap[(source[i] >> 4) & 0xff];
        destination[i * 2 + 1] = charMap[source[i] & 0xff];
    }
}


extern "C"
JNIEXPORT void JNICALL
Java_com_virjar_ucrack_unshell_Dumper_preventKillSelf(JNIEnv *env, jclass type) {
    void *libVMhandle = dlopen("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);

    void *addr = findFunction("exit", libVMhandle);
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Unable find symbol exit");
        return;
    }
    if (registerInlineHook((uint32_t) addr, (uint32_t) newExit,
                           (uint32_t **) &oldExit) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }
    dlclose(libVMhandle);

}


extern "C"
JNIEXPORT jint JNICALL
Java_com_virjar_ucrack_plugin_unpack_Dumper_apiLevel(JNIEnv *env, jobject instance) {
    return apiLevel();
}


JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    initDvmFunctionTables();

    JNIEnv *jniEnv;
    vm->GetEnv((void **) &jniEnv, JNI_VERSION_1_6);
    return JNI_VERSION_1_6;
}

jobject createArrayList(JNIEnv *jniEnv) {
    jclass arrayList_class = jniEnv->FindClass("java/util/ArrayList");//获得ArrayList类引用
    jmethodID arrayList_construct = jniEnv->GetMethodID(arrayList_class, "<init>",
                                                        "()V"); //获得得构造函数Id
    return jniEnv->NewObject(arrayList_class, arrayList_construct);
}

jboolean addToArrayList(JNIEnv *jniEnv, jobject arrayList, jobject element) {
    jmethodID list_add = jniEnv->GetMethodID(jniEnv->GetObjectClass(arrayList), "add",
                                             "(Ljava/lang/Object;)Z");
    return jniEnv->CallBooleanMethod(arrayList, list_add, element);
}

void threwIllegalStateException(JNIEnv *jniEnv, const char *message) {
    jniEnv->ExceptionDescribe();
    jniEnv->ExceptionClear();
    jclass illegalStateExceptionClass = jniEnv->FindClass("java/lang/IllegalStateException");
    jniEnv->ThrowNew(illegalStateExceptionClass, message);
}

jobject createByteBuffer(JNIEnv *env, unsigned char *data, int size) {

    jbyteArray byteArray = env->NewByteArray(size);
    env->SetByteArrayRegion(byteArray, 0, size, (const jbyte *) data);
    jclass byteBufferClass = env->FindClass("java/nio/ByteBuffer");
    jmethodID wrapMethod = env->GetStaticMethodID(byteBufferClass, "wrap",
                                                  "([BII)Ljava/nio/ByteBuffer;");
    return env->CallStaticObjectMethod(byteBufferClass, wrapMethod, byteArray, 0, size);
}

void (*oldDvmDetachCurrentThread)();

JavaVM *g_jvm = NULL;
//jobject g_obj_interceptorClass = NULL;

void newDvmDetachCurrentThread() {
    JNIEnv *env;
    jmethodID interceptMethodId;
    //Attach当前线程，请注意，千万不要使用AttachCurrentThread，不要听网上的。
    //该方法的场景是，当在jni上面创建新的线程，且需要在新线程里面使用JNIEnv的时候，通过该函数绑定JNI环境
    //如果一个函数已经处于JNI环境中了，那么不应该在绑定
    //另外AttachCurrentThread应该和DetachCurrentThread成对出现。所以，只有native（pthread_create）的新线程需要这样。。。
    //网上让随意用这个的，那是没有踩到坑，比如：https://blog.csdn.net/u011068702/article/details/78066746
//    if (g_jvm->AttachCurrentThread(&env, NULL) != JNI_OK) {
//        goto bail;
//    }
    //找到对应的类
    g_jvm->GetEnv((void **) &env, JNI_VERSION_1_6);
    if (env == NULL) {
        //当前线程已经退出了，拦截已经没有意义了，我认为在DvmDetachCurrentThread执行之后，都是线程结束逻辑
        goto bail;
    }
    //这个可以安全使用，这是因为g_obj_interceptorClass是全局间接引用，如果g_obj_interceptorClass是直接赋值过来的，换了一个线程之后
    //是找不到他的引用地址的，因为间接引用表和线程绑定的
    //interceptMethodId = env->GetStaticMethodID((jclass) g_obj_interceptorClass,
    //                                            "registerInterceptor",
    //                                           "()V");
    //env->CallStaticObjectMethod((jclass) g_obj_interceptorClass, interceptMethodId);
    // g_jvm->DetachCurrentThread();
    if (env->ExceptionCheck()) {
        //这个监听是有效的，想办法把异常拿出来看看
        ALOGE("thread exit with UncaughtException");
        //但是这个调用是无效的，这是因为爱加密把stdout给替换了？
        env->ExceptionDescribe();
    }
    bail:
    oldDvmDetachCurrentThread();
}

/*instance*/
extern "C"
JNIEXPORT void JNICALL
Java_com_virjar_ucrack_plugin_UncaughtExceptionInterceptor_interceptNative(JNIEnv *env,
                                                                           jobject /* this */) {
    void *libVMhandle = dlopen("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);
    if (libVMhandle == NULL) {
        return;
    }
    void *addr = findFunction("_Z22dvmDetachCurrentThreadv", libVMhandle);
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "Unable find symbol _Z22dvmDetachCurrentThreadv");
        return;
    }
    if (registerInlineHook((uint32_t) addr, (uint32_t) newDvmDetachCurrentThread,
                           (uint32_t **) &oldDvmDetachCurrentThread) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }
    if (inlineHook((uint32_t) addr) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }
    env->GetJavaVM(&g_jvm);
    // g_obj_interceptorClass = env->NewGlobalRef(interceptorClass);
    dlclose(libVMhandle);
}



extern "C"
JNIEXPORT void JNICALL
Java_com_virjar_ucrack_plugin_ExitMonitor_monitorAppExitNative(JNIEnv *env,
                                                               jobject instance) {
    void *libVMhandle = dlopen("libc.so", RTLD_GLOBAL | RTLD_LAZY);
    if (libVMhandle == NULL) {
        return;
    }
    void *addr = findFunction("exit", libVMhandle);
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Unable find symbol exit");
        return;
    }
    if (registerInlineHook((uint32_t) addr, (uint32_t) newExit,
                           (uint32_t **) &oldExit) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }


    addr = findFunction("abort", libVMhandle);
    if (addr == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Unable find symbol abort");
        return;
    }
    if (registerInlineHook((uint32_t) addr, (uint32_t) newAbort,
                           (uint32_t **) &oldAbort) != ELE7EN_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "register hook failed");
        return;
    }


    dlclose(libVMhandle);
}