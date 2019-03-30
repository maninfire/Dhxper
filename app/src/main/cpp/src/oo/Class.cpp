/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Class loading, including bootstrap class loader, linking, and
 * initialization.
 */

#define LOG_CLASS_LOADING 0

#include "libdex/DexClass.h"
#include "Class.h"
#include "Array.h"

#include <stdlib.h>
#include <stddef.h>
#include <sys/stat.h>
#include <include/DvmFunctionTable.h>
#include <cstring>

#if LOG_CLASS_LOADING
#include <unistd.h>
#include <pthread.h>
#include <cutils/process_name.h>
#include <sys/types.h>
#endif

/*
Notes on Linking and Verification

The basic way to retrieve a class is to load it, make sure its superclass
and interfaces are available, prepare its fields, and return it.  This gets
a little more complicated when multiple threads can be trying to retrieve
the class simultaneously, requiring that we use the class object's monitor
to keep things orderly.

The linking (preparing, resolving) of a class can cause us to recursively
load superclasses and interfaces.  Barring circular references (e.g. two
classes that are superclasses of each other), this will complete without
the loader attempting to access the partially-linked class.

With verification, the situation is different.  If we try to verify
every class as we load it, we quickly run into trouble.  Even the lowly
java.lang.Object requires CloneNotSupportedException; follow the list
of referenced classes and you can head down quite a trail.  The trail
eventually leads back to Object, which is officially not fully-formed yet.

The VM spec (specifically, v2 5.4.1) notes that classes pulled in during
verification do not need to be prepared or verified.  This means that we
are allowed to have loaded but unverified classes.  It further notes that
the class must be verified before it is initialized, which allows us to
defer verification for all classes until class init.  You can't execute
code or access fields in an uninitialized class, so this is safe.

It also allows a more peaceful coexistence between verified and
unverifiable code.  If class A refers to B, and B has a method that
refers to a bogus class C, should we allow class A to be verified?
If A only exercises parts of B that don't use class C, then there is
nothing wrong with running code in A.  We can fully verify both A and B,
and allow execution to continue until B causes initialization of C.  The
VerifyError is thrown close to the point of use.

This gets a little weird with java.lang.Class, which is the only class
that can be instantiated before it is initialized.  We have to force
initialization right after the class is created, because by definition we
have instances of it on the heap, and somebody might get a class object and
start making virtual calls on it.  We can end up going recursive during
verification of java.lang.Class, but we avoid that by checking to see if
verification is already in progress before we try to initialize it.
*/

/*
Notes on class loaders and interaction with optimization / verification

In what follows, "pre-verification" and "optimization" are the steps
performed by the dexopt command, which attempts to verify and optimize
classes as part of unpacking jar files and storing the DEX data in the
dalvik-cache directory.  These steps are performed by loading the DEX
files directly, without any assistance from ClassLoader instances.

When we pre-verify and optimize a class in a DEX file, we make some
assumptions about where the class loader will go to look for classes.
If we can't guarantee those assumptions, e.g. because a class ("AppClass")
references something not defined in the bootstrap jars or the AppClass jar,
we can't pre-verify or optimize the class.

The VM doesn't define the behavior of user-defined class loaders.
For example, suppose application class AppClass, loaded by UserLoader,
has a method that creates a java.lang.String.  The first time
AppClass.stringyMethod tries to do something with java.lang.String, it
asks UserLoader to find it.  UserLoader is expected to defer to its parent
loader, but isn't required to.  UserLoader might provide a replacement
for String.

We can run into trouble if we pre-verify AppClass with the assumption that
java.lang.String will come from core.jar, and don't verify this assumption
at runtime.  There are two places that an alternate implementation of
java.lang.String can come from: the AppClass jar, or from some other jar
that UserLoader knows about.  (Someday UserLoader will be able to generate
some bytecode and call DefineClass, but not yet.)

To handle the first situation, the pre-verifier will explicitly check for
conflicts between the class being optimized/verified and the bootstrap
classes.  If an app jar contains a class that has the same package and
class name as a class in a bootstrap jar, the verification resolver refuses
to find either, which will block pre-verification and optimization on
classes that reference ambiguity.  The VM will postpone verification of
the app class until first load.

For the second situation, we need to ensure that all references from a
pre-verified class are satisified by the class' jar or earlier bootstrap
jars.  In concrete terms: when resolving a reference to NewClass,
which was caused by a reference in class AppClass, we check to see if
AppClass was pre-verified.  If so, we require that NewClass comes out
of either the AppClass jar or one of the jars in the bootstrap path.
(We may not control the class loaders, but we do manage the DEX files.
We can verify that it's either (loader==null && dexFile==a_boot_dex)
or (loader==UserLoader && dexFile==AppClass.dexFile).  Classes from
DefineClass can't be pre-verified, so this doesn't apply.)

This should ensure that you can't "fake out" the pre-verifier by creating
a user-defined class loader that replaces system classes.  It should
also ensure that you can write such a loader and have it work in the
expected fashion; all you lose is some performance due to "just-in-time
verification" and the lack of DEX optimizations.

There is a "back door" of sorts in the class resolution check, due to
the fact that the "class ref" entries are shared between the bytecode
and meta-data references (e.g. annotations and exception handler lists).
The class references in annotations have no bearing on class verification,
so when a class does an annotation query that causes a class reference
index to be resolved, we don't want to fail just because the calling
class was pre-verified and the resolved class is in some random DEX file.
The successful resolution adds the class to the "resolved classes" table,
so when optimized bytecode references it we don't repeat the resolve-time
check.  We can avoid this by not updating the "resolved classes" table
when the class reference doesn't come out of something that has been
checked by the verifier, but that has a nonzero performance impact.
Since the ultimate goal of this test is to catch an unusual situation
(user-defined class loaders redefining core classes), the added caution
may not be worth the performance hit.
*/

/*
 * Class serial numbers start at this value.  We use a nonzero initial
 * value so they stand out in binary dumps (e.g. hprof output).
 */
#define INITIAL_CLASS_SERIAL_NUMBER 0x50000000

/*
 * Constant used to size an auxillary class object data structure.
 * For optimum memory use this should be equal to or slightly larger than
 * the number of classes loaded when the zygote finishes initializing.
 */
#define ZYGOTE_CLASS_CUTOFF 2304

#define CLASS_SFIELD_SLOTS 1

static ClassPathEntry *processClassPath(const char *pathStr, bool isBootstrap);

static void freeCpeArray(ClassPathEntry *cpe);

static ClassObject *findClassFromLoaderNoInit(
        const char *descriptor, Object *loader);

static ClassObject *findClassNoInit(const char *descriptor, Object *loader, \
    DvmDex *pDvmDex);

static ClassObject *loadClassFromDex(DvmDex *pDvmDex,
                                     const DexClassDef *pClassDef, Object *loader);

static void loadMethodFromDex(ClassObject *clazz, const DexMethod *pDexMethod, \
    Method *meth);

static int computeJniArgInfo(const DexProto *proto);

static void loadSFieldFromDex(ClassObject *clazz,
                              const DexField *pDexSField, StaticField *sfield);

static void loadIFieldFromDex(ClassObject *clazz,
                              const DexField *pDexIField, InstField *field);

static bool precacheReferenceOffsets(ClassObject *clazz);

static void computeRefOffsets(ClassObject *clazz);

static void freeMethodInnards(Method *meth);

static bool createVtable(ClassObject *clazz);

static bool createIftable(ClassObject *clazz);

static bool insertMethodStubs(ClassObject *clazz);

static bool computeFieldOffsets(ClassObject *clazz);

static void throwEarlierClassFailure(ClassObject *clazz);

#if LOG_CLASS_LOADING
/*
 * Logs information about a class loading with given timestamp.
 *
 * TODO: In the case where we fail in dvmLinkClass() and log the class as closing (type='<'),
 * it would probably be better to use a new type code to indicate the failure.  This change would
 * require a matching change in the parser and analysis code in frameworks/base/tools/preload.
 */
static void logClassLoadWithTime(char type, ClassObject* clazz, u8 time) {
    pid_t ppid = getppid();
    pid_t pid = getpid();
    unsigned int tid = (unsigned int) pthread_self();

    ALOG(LOG_INFO, "PRELOAD", "%c%d:%d:%d:%s:%d:%s:%lld", type, ppid, pid, tid,
        get_process_name(), (int) clazz->classLoader, clazz->descriptor,
        time);
}

/*
 * Logs information about a class loading.
 */
static void logClassLoad(char type, ClassObject* clazz) {
    logClassLoadWithTime(type, clazz, dvmGetThreadCpuTimeNsec());
}
#endif


static size_t classObjectSize(size_t sfieldCount) {
    return dvmFunctionTables.classObjectSize(sfieldCount);
}

size_t dvmClassObjectSize(const ClassObject *clazz) {
    assert(clazz != NULL);
    return classObjectSize(clazz->sfieldCount);
}

/* (documented in header) */
ClassObject *dvmFindPrimitiveClass(char type) {
    return dvmFunctionTables.dvmFindPrimitiveClass(type);
}

/*
 * Synthesize a primitive class.
 *
 * Just creates the class and returns it (does not add it to the class list).
 */
static bool createPrimitiveType(PrimitiveType primitiveType, ClassObject **pClass) {
    return dvmFunctionTables.createPrimitiveType(primitiveType, pClass);
}

/*
 * ===========================================================================
 *      Bootstrap class loader
 * ===========================================================================
 */



/*
 * Returns "true" if the class path contains the specified path.
 */
bool dvmClassPathContains(const ClassPathEntry *cpe, const char *path) {
    while (cpe->kind != kCpeLastEntry) {
        if (strcmp(cpe->fileName, path) == 0)
            return true;

        cpe++;
    }
    return false;
}

/*
 * Free an array of ClassPathEntry structs.
 *
 * We release the contents of each entry, then free the array itself.
 */
static void freeCpeArray(ClassPathEntry *cpe) {
    dvmFunctionTables.freeCpeArray(cpe);
}

/*
 * Get the filename suffix of the given file (everything after the
 * last "." if any, or "<none>" if there's no apparent suffix). The
 * passed-in buffer will always be '\0' terminated.
 */
static void getFileNameSuffix(const char *fileName, char *suffixBuf, size_t suffixBufLen) {
    const char *lastDot = strrchr(fileName, '.');

    strlcpy(suffixBuf, (lastDot == NULL) ? "<none>" : (lastDot + 1), suffixBufLen);
}

/*
 * Prepare a ClassPathEntry struct, which at this point only has a valid
 * filename.  We need to figure out what kind of file it is, and for
 * everything other than directories we need to open it up and see
 * what's inside.
 */
static bool prepareCpe(ClassPathEntry *cpe, bool isBootstrap) {
    return dvmFunctionTables.prepareCpe(cpe, isBootstrap);
}

/*
 * Convert a colon-separated list of directories, Zip files, and DEX files
 * into an array of ClassPathEntry structs.
 *
 * During normal startup we fail if there are no entries, because we won't
 * get very far without the basic language support classes, but if we're
 * optimizing a DEX file we allow it.
 *
 * If entries are added or removed from the bootstrap class path, the
 * dependencies in the DEX files will break, and everything except the
 * very first entry will need to be regenerated.
 */
static ClassPathEntry *processClassPath(const char *pathStr, bool isBootstrap) {
    return dvmFunctionTables.processClassPath(pathStr, isBootstrap);
}

/*
 * Search the DEX files we loaded from the bootstrap class path for a DEX
 * file that has the class with the matching descriptor.
 *
 * Returns the matching DEX file and DexClassDef entry if found, otherwise
 * returns NULL.
 */
static DvmDex *searchBootPathForClass(const char *descriptor,
                                      const DexClassDef **ppClassDef) {
    return dvmFunctionTables.searchBootPathForClass(descriptor, ppClassDef);
}

/*
 * Set the "extra" DEX, which becomes a de facto member of the bootstrap
 * class set.
 */
void dvmSetBootPathExtraDex(DvmDex *pDvmDex) {
    dvmFunctionTables.dvmSetBootPathExtraDex(pDvmDex);
}


/*
 * Return the #of entries in the bootstrap class path.
 *
 * (Used for ClassLoader.getResources().)
 */
int dvmGetBootPathSize() {
    return dvmFunctionTables.dvmGetBootPathSize();
}

/*
 * Find a resource with the specified name in entry N of the boot class path.
 *
 * We return a newly-allocated String of one of these forms:
 *   file://path/name
 *   jar:file://path!/name
 * Where "path" is the bootstrap class path entry and "name" is the string
 * passed into this method.  "path" needs to be an absolute path (starting
 * with '/'); if it's not we'd need to "absolutify" it as part of forming
 * the URL string.
 */
StringObject *dvmGetBootPathResource(const char *name, int idx) {
    return dvmFunctionTables.dvmGetBootPathResource(name, idx);
}


/*
 * ===========================================================================
 *      Class list management
 * ===========================================================================
 */

/* search for these criteria in the Class hash table */
struct ClassMatchCriteria {
    const char *descriptor;
    Object *loader;
};

#define kInitLoaderInc  4       /* must be power of 2 */

static InitiatingLoaderList *dvmGetInitiatingLoaderList(ClassObject *clazz) {
    return dvmFunctionTables.dvmGetInitiatingLoaderList(clazz);
}

/*
 * Determine if "loader" appears in clazz' initiating loader list.
 *
 * The class hash table lock must be held when calling here, since
 * it's also used when updating a class' initiating loader list.
 *
 * TODO: switch to some sort of lock-free data structure so we don't have
 * to grab the lock to do a lookup.  Among other things, this would improve
 * the speed of compareDescriptorClasses().
 */
bool dvmLoaderInInitiatingList(const ClassObject *clazz, const Object *loader) {
    /*
     * The bootstrap class loader can't be just an initiating loader for
     * anything (it's always the defining loader if the class is visible
     * to it).  We don't put defining loaders in the initiating list.
     */
    if (loader == NULL)
        return false;

    /*
     * Scan the list for a match.  The list is expected to be short.
     */
    /* Cast to remove the const from clazz, but use const loaderList */
    ClassObject *nonConstClazz = (ClassObject *) clazz;
    const InitiatingLoaderList *loaderList =
            dvmGetInitiatingLoaderList(nonConstClazz);
    int i;
    for (i = loaderList->initiatingLoaderCount - 1; i >= 0; --i) {
        if (loaderList->initiatingLoaders[i] == loader) {
            //ALOGI("+++ found initiating match %p in %s",
            //    loader, clazz->descriptor);
            return true;
        }
    }
    return false;
}

/*
 * Add "loader" to clazz's initiating loader set, unless it's the defining
 * class loader.
 *
 * In the common case this will be a short list, so we don't need to do
 * anything too fancy here.
 *
 * This locks gDvm.loadedClasses for synchronization, so don't hold it
 * when calling here.
 */
void dvmAddInitiatingLoader(ClassObject *clazz, Object *loader) {
    dvmFunctionTables.dvmAddInitiatingLoader(clazz, loader);
}

/*
 * (This is a dvmHashTableLookup callback.)
 *
 * Entries in the class hash table are stored as { descriptor, d-loader }
 * tuples.  If the hashed class descriptor matches the requested descriptor,
 * and the hashed defining class loader matches the requested class
 * loader, we're good.  If only the descriptor matches, we check to see if the
 * loader is in the hashed class' initiating loader list.  If so, we
 * can return "true" immediately and skip some of the loadClass melodrama.
 *
 * The caller must lock the hash table before calling here.
 *
 * Returns 0 if a matching entry is found, nonzero otherwise.
 */
static int hashcmpClassByCrit(const void *vclazz, const void *vcrit) {
    const ClassObject *clazz = (const ClassObject *) vclazz;
    const ClassMatchCriteria *pCrit = (const ClassMatchCriteria *) vcrit;
    bool match;

    match = (strcmp(clazz->descriptor, pCrit->descriptor) == 0 &&
             (clazz->classLoader == pCrit->loader ||
              (pCrit->loader != NULL &&
               dvmLoaderInInitiatingList(clazz, pCrit->loader))));
    //if (match)
    //    ALOGI("+++ %s %p matches existing %s %p",
    //        pCrit->descriptor, pCrit->loader,
    //        clazz->descriptor, clazz->classLoader);
    return !match;
}

/*
 * Like hashcmpClassByCrit, but passing in a fully-formed ClassObject
 * instead of a ClassMatchCriteria.
 */
static int hashcmpClassByClass(const void *vclazz, const void *vaddclazz) {
    const ClassObject *clazz = (const ClassObject *) vclazz;
    const ClassObject *addClazz = (const ClassObject *) vaddclazz;
    bool match;

    match = (strcmp(clazz->descriptor, addClazz->descriptor) == 0 &&
             (clazz->classLoader == addClazz->classLoader ||
              (addClazz->classLoader != NULL &&
               dvmLoaderInInitiatingList(clazz, addClazz->classLoader))));
    return !match;
}

/*
 * Search through the hash table to find an entry with a matching descriptor
 * and an initiating class loader that matches "loader".
 *
 * The table entries are hashed on descriptor only, because they're unique
 * on *defining* class loader, not *initiating* class loader.  This isn't
 * great, because it guarantees we will have to probe when multiple
 * class loaders are used.
 *
 * Note this does NOT try to load a class; it just finds a class that
 * has already been loaded.
 *
 * If "unprepOkay" is set, this will return classes that have been added
 * to the hash table but are not yet fully loaded and linked.  Otherwise,
 * such classes are ignored.  (The only place that should set "unprepOkay"
 * is findClassNoInit(), which will wait for the prep to finish.)
 *
 * Returns NULL if not found.
 */
ClassObject *dvmLookupClass(const char *descriptor, Object *loader,
                            bool unprepOkay) {
    return dvmFunctionTables.dvmLookupClass(descriptor, loader, unprepOkay);
}

/*
 * Add a new class to the hash table.
 *
 * The class is considered "new" if it doesn't match on both the class
 * descriptor and the defining class loader.
 *
 * TODO: we should probably have separate hash tables for each
 * ClassLoader. This could speed up dvmLookupClass and
 * other common operations. It does imply a VM-visible data structure
 * for each ClassLoader object with loaded classes, which we don't
 * have yet.
 */
bool dvmAddClassToHash(ClassObject *clazz) {
    return dvmFunctionTables.dvmAddClassToHash(clazz);
}

#if 0
/*
 * Compute hash value for a class.
 */
u4 hashcalcClass(const void* item)
{
    return dvmComputeUtf8Hash(((const ClassObject*) item)->descriptor);
}

/*
 * Check the performance of the "loadedClasses" hash table.
 */
void dvmCheckClassTablePerf()
{
    dvmHashTableLock(gDvm.loadedClasses);
    dvmHashTableProbeCount(gDvm.loadedClasses, hashcalcClass,
        hashcmpClassByClass);
    dvmHashTableUnlock(gDvm.loadedClasses);
}
#endif


/*
 * ===========================================================================
 *      Class creation
 * ===========================================================================
 */

/*
 * Set clazz->serialNumber to the next available value.
 *
 * This usually happens *very* early in class creation, so don't expect
 * anything else in the class to be ready.
 */
void dvmSetClassSerialNumber(ClassObject *clazz) {
    dvmFunctionTables.dvmSetClassSerialNumber(clazz);
}


/*
 * Find the named class (by descriptor), using the specified
 * initiating ClassLoader.
 *
 * The class will be loaded and initialized if it has not already been.
 * If necessary, the superclass will be loaded.
 *
 * If the class can't be found, returns NULL with an appropriate exception
 * raised.
 */
ClassObject *dvmFindClass(const char *descriptor, Object *loader) {
    return dvmFunctionTables.dvmFindClass(descriptor, loader);
}

/*
 * Find the named class (by descriptor), using the specified
 * initiating ClassLoader.
 *
 * The class will be loaded if it has not already been, as will its
 * superclass.  It will not be initialized.
 *
 * If the class can't be found, returns NULL with an appropriate exception
 * raised.
 */
ClassObject *dvmFindClassNoInit(const char *descriptor,
                                Object *loader) {
    assert(descriptor != NULL);
    //assert(loader != NULL);

            LOGVV("FindClassNoInit '%s' %p", descriptor, loader);

    if (*descriptor == '[') {
        /*
         * Array class.  Find in table, generate if not found.
         */
        return dvmFindArrayClass(descriptor, loader);
    } else {
        /*
         * Regular class.  Find in table, load if not found.
         */
        if (loader != NULL) {
            return findClassFromLoaderNoInit(descriptor, loader);
        } else {
            return dvmFindSystemClassNoInit(descriptor);
        }
    }
}

/*
 * Load the named class (by descriptor) from the specified class
 * loader.  This calls out to let the ClassLoader object do its thing.
 *
 * Returns with NULL and an exception raised on error.
 */
static ClassObject *findClassFromLoaderNoInit(const char *descriptor,
                                              Object *loader) {
    return dvmFunctionTables.findClassFromLoaderNoInit(descriptor, loader);
}

/*
 * Load the named class (by descriptor) from the specified DEX file.
 * Used by class loaders to instantiate a class object from a
 * VM-managed DEX.
 */
ClassObject *dvmDefineClass(DvmDex *pDvmDex, const char *descriptor,
                            Object *classLoader) {
    assert(pDvmDex != NULL);

    return findClassNoInit(descriptor, classLoader, pDvmDex);
}


/*
 * Find the named class (by descriptor), scanning through the
 * bootclasspath if it hasn't already been loaded.
 *
 * "descriptor" looks like "Landroid/debug/Stuff;".
 *
 * Uses NULL as the defining class loader.
 */
ClassObject *dvmFindSystemClass(const char *descriptor) {
    return dvmFunctionTables.dvmFindSystemClass(descriptor);
}

/*
 * Find the named class (by descriptor), searching for it in the
 * bootclasspath.
 *
 * On failure, this returns NULL with an exception raised.
 */
ClassObject *dvmFindSystemClassNoInit(const char *descriptor) {
    return findClassNoInit(descriptor, NULL, NULL);
}

/*
 * Find the named class (by descriptor). If it's not already loaded,
 * we load it and link it, but don't execute <clinit>. (The VM has
 * specific limitations on which events can cause initialization.)
 *
 * If "pDexFile" is NULL, we will search the bootclasspath for an entry.
 *
 * On failure, this returns NULL with an exception raised.
 *
 * TODO: we need to return an indication of whether we loaded the class or
 * used an existing definition.  If somebody deliberately tries to load a
 * class twice in the same class loader, they should get a LinkageError,
 * but inadvertent simultaneous class references should "just work".
 */
static ClassObject *findClassNoInit(const char *descriptor, Object *loader,
                                    DvmDex *pDvmDex) {
    return dvmFunctionTables.findClassNoInit(descriptor, loader, pDvmDex);
}


/*
 * Try to load the indicated class from the specified DEX file.
 *
 * This is effectively loadClass()+defineClass() for a DexClassDef.  The
 * loading was largely done when we crunched through the DEX.
 *
 * Returns NULL on failure.  If we locate the class but encounter an error
 * while processing it, an appropriate exception is thrown.
 */
static ClassObject *loadClassFromDex(DvmDex *pDvmDex,
                                     const DexClassDef *pClassDef, Object *classLoader) {
    return dvmFunctionTables.loadClassFromDex(pDvmDex, pClassDef, classLoader);
}

/*
 * Free anything in a ClassObject that was allocated on the system heap.
 *
 * The ClassObject itself is allocated on the GC heap, so we leave it for
 * the garbage collector.
 *
 * NOTE: this may be called with a partially-constructed object.
 * NOTE: there is no particular ordering imposed, so don't go poking at
 * superclasses.
 */
void dvmFreeClassInnards(ClassObject *clazz) {
    dvmFunctionTables.dvmFreeClassInnards(clazz);
}

/*
 * Free anything in a Method that was allocated on the system heap.
 *
 * The containing class is largely torn down by this point.
 */
static void freeMethodInnards(Method *meth) {
    dvmFunctionTables.freeMethodInnards(meth);
}

/*
 * Pull the interesting pieces out of a DexMethod.
 *
 * The DEX file isn't going anywhere, so we don't need to make copies of
 * the code area.
 */
static void loadMethodFromDex(ClassObject *clazz, const DexMethod *pDexMethod,
                              Method *meth) {
    dvmFunctionTables.loadMethodFromDex(clazz, pDexMethod, meth);
}


/*
 * jniArgInfo (32-bit int) layout:
 *   SRRRHHHH HHHHHHHH HHHHHHHH HHHHHHHH
 *
 *   S - if set, do things the hard way (scan the signature)
 *   R - return-type enumeration
 *   H - target-specific hints
 *
 * This info is used at invocation time by dvmPlatformInvoke.  In most
 * cases, the target-specific hints allow dvmPlatformInvoke to avoid
 * having to fully parse the signature.
 *
 * The return-type bits are always set, even if target-specific hint bits
 * are unavailable.
 */
static int computeJniArgInfo(const DexProto *proto) {
    return dvmFunctionTables.computeJniArgInfo(proto);
}

/*
 * Load information about a static field.
 *
 * This also "prepares" static fields by initializing them
 * to their "standard default values".
 */
static void loadSFieldFromDex(ClassObject *clazz,
                              const DexField *pDexSField, StaticField *sfield) {
    DexFile *pDexFile = clazz->pDvmDex->pDexFile;
    const DexFieldId *pFieldId;

    pFieldId = dexGetFieldId(pDexFile, pDexSField->fieldIdx);

    sfield->clazz = clazz;
    sfield->name = dexStringById(pDexFile, pFieldId->nameIdx);
    sfield->signature = dexStringByTypeIdx(pDexFile, pFieldId->typeIdx);
    sfield->accessFlags = pDexSField->accessFlags;

    /* Static object field values are set to "standard default values"
     * (null or 0) until the class is initialized.  We delay loading
     * constant values from the class until that time.
     */
    //sfield->value.j = 0;
    assert(sfield->value.j == 0LL);     // cleared earlier with calloc
}

/*
 * Load information about an instance field.
 */
static void loadIFieldFromDex(ClassObject *clazz,
                              const DexField *pDexIField, InstField *ifield) {
    DexFile *pDexFile = clazz->pDvmDex->pDexFile;
    const DexFieldId *pFieldId;

    pFieldId = dexGetFieldId(pDexFile, pDexIField->fieldIdx);

    ifield->clazz = clazz;
    ifield->name = dexStringById(pDexFile, pFieldId->nameIdx);
    ifield->signature = dexStringByTypeIdx(pDexFile, pFieldId->typeIdx);
    ifield->accessFlags = pDexIField->accessFlags;
#ifndef NDEBUG
    assert(ifield->byteOffset == 0);    // cleared earlier with calloc
    ifield->byteOffset = -1;    // make it obvious if we fail to set later
#endif
}

/*
 * Cache java.lang.ref.Reference fields and methods.
 */
static bool precacheReferenceOffsets(ClassObject *clazz) {
    return dvmFunctionTables.precacheReferenceOffsets(clazz);
}


/*
 * Set the bitmap of reference offsets, refOffsets, from the ifields
 * list.
 */
static void computeRefOffsets(ClassObject *clazz) {
    if (clazz->super != NULL) {
        clazz->refOffsets = clazz->super->refOffsets;
    } else {
        clazz->refOffsets = 0;
    }
    /*
     * If our superclass overflowed, we don't stand a chance.
     */
    if (clazz->refOffsets != CLASS_WALK_SUPER) {
        InstField *f;
        int i;

        /* All of the fields that contain object references
         * are guaranteed to be at the beginning of the ifields list.
         */
        f = clazz->ifields;
        const int ifieldRefCount = clazz->ifieldRefCount;
        for (i = 0; i < ifieldRefCount; i++) {
            /*
             * Note that, per the comment on struct InstField,
             * f->byteOffset is the offset from the beginning of
             * obj, not the offset into obj->instanceData.
             */
            assert(f->byteOffset >= (int) CLASS_SMALLEST_OFFSET);
            assert((f->byteOffset & (CLASS_OFFSET_ALIGNMENT - 1)) == 0);
            if (CLASS_CAN_ENCODE_OFFSET(f->byteOffset)) {
                u4 newBit = CLASS_BIT_FROM_OFFSET(f->byteOffset);
                assert(newBit != 0);
                clazz->refOffsets |= newBit;
            } else {
                clazz->refOffsets = CLASS_WALK_SUPER;
                break;
            }
            f++;
        }
    }
}


/*
 * Link (prepare and resolve).  Verification is deferred until later.
 *
 * This converts symbolic references into pointers.  It's independent of
 * the source file format.
 *
 * If clazz->status is CLASS_IDX, then clazz->super and interfaces[] are
 * holding class reference indices rather than pointers.  The class
 * references will be resolved during link.  (This is done when
 * loading from DEX to avoid having to create additional storage to
 * pass the indices around.)
 *
 * Returns "false" with an exception pending on failure.
 */
bool dvmLinkClass(ClassObject *clazz) {
    return dvmFunctionTables.dvmLinkClass(clazz);
}

/*
 * Create the virtual method table.
 *
 * The top part of the table is a copy of the table from our superclass,
 * with our local methods overriding theirs.  The bottom part of the table
 * has any new methods we defined.
 */
static bool createVtable(ClassObject *clazz) {
    return dvmFunctionTables.createVtable(clazz);
}

/*
 * Create and populate "iftable".
 *
 * The set of interfaces we support is the combination of the interfaces
 * we implement directly and those implemented by our superclass.  Each
 * interface can have one or more "superinterfaces", which we must also
 * support.  For speed we flatten the tree out.
 *
 * We might be able to speed this up when there are lots of interfaces
 * by merge-sorting the class pointers and binary-searching when removing
 * duplicates.  We could also drop the duplicate removal -- it's only
 * there to reduce the memory footprint.
 *
 * Because of "Miranda methods", this may reallocate clazz->virtualMethods.
 *
 * Returns "true" on success.
 */
static bool createIftable(ClassObject *clazz) {
    return dvmFunctionTables.createIftable(clazz);
}


/*
 * Provide "stub" implementations for methods without them.
 *
 * Currently we provide an implementation for all abstract methods that
 * throws an AbstractMethodError exception.  This allows us to avoid an
 * explicit check for abstract methods in every virtual call.
 *
 * NOTE: for Miranda methods, the method declaration is a clone of what
 * was found in the interface class.  That copy may already have had the
 * function pointer filled in, so don't be surprised if it's not NULL.
 *
 * NOTE: this sets the "native" flag, giving us an "abstract native" method,
 * which is nonsensical.  Need to make sure that this doesn't escape the
 * VM.  We can either mask it out in reflection calls, or copy "native"
 * into the high 16 bits of accessFlags and check that internally.
 */
static bool insertMethodStubs(ClassObject *clazz) {
    return dvmFunctionTables.insertMethodStubs(clazz);
}


/*
 * Swap two instance fields.
 */
static inline void swapField(InstField *pOne, InstField *pTwo) {
    InstField swap;

            LOGVV("  --- swap '%s' and '%s'", pOne->name, pTwo->name);
    swap = *pOne;
    *pOne = *pTwo;
    *pTwo = swap;
}

/*
 * Assign instance fields to u4 slots.
 *
 * The top portion of the instance field area is occupied by the superclass
 * fields, the bottom by the fields for this class.
 *
 * "long" and "double" fields occupy two adjacent slots.  On some
 * architectures, 64-bit quantities must be 64-bit aligned, so we need to
 * arrange fields (or introduce padding) to ensure this.  We assume the
 * fields of the topmost superclass (i.e. Object) are 64-bit aligned, so
 * we can just ensure that the offset is "even".  To avoid wasting space,
 * we want to move non-reference 32-bit fields into gaps rather than
 * creating pad words.
 *
 * In the worst case we will waste 4 bytes, but because objects are
 * allocated on >= 64-bit boundaries, those bytes may well be wasted anyway
 * (assuming this is the most-derived class).
 *
 * Pad words are not represented in the field table, so the field table
 * itself does not change size.
 *
 * The number of field slots determines the size of the object, so we
 * set that here too.
 *
 * This function feels a little more complicated than I'd like, but it
 * has the property of moving the smallest possible set of fields, which
 * should reduce the time required to load a class.
 *
 * NOTE: reference fields *must* come first, or precacheReferenceOffsets()
 * will break.
 */
static bool computeFieldOffsets(ClassObject *clazz) {
    return dvmFunctionTables.computeFieldOffsets(clazz);
}

/*
 * The class failed to initialize on a previous attempt, so we want to throw
 * a NoClassDefFoundError (v2 2.17.5).  The exception to this rule is if we
 * failed in verification, in which case v2 5.4.1 says we need to re-throw
 * the previous error.
 */
static void throwEarlierClassFailure(ClassObject *clazz) {
    dvmFunctionTables.throwEarlierClassFailure(clazz);
}


/*
 * Returns true if the class is being initialized by us (which means that
 * calling dvmInitClass will return immediately after fiddling with locks).
 * Returns false if it's not being initialized, or if it's being
 * initialized by another thread.
 *
 * The value for initThreadId is always set to "self->threadId", by the
 * thread doing the initializing.  If it was done by the current thread,
 * we are guaranteed to see "initializing" and our thread ID, even on SMP.
 * If it was done by another thread, the only bad situation is one in
 * which we see "initializing" and a stale copy of our own thread ID
 * while another thread is actually handling init.
 *
 * The initThreadId field is used during class linking, so it *is*
 * possible to have a stale value floating around.  We need to ensure
 * that memory accesses happen in the correct order.
 */
bool dvmIsClassInitializing(const ClassObject *clazz) {
    return dvmFunctionTables.dvmIsClassInitializing(clazz);
}

/*
 * If a class has not been initialized, do so by executing the code in
 * <clinit>.  The sequence is described in the VM spec v2 2.17.5.
 *
 * It is possible for multiple threads to arrive here simultaneously, so
 * we need to lock the class while we check stuff.  We know that no
 * interpreted code has access to the class yet, so we can use the class's
 * monitor lock.
 *
 * We will often be called recursively, e.g. when the <clinit> code resolves
 * one of its fields, the field resolution will try to initialize the class.
 * In that case we will return "true" even though the class isn't actually
 * ready to go.  The ambiguity can be resolved with dvmIsClassInitializing().
 * (TODO: consider having this return an enum to avoid the extra call --
 * return -1 on failure, 0 on success, 1 on still-initializing.  Looks like
 * dvmIsClassInitializing() is always paired with *Initialized())
 *
 * This can get very interesting if a class has a static field initialized
 * to a new instance of itself.  <clinit> will end up calling <init> on
 * the members it is initializing, which is fine unless it uses the contents
 * of static fields to initialize instance fields.  This will leave the
 * static-referenced objects in a partially initialized state.  This is
 * reasonably rare and can sometimes be cured with proper field ordering.
 *
 * On failure, returns "false" with an exception raised.
 *
 * -----
 *
 * It is possible to cause a deadlock by having a situation like this:
 *   class A { static { sleep(10000); new B(); } }
 *   class B { static { sleep(10000); new A(); } }
 *   new Thread() { public void run() { new A(); } }.start();
 *   new Thread() { public void run() { new B(); } }.start();
 * This appears to be expected under the spec.
 *
 * The interesting question is what to do if somebody calls Thread.interrupt()
 * on one of the deadlocked threads.  According to the VM spec, they're both
 * sitting in "wait".  Should the interrupt code quietly raise the
 * "interrupted" flag, or should the "wait" return immediately with an
 * exception raised?
 *
 * This gets a little murky.  The VM spec says we call "wait", and the
 * spec for Thread.interrupt says Object.wait is interruptible.  So it
 * seems that, if we get unlucky and interrupt class initialization, we
 * are expected to throw (which gets converted to ExceptionInInitializerError
 * since InterruptedException is checked).
 *
 * There are a couple of problems here.  First, all threads are expected to
 * present a consistent view of class initialization, so we can't have it
 * fail in one thread and succeed in another.  Second, once a class fails
 * to initialize, it must *always* fail.  This means that a stray interrupt()
 * call could render a class unusable for the lifetime of the VM.
 *
 * In most cases -- the deadlock example above being a counter-example --
 * the interrupting thread can't tell whether the target thread handled
 * the initialization itself or had to wait while another thread did the
 * work.  Refusing to interrupt class initialization is, in most cases,
 * not something that a program can reliably detect.
 *
 * On the assumption that interrupting class initialization is highly
 * undesirable in most circumstances, and that failing to do so does not
 * deviate from the spec in a meaningful way, we don't allow class init
 * to be interrupted by Thread.interrupt().
 */
bool dvmInitClass(ClassObject *clazz) {
    return dvmFunctionTables.dvmInitClass(clazz);
}

/*
 * Replace method->nativeFunc and method->insns with new values.  This is
 * commonly performed after successful resolution of a native method.
 *
 * There are three basic states:
 *  (1) (initial) nativeFunc = dvmResolveNativeMethod, insns = NULL
 *  (2) (internal native) nativeFunc = <impl>, insns = NULL
 *  (3) (JNI) nativeFunc = JNI call bridge, insns = <impl>
 *
 * nativeFunc must never be NULL for a native method.
 *
 * The most common transitions are (1)->(2) and (1)->(3).  The former is
 * atomic, since only one field is updated; the latter is not, but since
 * dvmResolveNativeMethod ignores the "insns" field we just need to make
 * sure the update happens in the correct order.
 *
 * A transition from (2)->(1) would work fine, but (3)->(1) will not,
 * because both fields change.  If we did this while a thread was executing
 * in the call bridge, we could null out the "insns" field right before
 * the bridge tried to call through it.  So, once "insns" is set, we do
 * not allow it to be cleared.  A NULL value for the "insns" argument is
 * treated as "do not change existing value".
 */
void dvmSetNativeFunc(Method *method, DalvikBridgeFunc func,
                      const u2 *insns) {
    dvmFunctionTables.dvmSetNativeFunc(method, func, insns);
}

/*
 * Add a RegisterMap to a Method.  This is done when we verify the class
 * and compute the register maps at class initialization time (i.e. when
 * we don't have a pre-generated map).  This means "pMap" is on the heap
 * and should be freed when the Method is discarded.
 */
void dvmSetRegisterMap(Method *method, const RegisterMap *pMap) {
    dvmFunctionTables.dvmSetRegisterMap(method, pMap);
}

/*
 * dvmHashForeach callback.  A nonzero return value causes foreach to
 * bail out.
 */
static int findClassCallback(void *vclazz, void *arg) {
    ClassObject *clazz = (ClassObject *) vclazz;
    const char *descriptor = (const char *) arg;

    if (strcmp(clazz->descriptor, descriptor) == 0)
        return (int) clazz;
    return 0;
}

/*
 * Find a loaded class by descriptor. Returns the first one found.
 * Because there can be more than one if class loaders are involved,
 * this is not an especially good API. (Currently only used by the
 * debugger and "checking" JNI.)
 *
 * "descriptor" should have the form "Ljava/lang/Class;" or
 * "[Ljava/lang/Class;", i.e. a descriptor and not an internal-form
 * class name.
 */
ClassObject *dvmFindLoadedClass(const char *descriptor) {
    return dvmFunctionTables.dvmFindLoadedClass(descriptor);
}

/*
 * Retrieve the system (a/k/a application) class loader.
 *
 * The caller must call dvmReleaseTrackedAlloc on the result.
 */
Object *dvmGetSystemClassLoader() {
    return dvmFunctionTables.dvmGetSystemClassLoader();
}


/*
 * This is a dvmHashForeach callback.
 */
static int dumpClass(void *vclazz, void *varg) {
    const ClassObject *clazz = (const ClassObject *) vclazz;
    const ClassObject *super;
    int flags = (int) varg;
    char *desc;
    int i;

    if (clazz == NULL) {
        ALOGI("dumpClass: ignoring request to dump null class");
        return 0;
    }

    if ((flags & kDumpClassFullDetail) == 0) {
        bool showInit = (flags & kDumpClassInitialized) != 0;
        bool showLoader = (flags & kDumpClassClassLoader) != 0;
        const char *initStr;

        initStr = dvmIsClassInitialized(clazz) ? "true" : "false";

        if (showInit && showLoader)
            ALOGI("%s %p %s", clazz->descriptor, clazz->classLoader, initStr);
        else if (showInit)
            ALOGI("%s %s", clazz->descriptor, initStr);
        else if (showLoader)
            ALOGI("%s %p", clazz->descriptor, clazz->classLoader);
        else
            ALOGI("%s", clazz->descriptor);

        return 0;
    }

    /* clazz->super briefly holds the superclass index during class prep */
    if ((u4) clazz->super > 0x10000 && (u4) clazz->super != (u4) -1)
        super = clazz->super;
    else
        super = NULL;

    ALOGI("----- %s '%s' cl=%p ser=0x%08x -----",
          dvmIsInterfaceClass(clazz) ? "interface" : "class",
          clazz->descriptor, clazz->classLoader, clazz->serialNumber);
    ALOGI("  objectSize=%d (%d from super)", (int) clazz->objectSize,
          super != NULL ? (int) super->objectSize : -1);
    ALOGI("  access=0x%04x.%04x", clazz->accessFlags >> 16,
          clazz->accessFlags & JAVA_FLAGS_MASK);
    if (super != NULL)
        ALOGI("  super='%s' (cl=%p)", super->descriptor, super->classLoader);
    if (dvmIsArrayClass(clazz)) {
        ALOGI("  dimensions=%d elementClass=%s",
              clazz->arrayDim, clazz->elementClass->descriptor);
    }
    if (clazz->iftableCount > 0) {
        ALOGI("  interfaces (%d):", clazz->iftableCount);
        for (i = 0; i < clazz->iftableCount; i++) {
            InterfaceEntry *ent = &clazz->iftable[i];
            int j;

            ALOGI("    %2d: %s (cl=%p)",
                  i, ent->clazz->descriptor, ent->clazz->classLoader);

            /* enable when needed */
            if (false && ent->methodIndexArray != NULL) {
                for (j = 0; j < ent->clazz->virtualMethodCount; j++)
                    ALOGI("      %2d: %d %s %s",
                          j, ent->methodIndexArray[j],
                          ent->clazz->virtualMethods[j].name,
                          clazz->vtable[ent->methodIndexArray[j]]->name);
            }
        }
    }
    if (!dvmIsInterfaceClass(clazz)) {
        ALOGI("  vtable (%d entries, %d in super):", clazz->vtableCount,
              super != NULL ? super->vtableCount : 0);
        for (i = 0; i < clazz->vtableCount; i++) {
            desc = dexProtoCopyMethodDescriptor(&clazz->vtable[i]->prototype);
            ALOGI("    %s%2d: %p %20s %s",
                  (i != clazz->vtable[i]->methodIndex) ? "*** " : "",
                  (u4) clazz->vtable[i]->methodIndex, clazz->vtable[i],
                  clazz->vtable[i]->name, desc);
            free(desc);
        }
        ALOGI("  direct methods (%d entries):", clazz->directMethodCount);
        for (i = 0; i < clazz->directMethodCount; i++) {
            desc = dexProtoCopyMethodDescriptor(
                    &clazz->directMethods[i].prototype);
            ALOGI("    %2d: %20s %s", i, clazz->directMethods[i].name,
                  desc);
            free(desc);
        }
    } else {
        ALOGI("  interface methods (%d):", clazz->virtualMethodCount);
        for (i = 0; i < clazz->virtualMethodCount; i++) {
            desc = dexProtoCopyMethodDescriptor(
                    &clazz->virtualMethods[i].prototype);
            ALOGI("    %2d: %2d %20s %s", i,
                  (u4) clazz->virtualMethods[i].methodIndex,
                  clazz->virtualMethods[i].name,
                  desc);
            free(desc);
        }
    }
    if (clazz->sfieldCount > 0) {
        ALOGI("  static fields (%d entries):", clazz->sfieldCount);
        for (i = 0; i < clazz->sfieldCount; i++) {
            ALOGI("    %2d: %20s %s", i, clazz->sfields[i].name,
                  clazz->sfields[i].signature);
        }
    }
    if (clazz->ifieldCount > 0) {
        ALOGI("  instance fields (%d entries):", clazz->ifieldCount);
        for (i = 0; i < clazz->ifieldCount; i++) {
            ALOGI("    %2d: %20s %s", i, clazz->ifields[i].name,
                  clazz->ifields[i].signature);
        }
    }
    return 0;
}

/*
 * Dump the contents of a single class.
 *
 * Pass kDumpClassFullDetail into "flags" to get lots of detail.
 */
void dvmDumpClass(const ClassObject *clazz, int flags) {
    dumpClass((void *) clazz, (void *) flags);
}

/*
 * Dump the contents of all classes.
 */
void dvmDumpAllClasses(int flags) {
    dvmFunctionTables.dvmDumpAllClasses(flags);
}

/*
 * Get the number of loaded classes
 */
int dvmGetNumLoadedClasses() {
    return dvmFunctionTables.dvmGetNumLoadedClasses();
}

/*
 * Write some statistics to the log file.
 */
void dvmDumpLoaderStats(const char *msg) {
    dvmFunctionTables.dvmDumpLoaderStats(msg);
}

/*
 * ===========================================================================
 *      Method Prototypes and Descriptors
 * ===========================================================================
 */

/*
 * Compare the two method names and prototypes, a la strcmp(). The
 * name is considered the "major" order and the prototype the "minor"
 * order. The prototypes are compared as if by dvmCompareMethodProtos().
 */
int dvmCompareMethodNamesAndProtos(const Method *method1,
                                   const Method *method2) {
    int result = strcmp(method1->name, method2->name);

    if (result != 0) {
        return result;
    }

    return dvmCompareMethodProtos(method1, method2);
}

/*
 * Compare the two method names and prototypes, a la strcmp(), ignoring
 * the return value. The name is considered the "major" order and the
 * prototype the "minor" order. The prototypes are compared as if by
 * dvmCompareMethodArgProtos().
 */
int dvmCompareMethodNamesAndParameterProtos(const Method *method1,
                                            const Method *method2) {
    int result = strcmp(method1->name, method2->name);

    if (result != 0) {
        return result;
    }

    return dvmCompareMethodParameterProtos(method1, method2);
}

/*
 * Compare a (name, prototype) pair with the (name, prototype) of
 * a method, a la strcmp(). The name is considered the "major" order and
 * the prototype the "minor" order. The descriptor and prototype are
 * compared as if by dvmCompareDescriptorAndMethodProto().
 */
int dvmCompareNameProtoAndMethod(const char *name,
                                 const DexProto *proto, const Method *method) {
    int result = strcmp(name, method->name);

    if (result != 0) {
        return result;
    }

    return dexProtoCompare(proto, &method->prototype);
}

/*
 * Compare a (name, method descriptor) pair with the (name, prototype) of
 * a method, a la strcmp(). The name is considered the "major" order and
 * the prototype the "minor" order. The descriptor and prototype are
 * compared as if by dvmCompareDescriptorAndMethodProto().
 */
int dvmCompareNameDescriptorAndMethod(const char *name,
                                      const char *descriptor, const Method *method) {
    int result = strcmp(name, method->name);

    if (result != 0) {
        return result;
    }

    return dvmCompareDescriptorAndMethodProto(descriptor, method);
}
