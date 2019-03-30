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
 * Array objects.
 */


#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <string>
#include "DvmFunctionTable.h"
#include "Object.h"
#include "ObjectInlines.h"
#include "Class.h"
#include "TypeCheck.h"
#include "Array.h"

/* width of an object reference, for arrays of objects */
static size_t kObjectArrayRefWidth = sizeof(Object *);

static ClassObject *createArrayClass(const char *descriptor, Object *loader);

/*
 * Allocate space for a new array object.  This is the lowest-level array
 * allocation function.
 *
 * Pass in the array class and the width of each element.
 *
 * On failure, returns NULL with an exception raised.
 */
static ArrayObject *allocArray(ClassObject *arrayClass, size_t length,
                               size_t elemWidth, int allocFlags) {
    return dvmFunctionTables.allocArray(arrayClass, length, elemWidth, allocFlags);
}

/*
 * Create a new array, given an array class.  The class may represent an
 * array of references or primitives.
 */
ArrayObject *dvmAllocArrayByClass(ClassObject *arrayClass,
                                  size_t length, int allocFlags) {
    const char *descriptor = arrayClass->descriptor;

    assert(descriptor[0] == '[');       /* must be array class */
    if (descriptor[1] != '[' && descriptor[1] != 'L') {
        /* primitive array */
        assert(descriptor[2] == '\0');
        return dvmAllocPrimitiveArray(descriptor[1], length, allocFlags);
    } else {
        return allocArray(arrayClass, length, kObjectArrayRefWidth,
                          allocFlags);
    }
}

/*
 * Find the array class for "elemClassObj", which could itself be an
 * array class.
 */
ClassObject *dvmFindArrayClassForElement(ClassObject *elemClassObj) {
    ClassObject *arrayClass;

    assert(elemClassObj != NULL);

    /* Simply prepend "[" to the descriptor. */
    int nameLen = strlen(elemClassObj->descriptor);
    char className[nameLen + 2];

    className[0] = '[';
    memcpy(className + 1, elemClassObj->descriptor, nameLen + 1);
    arrayClass = dvmFindArrayClass(className, elemClassObj->classLoader);

    return arrayClass;
}

/*
 * Create a new array that holds primitive types.
 *
 * "type" is the primitive type letter, e.g. 'I' for int or 'J' for long.
 */
ArrayObject *dvmAllocPrimitiveArray(char type, size_t length, int allocFlags) {
    return dvmFunctionTables.dvmAllocPrimitiveArray(type, length, allocFlags);
}

/*
 * Recursively create an array with multiple dimensions.  Elements may be
 * Objects or primitive types.
 *
 * The dimension we're creating is in dimensions[0], so when we recurse
 * we advance the pointer.
 */
ArrayObject *dvmAllocMultiArray(ClassObject *arrayClass, int curDim,
                                const int *dimensions) {
    return dvmFunctionTables.dvmAllocMultiArray(arrayClass, curDim, dimensions);
}


/*
 * Find an array class, by name (e.g. "[I").
 *
 * If the array class doesn't exist, we generate it.
 *
 * If the element class doesn't exist, we return NULL (no exception raised).
 */
ClassObject *dvmFindArrayClass(const char *descriptor, Object *loader) {
    ClassObject *clazz;

    assert(descriptor[0] == '[');
    //ALOGV("dvmFindArrayClass: '%s' %p", descriptor, loader);

    clazz = dvmLookupClass(descriptor, loader, false);
    if (clazz == NULL) {
        ALOGV("Array class '%s' %p not found; creating", descriptor, loader);
        clazz = createArrayClass(descriptor, loader);
        if (clazz != NULL)
            dvmAddInitiatingLoader(clazz, loader);
    }

    return clazz;
}

/*
 * Create an array class (i.e. the class object for the array, not the
 * array itself).  "descriptor" looks like "[C" or "[Ljava/lang/String;".
 *
 * If "descriptor" refers to an array of primitives, look up the
 * primitive type's internally-generated class object.
 *
 * "loader" is the class loader of the class that's referring to us.  It's
 * used to ensure that we're looking for the element type in the right
 * context.  It does NOT become the class loader for the array class; that
 * always comes from the base element class.
 *
 * Returns NULL with an exception raised on failure.
 */
static ClassObject *createArrayClass(const char *descriptor, Object *loader) {
    return dvmFunctionTables.createArrayClass(descriptor, loader);
}

/*
 * Copy the entire contents of one array of objects to another.  If the copy
 * is impossible because of a type clash, we fail and return "false".
 */
bool dvmCopyObjectArray(ArrayObject *dstArray, const ArrayObject *srcArray,
                        ClassObject *dstElemClass) {
    Object **src = (Object **) (void *) srcArray->contents;
    u4 length, count;

    assert(srcArray->length == dstArray->length);
    assert(dstArray->clazz->elementClass == dstElemClass ||
           (dstArray->clazz->elementClass == dstElemClass->elementClass &&
            dstArray->clazz->arrayDim == dstElemClass->arrayDim + 1));

    length = dstArray->length;
    for (count = 0; count < length; count++) {
        if (!dvmInstanceof(src[count]->clazz, dstElemClass)) {
            ALOGW("dvmCopyObjectArray: can't store %s in %s",
                  src[count]->clazz->descriptor, dstElemClass->descriptor);
            return false;
        }
        dvmSetObjectArrayElement(dstArray, count, src[count]);
    }

    return true;
}

/*
 * Copy the entire contents of an array of boxed primitives into an
 * array of primitives.  The boxed value must fit in the primitive (i.e.
 * narrowing conversions are not allowed).
 */
bool dvmUnboxObjectArray(ArrayObject *dstArray, const ArrayObject *srcArray,
                         ClassObject *dstElemClass) {
    return dvmFunctionTables.dvmUnboxObjectArray(dstArray, srcArray, dstElemClass);
}

/*
 * Returns the width, in bytes, required by elements in instances of
 * the array class.
 */
size_t dvmArrayClassElementWidth(const ClassObject *arrayClass) {
    return dvmFunctionTables.dvmArrayClassElementWidth(arrayClass);
}

