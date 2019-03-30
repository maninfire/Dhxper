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
 * Helper functions to access data fields in Objects.
 */
#ifndef DALVIK_OO_OBJECTINLINES_H_
#define DALVIK_OO_OBJECTINLINES_H_

#include "Inlines.h"
#include "Object.h"
#include "DvmFunctionTable.h"

/*
 * Store a single value in the array, and if the value isn't null,
 * note in the write barrier.
 */
INLINE void dvmSetObjectArrayElement(const ArrayObject *obj, int index,
                                     Object *val) {
    dvmFunctionTables.dvmSetObjectArrayElement(obj, index, val);
}


/*
 * Field access functions.  Pass in the word offset from Field->byteOffset.
 *
 * We guarantee that long/double field data is 64-bit aligned, so it's safe
 * to access them with ldrd/strd on ARM.
 *
 * The VM treats all fields as 32 or 64 bits, so the field set functions
 * write 32 bits even if the underlying type is smaller.
 *
 * Setting Object types to non-null values includes a call to the
 * write barrier.
 */
#define BYTE_OFFSET(_ptr, _offset)  ((void*) (((u1*)(_ptr)) + (_offset)))

INLINE JValue *dvmFieldPtr(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset));
}

INLINE bool dvmGetFieldBoolean(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->z;
}

INLINE s1 dvmGetFieldByte(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->b;
}

INLINE s2 dvmGetFieldShort(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->s;
}

INLINE u2 dvmGetFieldChar(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->c;
}

INLINE s4 dvmGetFieldInt(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->i;
}

INLINE s8 dvmGetFieldLong(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->j;
}

INLINE float dvmGetFieldFloat(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->f;
}

INLINE double dvmGetFieldDouble(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->d;
}

INLINE Object *dvmGetFieldObject(const Object *obj, int offset) {
    return ((JValue *) BYTE_OFFSET(obj, offset))->l;
}


INLINE void dvmSetFieldBoolean(Object *obj, int offset, bool val) {
    ((JValue *) BYTE_OFFSET(obj, offset))->i = val;
}

INLINE void dvmSetFieldByte(Object *obj, int offset, s1 val) {
    ((JValue *) BYTE_OFFSET(obj, offset))->i = val;
}

INLINE void dvmSetFieldShort(Object *obj, int offset, s2 val) {
    ((JValue *) BYTE_OFFSET(obj, offset))->i = val;
}

INLINE void dvmSetFieldChar(Object *obj, int offset, u2 val) {
    ((JValue *) BYTE_OFFSET(obj, offset))->i = val;
}

INLINE void dvmSetFieldInt(Object *obj, int offset, s4 val) {
    ((JValue *) BYTE_OFFSET(obj, offset))->i = val;
}

INLINE void dvmSetFieldFloat(Object *obj, int offset, float val) {
    ((JValue *) BYTE_OFFSET(obj, offset))->f = val;
}

INLINE void dvmSetFieldLong(Object *obj, int offset, s8 val) {
    ((JValue *) BYTE_OFFSET(obj, offset))->j = val;
}

INLINE void dvmSetFieldDouble(Object *obj, int offset, double val) {
    ((JValue *) BYTE_OFFSET(obj, offset))->d = val;
}


/*
 * Static field access functions.
 */
INLINE JValue *dvmStaticFieldPtr(const StaticField *sfield) {
    return (JValue *) &sfield->value;
}

INLINE bool dvmGetStaticFieldBoolean(const StaticField *sfield) {
    return sfield->value.z;
}

INLINE s1 dvmGetStaticFieldByte(const StaticField *sfield) {
    return sfield->value.b;
}

INLINE s2 dvmGetStaticFieldShort(const StaticField *sfield) {
    return sfield->value.s;
}

INLINE u2 dvmGetStaticFieldChar(const StaticField *sfield) {
    return sfield->value.c;
}

INLINE s4 dvmGetStaticFieldInt(const StaticField *sfield) {
    return sfield->value.i;
}

INLINE float dvmGetStaticFieldFloat(const StaticField *sfield) {
    return sfield->value.f;
}

INLINE s8 dvmGetStaticFieldLong(const StaticField *sfield) {
    return sfield->value.j;
}

INLINE double dvmGetStaticFieldDouble(const StaticField *sfield) {
    return sfield->value.d;
}


#endif  // DALVIK_OO_OBJECTINLINES_H_
