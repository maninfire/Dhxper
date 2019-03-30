cmake_minimum_required(VERSION 3.4.1)
message("Building ucrackNative for Android(${CMAKE_SYSTEM_PROCESSOR})...")

set(UCRACK_SOURCE
        src/unpack/init.cpp
        src/unpack/NativeStackTrace.cpp
        src/unpack/shell_version1.cpp
        src/unpack/shell_version3.cpp
        src/unpack/socrack.cpp
        )

set(INLINE_HOOK_SOURCE
        src/inlinehook/dlopen.c
        src/inlinehook/inlineHook.c
        src/inlinehook/relocate.c
        )

set(LIB_DEX_SOURCE
        src/libdex/CmdUtils.cpp
        src/libdex/DexCatch.cpp
        src/libdex/DexClass.cpp
        src/libdex/DexDataMap.cpp
        src/libdex/DexDebugInfo.cpp
        src/libdex/DexFile.cpp
        src/libdex/DexInlines.cpp
        src/libdex/DexOptData.cpp
        src/libdex/DexOpcodes.cpp
        src/libdex/DexProto.cpp
        src/libdex/DexSwapVerify.cpp
        src/libdex/DexUtf.cpp
        src/libdex/InstrUtils.cpp
        src/libdex/Leb128.cpp
        src/libdex/OptInvocation.cpp
        src/libdex/sha1.cpp
        src/libdex/SysUtil.cpp
        src/libdex/ZipArchive.cpp
        src/libdex/safe_iop.c
        )

set(LIB_DVM_OO_SOURCE
        src/oo/AccessCheck.cpp
        src/oo/Array.cpp
        src/oo/Class.cpp
        src/oo/Object.cpp
        src/oo/Resolve.cpp
        src/oo/TypeCheck.cpp
        )

set(LIB_VM
        src/vm/Hash.cpp
        )

set(ZLIB_SOURCE
        src/zlib/adler32.c
        src/zlib/compress.c
        src/zlib/crc32.c
        src/zlib/deflate.c
        src/zlib/gzclose.c
        src/zlib/gzlib.c
        src/zlib/gzread.c
        src/zlib/gzwrite.c
        src/zlib/infback.c
        src/zlib/inflate.c
        src/zlib/inftrees.c
        src/zlib/inffast.c
        src/zlib/trees.c
        src/zlib/uncompr.c
        src/zlib/zutil.c
        )

set(UCRACK_SOURCE ${LIB_VM} ${UCRACK_SOURCE} ${LIB_DEX_SOURCE} ${LIB_DVM_OO_SOURCE} ${ZLIB_SOURCE}
        ${INLINE_HOOK_SOURCE} )

set(LIBRARY_NAME "unshellnative")

include_directories(src)
include_directories(src/include)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -funwind-tables -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -funwind-tables -g")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s -Wl,--gc-sections")

add_library(${LIBRARY_NAME} SHARED ${UCRACK_SOURCE})


target_link_libraries(${LIBRARY_NAME} log)
