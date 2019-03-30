// Created by 邓维佳 on 2018/5/28.
//
#include <sys/types.h>
#include <libdex/common.h>
#include <stdio.h>
#include <string>
#include "NativeStackTrace.h"
#include "inlinehook/dlopen.h"

#define MAX_DEPTH                       31
#define MAX_BACKTRACE_LINE_LENGTH   800

//native堆栈输出真实实现
static int (*realPrintFunction)() = NULL;

//在Android5.0以下，使用libcorkscrew.so实现
ssize_t (*unwindFn)(backtrace_frame_t *, size_t, size_t)=NULL;

void (*unwindSymbFn)(const backtrace_frame_t *, size_t, backtrace_symbol_t *)=NULL;

void (*unwindSymbFreeFn)(backtrace_symbol_t *, size_t)=NULL;


static int printNativeStackTraceWithLibcorkscrew() {
    ssize_t i = 0;
    ssize_t result = 0;
    ssize_t count;
    backtrace_frame_t mStack[MAX_DEPTH];
    backtrace_symbol_t symbols[MAX_DEPTH];

    count = unwindFn(mStack, 1, MAX_DEPTH);
    unwindSymbFn(mStack, count, symbols);

    for (i = 0; i < count; i++) {
        char line[MAX_BACKTRACE_LINE_LENGTH];

        const char *mapName = symbols[i].map_name ? symbols[i].map_name : "<unknown>";
        const char *symbolName = symbols[i].demangled_name ? symbols[i].demangled_name
                                                           : symbols[i].symbol_name;
        size_t fieldWidth = (MAX_BACKTRACE_LINE_LENGTH - 80) / 2;

        if (symbolName) {
            uint32_t pc_offset = symbols[i].relative_pc - symbols[i].relative_symbol_addr;
            if (pc_offset) {
                snprintf(line, MAX_BACKTRACE_LINE_LENGTH, "#%02d  pc %08x  %.*s (%.*s+%u)",
                         i, symbols[i].relative_pc, fieldWidth, mapName,
                         fieldWidth, symbolName, pc_offset);
            } else {
                snprintf(line, MAX_BACKTRACE_LINE_LENGTH, "#%02d  pc %08x  %.*s (%.*s)",
                         i, symbols[i].relative_pc, fieldWidth, mapName,
                         fieldWidth, symbolName);
            }
        } else {
            snprintf(line, MAX_BACKTRACE_LINE_LENGTH, "#%02d  pc %08x  %.*s",
                     i, symbols[i].relative_pc, fieldWidth, mapName);
        }
        ALOGE("%s", line);
    }
    unwindSymbFreeFn(symbols, count);
    return result;
}

static bool resolvePrintStackFunctionWithLibcorkscrew() {
    void *gHandle = NULL;
    gHandle = dlopen("/system/lib/libcorkscrew.so", RTLD_NOW);
    if (gHandle == NULL) {
        return false;
    }
    unwindFn = (ssize_t (*)(backtrace_frame_t *, size_t, size_t)) dlsym(gHandle,
                                                                        "unwind_backtrace");
    unwindSymbFn = (void (*)(const backtrace_frame_t *, size_t, backtrace_symbol_t *)) dlsym(
            gHandle,
            "get_backtrace_symbols");

    unwindSymbFreeFn = (void (*)(backtrace_symbol_t *, size_t)) dlsym(gHandle,
                                                                      "free_backtrace_symbols");
    //dlclose(gHandle);
    if (unwindFn == NULL || unwindSymbFn == NULL || unwindSymbFreeFn == NULL) {
        return false;
    }
    realPrintFunction = printNativeStackTraceWithLibcorkscrew;
    return true;
}


Backtrace *(*createBacktraceMap)(int, int, void *)=NULL;

static int printStackFunctionWithLibbacktrace() {
    Backtrace *t = createBacktraceMap(-1, -1, NULL);
    if (!t) {
        return -1;
    }
    int ret = t->Unwind(0);
    if (!ret) {
        return -1;
    }
    size_t count = t->NumFrames();
    ALOGE("Backtrace:\n");
    for (size_t i = 0; i < count; i++) {
        std::string line = t->FormatFrameData(i);
        ALOGE("%s\n", line.c_str());
    }
    return 0;
}

static bool resolvePrintStackFunctionWithLibbacktrace() {
    void *libbacktrace = dlopen("/system/lib/libbacktrace.so", RTLD_LOCAL);
    if (!libbacktrace) {
        return false;
    }
    createBacktraceMap = (Backtrace *(*)(int, int, void *)) dlsym(libbacktrace,
                                                                  "_ZN9Backtrace6CreateEiiP12BacktraceMap");
    // dlclose(libbacktrace);
    realPrintFunction = printStackFunctionWithLibbacktrace;
    return createBacktraceMap != NULL;
}


static int defaultPrintFunction() {
    ALOGE("do not find native stack trace print function!!");
    return -1;
}


int printNativeStackTrace() {
    if (realPrintFunction != NULL) {
        return realPrintFunction();
    }
    if (resolvePrintStackFunctionWithLibcorkscrew()) {
        return realPrintFunction();
    }
    if (resolvePrintStackFunctionWithLibbacktrace()) {
        return realPrintFunction();
    }
    realPrintFunction = defaultPrintFunction;
    return realPrintFunction();
}


