//
// Created by 邓维佳 on 2018/5/28.
//

#ifndef XPOSEDDEMO_NATIVESTACKTRACE_H
#define XPOSEDDEMO_NATIVESTACKTRACE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <string>
#include <asm/mman.h>
#include <deque>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

////////////////////libcorkscrew.so////////////////////////////
/*
 * Describes a single frame of a backtrace.
 */
typedef struct {
    uintptr_t absolute_pc;     /* absolute PC offset */
    uintptr_t stack_top;       /* top of stack for this frame */
    size_t stack_size;         /* size of this stack frame */
} backtrace_frame_t;

/*
 * Describes the symbols associated with a backtrace frame.
 */
typedef struct {
    uintptr_t relative_pc;       /* relative frame PC offset from the start of the library,
                                    or the absolute PC if the library is unknown */
    uintptr_t relative_symbol_addr; /* relative offset of the symbol from the start of the
                                    library or 0 if the library is unknown */
    char *map_name;              /* executable or library name, or NULL if unknown */
    char *symbol_name;           /* symbol name, or NULL if unknown */
    char *demangled_name;        /* demangled symbol name, or NULL if unknown */
} backtrace_symbol_t;


////////////////////libbacktrace.so////////////////////////////

struct backtrace_map_t {
    uintptr_t start;
    uintptr_t end;
    int flags;
    std::string name;
};

class BacktraceMap {
public:
    // If uncached is true, then parse the current process map as of the call.
    // Passing a map created with uncached set to true to Backtrace::Create()
    // is unsupported.
    static BacktraceMap *Create(pid_t pid, bool uncached = false);

    virtual ~BacktraceMap();

    // Get the map data structure for the given address.
    virtual const backtrace_map_t *Find(uintptr_t addr);

    // The flags returned are the same flags as used by the mmap call.
    // The values are PROT_*.
    int GetFlags(uintptr_t pc) {
        const backtrace_map_t *map = Find(pc);
        if (map) {
            return map->flags;
        }
        return PROT_NONE;
    }

    bool IsReadable(uintptr_t pc) { return GetFlags(pc) & PROT_READ; }

    bool IsWritable(uintptr_t pc) { return GetFlags(pc) & PROT_WRITE; }

    bool IsExecutable(uintptr_t pc) { return GetFlags(pc) & PROT_EXEC; }

    typedef std::deque<backtrace_map_t>::iterator iterator;

    iterator begin() { return maps_.begin(); }

    iterator end() { return maps_.end(); }

    typedef std::deque<backtrace_map_t>::const_iterator const_iterator;

    const_iterator begin() const { return maps_.begin(); }

    const_iterator end() const { return maps_.end(); }

    virtual bool Build();

protected:
    BacktraceMap(pid_t pid);

    virtual bool ParseLine(const char *line, backtrace_map_t *map);

    std::deque<backtrace_map_t> maps_;
    pid_t pid_;
};

#if __LP64__
#define PRIPTR "016" PRIxPTR
typedef uint64_t word_t;
#else
#define PRIPTR "08" PRIxPTR
typedef uint32_t word_t;
#endif

struct backtrace_frame_data_t {
    size_t num;             // The current fame number.
    uintptr_t pc;           // The absolute pc.
    uintptr_t sp;           // The top of the stack.
    size_t stack_size;      // The size of the stack, zero indicate an unknown stack size.
    const backtrace_map_t *map;   // The map associated with the given pc.
    std::string func_name;  // The function name associated with this pc, NULL if not found.
    uintptr_t func_offset;  // pc relative to the start of the function, only valid if func_name is not NULL.
};

// Forward declarations.
class BacktraceImpl;

class Backtrace {
public:
    // Create the correct Backtrace object based on what is to be unwound.
    // If pid < 0 or equals the current pid, then the Backtrace object
    // corresponds to the current process.
    // If pid < 0 or equals the current pid and tid >= 0, then the Backtrace
    // object corresponds to a thread in the current process.
    // If pid >= 0 and tid < 0, then the Backtrace object corresponds to a
    // different process.
    // Tracing a thread in a different process is not supported.
    // If map is NULL, then create the map and manage it internally.
    // If map is not NULL, the map is still owned by the caller.
    static Backtrace *Create(pid_t pid, pid_t tid, BacktraceMap *map = NULL);

    virtual ~Backtrace();

    // Get the current stack trace and store in the backtrace_ structure.
    virtual bool Unwind(size_t num_ignore_frames, ucontext_t *context = NULL);

    // Get the function name and offset into the function given the pc.
    // If the string is empty, then no valid function name was found.
    virtual std::string GetFunctionName(uintptr_t pc, uintptr_t *offset);

    // Find the map associated with the given pc.
    virtual const backtrace_map_t *FindMap(uintptr_t pc);

    // Read the data at a specific address.
    virtual bool ReadWord(uintptr_t ptr, word_t *out_value) = 0;

    // Create a string representing the formatted line of backtrace information
    // for a single frame.
    virtual std::string FormatFrameData(size_t frame_num);

    virtual std::string FormatFrameData(const backtrace_frame_data_t *frame);

    pid_t Pid() { return pid_; }

    pid_t Tid() { return tid_; }

    size_t NumFrames() { return frames_.size(); }

    const backtrace_frame_data_t *GetFrame(size_t frame_num) {
        if (frame_num >= frames_.size()) {
            return NULL;
        }
        return &frames_[frame_num];
    }

    typedef std::vector<backtrace_frame_data_t>::iterator iterator;

    iterator begin() { return frames_.begin(); }

    iterator end() { return frames_.end(); }

    typedef std::vector<backtrace_frame_data_t>::const_iterator const_iterator;

    const_iterator begin() const { return frames_.begin(); }

    const_iterator end() const { return frames_.end(); }

    BacktraceMap *GetMap() { return map_; }

protected:
    Backtrace(BacktraceImpl *impl, pid_t pid, BacktraceMap *map);

    virtual bool VerifyReadWordArgs(uintptr_t ptr, word_t *out_value);

    bool BuildMap();

    pid_t pid_;
    pid_t tid_;

    BacktraceMap *map_;
    bool map_shared_;

    std::vector<backtrace_frame_data_t> frames_;

    BacktraceImpl *impl_;

    friend class BacktraceImpl;
};

class BacktraceImpl {
public:
    virtual ~BacktraceImpl() {}

    virtual bool Unwind(size_t num_ignore_frames, ucontext_t *ucontext) = 0;

    // The name returned is not demangled, Backtrace::GetFunctionName()
    // takes care of demangling the name.
    virtual std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t *offset) = 0;

    void SetParent(Backtrace *backtrace) { backtrace_obj_ = backtrace; }

    inline pid_t Pid() { return backtrace_obj_->Pid(); }

    inline pid_t Tid() { return backtrace_obj_->Tid(); }

    inline const backtrace_map_t *FindMap(uintptr_t addr) {
        return backtrace_obj_->FindMap(addr);
    }

    inline std::string GetFunctionName(uintptr_t pc, uintptr_t *offset) {
        return backtrace_obj_->GetFunctionName(pc, offset);
    }

    inline BacktraceMap *GetMap() { return backtrace_obj_->GetMap(); }

protected:
    inline std::vector<backtrace_frame_data_t> *GetFrames() { return &backtrace_obj_->frames_; }

    Backtrace *backtrace_obj_;
};
int printNativeStackTrace();
#ifdef __cplusplus
}

#endif


#endif //XPOSEDDEMO_NATIVESTACKTRACE_H
