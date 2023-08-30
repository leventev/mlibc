#pragma once

#include <sys/types.h>
#include <stdint.h>

#define cast(x) ((uint64_t) (x))

static inline uint64_t __syscall0(uint64_t no) {
    uint64_t ret;
    asm volatile("int $0x80" : "=a" (ret) : "a" (no) : "memory");
    return ret;
}

static inline uint64_t __syscall1(uint64_t no, uint64_t arg1) {
    uint64_t ret;
    asm volatile("int $0x80" : "=a" (ret) : "a" (no), "D" (arg1) : "memory");
    return ret;
}

static inline uint64_t __syscall2(uint64_t no, uint64_t arg1, uint64_t arg2) {
    uint64_t ret;
    asm volatile("int $0x80" : "=a" (ret) : "a" (no), "D" (arg1), "S" (arg2) : "memory");
    return ret;
}

static inline uint64_t __syscall3(uint64_t no, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    uint64_t ret;
    asm volatile("int $0x80" : "=a" (ret) : "a" (no), "D" (arg1), "S" (arg2), "d" (arg3) : "memory");
    return ret;
}

static inline uint64_t __syscall4(uint64_t no, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    uint64_t ret;
    register uint64_t r10 asm("r10") = arg4;
    asm volatile("int $0x80" : "=a" (ret) : "a" (no), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10) : "memory");
    return ret;
}

static inline uint64_t __syscall5(uint64_t no, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    uint64_t ret;
    register uint64_t r10 asm("r10") = arg4;
    register uint64_t r8 asm("r8") = arg5;
    asm volatile("int $0x80" : "=a" (ret) : "a" (no), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10), "r" (r8) : "memory");
    return ret;
}

static inline uint64_t __syscall6(uint64_t no, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    uint64_t ret;
    register uint64_t r10 asm("r10") = arg4;
    register uint64_t r8 asm("r8") = arg5;
    register uint64_t r9 asm("r9") = arg6;
    asm volatile("int $0x80" : "=a" (ret) : "a" (no), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10), "r" (r8), "r" (r9) : "memory");
    return ret;
}

#define syscall0(n) __syscall0(cast(n))
#define syscall1(n, a1) __syscall1(cast(n), cast(a1))
#define syscall2(n, a1, a2) __syscall2(cast(n), cast(a1), cast(a2))
#define syscall3(n, a1, a2, a3) __syscall3(cast(n), cast(a1), cast(a2), cast(a3))
#define syscall4(n, a1, a2, a3, a4) __syscall4(cast(n), cast(a1), cast(a2), cast(a3), cast(a4))
#define syscall5(n, a1, a2, a3, a4, a5) __syscall5(cast(n), cast(a1), cast(a2), cast(a3), cast(a4), cast(a5))
#define syscall6(n, a1, a2, a3, a4, a5, a6) __syscall6(cast(n), cast(a1), cast(a2), cast(a3), cast(a4), cast(a5), cast(a6))
