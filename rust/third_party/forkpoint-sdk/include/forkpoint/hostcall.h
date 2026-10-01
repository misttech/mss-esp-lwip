/* Copyright 2026 Mist Tecnologia LTDA. All rights reserved. */

/* Report a probe to the Forkpoint host through the hostcall device.
 *
 * The hostcall device is a memory-mapped window that exists only in the Forkpoint virtual
 * machine. A board's Device Tree places it (compatible "forkpoint,hostcall"), and the build
 * passes the same address as FPT_HOSTCALL_BASE. A call is five aligned 32-bit stores. The last
 * one reports the probe, and the host sees it at exactly that instruction. The stores share
 * one staging area in the device, so fpt_probe masks interrupts around them: a handler that
 * probes while thread code is part-way through its own call cannot mix the two. Cortex-M masks
 * with PRIMASK. RISC-V clears mstatus.MIE and restores only that bit, which needs the
 * Zicsr extension in the translation unit. It works from thread or handler mode, with
 * interrupts already masked, and inside critical sections. It cannot mask
 * an exception those bits do not block (NMI, HardFault, or a RISC-V exception), so those
 * contexts must not probe. It uses no heap, no OS, and no exception or interrupt vector, and
 * it never stops the firmware.
 *
 * The device defines only 32-bit accesses. An 8-bit architecture such as AVR splits a uint32_t
 * store into byte stores, so this header rejects it. A narrower or unaligned access, one past
 * the last register, or a write to a read-only register fails the run as an illegal MMIO
 * access.
 *
 * Every call compiles to nothing unless FPT_ENABLE is defined, so a production build never
 * touches the window: on real silicon it is unmapped memory.
 *
 * Property macros (FPT_ALWAYS, FPT_SOMETIMES, FPT_REACHABLE, FPT_UNREACHABLE,
 * FPT_ALWAYS_OR_UNREACHABLE) report a probe and keep running. The probe id is the FNV-1a 64-bit
 * hash of the message, the same hash sdk/rust/forkpoint uses, so the id does not depend on
 * where the compiler placed the string. The value is 1 when the condition holds and 0 when it
 * does not. Without FPT_ENABLE the macros do not evaluate their condition. The numeric forms
 * (FPT_ALWAYS_LESS_THAN and the rest of the eight) compare their operands as int64_t and add a
 * guidance probe with left - right; FPT_SOMETIMES_ALL and FPT_ALWAYS_SOME take propositions and
 * add a guidance probe with which held; FPT_DETAILS reports a value for an assertion.
 *
 * fpt_get_random returns a value from the machine's seeded source (layout version 2): the run's
 * --seed decides it and a replay draws it again. Without a version 2 device, or without
 * FPT_ENABLE, it falls back to a deterministic xorshift generator, one per translation unit,
 * since bare metal has no universal entropy source.
 *
 * The register layout is documented in src/dvmc/devices/src/hostcall.rs. */

#ifndef FORKPOINT_HOSTCALL_H
#define FORKPOINT_HOSTCALL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FPT_HOSTCALL_MAGIC 0x43485046u /* "FPHC" in memory order */
/* The layout this header knows. Version 1 has the probe registers; version 2 adds RANDOM. */
#define FPT_HOSTCALL_VERSION 2u

/* Property probe kinds. Firmware that picks its own kinds should stay below this range.
 * The explorer records these probes; it does not steer on them yet. */
#define FPT_KIND_ALWAYS 0x46505401u
#define FPT_KIND_SOMETIMES 0x46505402u
#define FPT_KIND_UNREACHABLE 0x46505403u
#define FPT_KIND_REACHABLE 0x46505404u

/* Lifecycle probe kinds: fpt_setup_complete and fpt_send_event. */
#define FPT_KIND_SETUP_COMPLETE 0x46505408u
#define FPT_KIND_EVENT 0x46505409u

/* Guidance and details probe kinds, reported after an assertion's own probe with its id: a
 * numeric assertion's left - right (an int64_t's bits, saturated), which propositions of a
 * named assertion held (the first in bit 0), and FPT_DETAILS's value. */
#define FPT_KIND_GUIDANCE_NUMERIC 0x46505405u
#define FPT_KIND_GUIDANCE_BOOLEAN 0x46505406u
#define FPT_KIND_DETAILS 0x46505407u

/* The fallback generator: xorshift64*, deterministic, one state per translation unit. */
static inline uint64_t fpt_fallback_random(void) {
  static uint64_t state = 0x9e3779b97f4a7c15ull;
  state ^= state >> 12;
  state ^= state << 25;
  state ^= state >> 27;
  return state * 0x2545f4914f6cdd1dull;
}

#ifdef FPT_ENABLE

#ifndef FPT_HOSTCALL_BASE
#error "FPT_ENABLE needs FPT_HOSTCALL_BASE, the hostcall device's address in the Device Tree"
#endif

#if defined(__riscv)
#define FPT_HOSTCALL_ARCH_RISCV 1
#elif defined(__ARM_ARCH_PROFILE) && __ARM_ARCH_PROFILE == 'M'
#define FPT_HOSTCALL_ARCH_ARM_M 1
#else
#error "the hostcall SDK supports Cortex-M and RISC-V: it needs 32-bit stores and an interrupt mask"
#endif

#define FPT_HOSTCALL_REG(offset) (*(volatile uint32_t *)(uintptr_t)(FPT_HOSTCALL_BASE + (offset)))

#if defined(FPT_HOSTCALL_ARCH_RISCV)
/* Clear mstatus.MIE and return the previous mstatus, for fpt_hostcall_unmask. */
static inline uint32_t fpt_hostcall_mask(void) {
  uint32_t mstatus;
  __asm__ volatile("csrrci %0, mstatus, 8" : "=r"(mstatus)::"memory");
  return mstatus;
}

static inline void fpt_hostcall_unmask(uint32_t mstatus) {
  uint32_t mie = mstatus & 8u;
  __asm__ volatile("csrs mstatus, %0" ::"r"(mie) : "memory");
}
#else
/* Mask interrupts and return the previous PRIMASK, for fpt_hostcall_unmask. */
static inline uint32_t fpt_hostcall_mask(void) {
  uint32_t primask;
  __asm__ volatile("mrs %0, primask\n\tcpsid i" : "=r"(primask)::"memory");
  return primask;
}

static inline void fpt_hostcall_unmask(uint32_t primask) {
  __asm__ volatile("msr primask, %0" ::"r"(primask) : "memory");
}
#endif

/* The layout version of the hostcall device at FPT_HOSTCALL_BASE, or 0 when none answers. */
static inline uint32_t fpt_hostcall_version(void) {
  return FPT_HOSTCALL_REG(0x00u) == FPT_HOSTCALL_MAGIC ? FPT_HOSTCALL_REG(0x04u) : 0u;
}

/* Whether the hostcall device answers at FPT_HOSTCALL_BASE with probe registers: layout
 * version 1 or later, whose registers are those of version 1 plus more. */
static inline int fpt_hostcall_present(void) { return fpt_hostcall_version() >= 1u; }

/* A value from the machine's seeded source: a write to RANDOM draws it, and RANDOM_LO and
 * RANDOM_HI hold it. Without a version 2 device, the fallback generator. */
static inline uint64_t fpt_get_random(void) {
  if (fpt_hostcall_version() < 2u) {
    return fpt_fallback_random();
  }
  uint32_t mask = fpt_hostcall_mask();
  FPT_HOSTCALL_REG(0x1Cu) = 0u;
  uint64_t value = (uint64_t)FPT_HOSTCALL_REG(0x24u) << 32 | FPT_HOSTCALL_REG(0x20u);
  fpt_hostcall_unmask(mask);
  return value;
}

/* Report probe `id` with `value`. The host records it in the trace, and `fpt explore
 * --stop-at-probe ID` stops right after the call. What `kind` means is agreed between the
 * firmware and whatever reads the trace. */
static inline void fpt_probe(uint32_t kind, uint64_t id, uint64_t value) {
  uint32_t mask = fpt_hostcall_mask();
  FPT_HOSTCALL_REG(0x08u) = (uint32_t)id;
  FPT_HOSTCALL_REG(0x0Cu) = (uint32_t)(id >> 32);
  FPT_HOSTCALL_REG(0x10u) = (uint32_t)value;
  FPT_HOSTCALL_REG(0x14u) = (uint32_t)(value >> 32);
  FPT_HOSTCALL_REG(0x18u) = kind;
  fpt_hostcall_unmask(mask);
}

/* Setup is over: what runs from here is what is worth exploring. `fpt explore
 * --fork-after-setup` runs to the first call and forks from that state. Only the first call
 * counts. */
static inline void fpt_setup_complete(uint64_t details) {
  fpt_probe(FPT_KIND_SETUP_COMPLETE, 0, details);
}

/* FNV-1a 64 of `message`. The Rust SDK's `message_id` computes the same value. The hash is
 * kept as two 32-bit words, so it needs no 64-bit multiply, which a freestanding Cortex-M0+
 * build has no runtime helper for. The prime is 2^40 + 0x1b3: the hash times 0x1b3, from 16-bit
 * partial products that fit in 32 bits, plus the low word shifted into the high word. */
static inline uint64_t fpt_message_id(const char *message) {
  uint32_t lo = 0x84222325u;
  uint32_t hi = 0xcbf29ce4u;
  const unsigned char *byte = (const unsigned char *)message;
  while (*byte != 0u) {
    lo ^= *byte++;
    uint32_t low_half = (lo & 0xFFFFu) * 0x1B3u;
    uint32_t high_half = (lo >> 16) * 0x1B3u;
    uint32_t product = low_half + (high_half << 16);
    hi = (high_half >> 16) + (product < low_half) + hi * 0x1B3u + (lo << 8);
    lo = product;
  }
  return (uint64_t)hi << 32 | lo;
}

/* Something happened that a reader of the trace should see, named by `name` (its FNV-1a hash is
 * the probe id) with `details`. */
static inline void fpt_send_event(const char *name, uint64_t details) {
  fpt_probe(FPT_KIND_EVENT, fpt_message_id(name), details);
}

/* The assertion catalog: each property macro also leaves a record in the image's .fpt_catalog
 * section, in the layout sdk/rust/forkpoint/src/catalog.rs documents, so the host knows every
 * assertion before a run, the ones no run reaches included. A C record carries no id (0): C
 * cannot hash a string at compile time, so the host derives it from the message, the FNV-1a hash
 * the probe carries. C has no column (0) and no module path (empty). The message must be a string
 * literal. A firmware linker script keeps the section out of target memory:
 *
 *   .fpt_catalog (INFO) : { KEEP(*(.fpt_catalog)) }
 *
 * C++ cannot initialize an array with a string that leaves out its terminator, so a C++
 * translation unit writes no records. */
#define FPT_CATALOG_ALWAYS 0u
#define FPT_CATALOG_ALWAYS_OR_UNREACHABLE 1u
#define FPT_CATALOG_SOMETIMES 2u
#define FPT_CATALOG_REACHABLE 3u
#define FPT_CATALOG_UNREACHABLE 4u

#ifdef __cplusplus
#define FPT_CATALOG_RECORD(fpt_kind, fpt_message)
#else
#define FPT_CATALOG_RECORD(fpt_kind, fpt_message)                                                  \
  static const struct {                                                                            \
    char magic[4];                                                                                 \
    uint32_t len;                                                                                  \
    uint8_t kind, zero[3];                                                                         \
    uint32_t id_lo, id_hi, line, column;                                                           \
    uint16_t file_len, module_len, message_len, zero16;                                            \
    char file[sizeof(__FILE__) - 1] __attribute__((nonstring));                                    \
    char text[sizeof("" fpt_message "") - 1] __attribute__((nonstring));                           \
  } fpt_catalog_record                                                                             \
      __attribute__((section(".fpt_catalog"), used, aligned(4))) = {{'F', 'P', 'T', 'A'},          \
                                                                    sizeof fpt_catalog_record,     \
                                                                    (fpt_kind),                    \
                                                                    {0u, 0u, 0u},                  \
                                                                    0u,                            \
                                                                    0u,                            \
                                                                    __LINE__,                      \
                                                                    0u,                            \
                                                                    sizeof(__FILE__) - 1,          \
                                                                    0u,                            \
                                                                    sizeof("" fpt_message "") - 1, \
                                                                    0u,                            \
                                                                    __FILE__,                      \
                                                                    fpt_message}
#endif

#define FPT_ALWAYS(condition, message)                                                    \
  do {                                                                                    \
    FPT_CATALOG_RECORD(FPT_CATALOG_ALWAYS, message);                                      \
    fpt_probe(FPT_KIND_ALWAYS, fpt_message_id(message), (uint64_t)((condition) ? 1 : 0)); \
  } while (0)

#define FPT_SOMETIMES(condition, message)                                                    \
  do {                                                                                       \
    FPT_CATALOG_RECORD(FPT_CATALOG_SOMETIMES, message);                                      \
    fpt_probe(FPT_KIND_SOMETIMES, fpt_message_id(message), (uint64_t)((condition) ? 1 : 0)); \
  } while (0)

#define FPT_REACHABLE(message)                                 \
  do {                                                         \
    FPT_CATALOG_RECORD(FPT_CATALOG_REACHABLE, message);        \
    fpt_probe(FPT_KIND_REACHABLE, fpt_message_id(message), 1); \
  } while (0)

#define FPT_UNREACHABLE(message)                                 \
  do {                                                           \
    FPT_CATALOG_RECORD(FPT_CATALOG_UNREACHABLE, message);        \
    fpt_probe(FPT_KIND_UNREACHABLE, fpt_message_id(message), 1); \
  } while (0)

#define FPT_ALWAYS_OR_UNREACHABLE(condition, message)               \
  do {                                                              \
    FPT_CATALOG_RECORD(FPT_CATALOG_ALWAYS_OR_UNREACHABLE, message); \
    if (condition) {                                                \
      fpt_probe(FPT_KIND_ALWAYS, fpt_message_id(message), 1);       \
    } else {                                                        \
      fpt_probe(FPT_KIND_UNREACHABLE, fpt_message_id(message), 0);  \
    }                                                               \
  } while (0)

/* left - right, saturated to an int64_t, without overflow. */
static inline int64_t fpt_saturating_difference(int64_t left, int64_t right) {
  if (right > 0 && left < INT64_MIN + right) {
    return INT64_MIN;
  }
  if (right < 0 && left > INT64_MAX + right) {
    return INT64_MAX;
  }
  return left - right;
}

/* Report a numeric assertion: whether `left op right` held under `probe_kind`, then
 * left - right as guidance. Each operand is converted to int64_t and evaluated once. */
#define FPT_NUMERIC(catalog_kind, probe_kind, op, left, right, message)  \
  do {                                                                   \
    FPT_CATALOG_RECORD(catalog_kind, message);                           \
    int64_t fpt_left = (int64_t)(left);                                  \
    int64_t fpt_right = (int64_t)(right);                                \
    uint64_t fpt_id = fpt_message_id(message);                           \
    fpt_probe(probe_kind, fpt_id, fpt_left op fpt_right ? 1u : 0u);      \
    fpt_probe(FPT_KIND_GUIDANCE_NUMERIC, fpt_id,                         \
              (uint64_t)fpt_saturating_difference(fpt_left, fpt_right)); \
  } while (0)

#define FPT_ALWAYS_GREATER_THAN(left, right, message) \
  FPT_NUMERIC(FPT_CATALOG_ALWAYS, FPT_KIND_ALWAYS, >, left, right, message)
#define FPT_ALWAYS_GREATER_THAN_OR_EQUAL_TO(left, right, message) \
  FPT_NUMERIC(FPT_CATALOG_ALWAYS, FPT_KIND_ALWAYS, >=, left, right, message)
#define FPT_ALWAYS_LESS_THAN(left, right, message) \
  FPT_NUMERIC(FPT_CATALOG_ALWAYS, FPT_KIND_ALWAYS, <, left, right, message)
#define FPT_ALWAYS_LESS_THAN_OR_EQUAL_TO(left, right, message) \
  FPT_NUMERIC(FPT_CATALOG_ALWAYS, FPT_KIND_ALWAYS, <=, left, right, message)
#define FPT_SOMETIMES_GREATER_THAN(left, right, message) \
  FPT_NUMERIC(FPT_CATALOG_SOMETIMES, FPT_KIND_SOMETIMES, >, left, right, message)
#define FPT_SOMETIMES_GREATER_THAN_OR_EQUAL_TO(left, right, message) \
  FPT_NUMERIC(FPT_CATALOG_SOMETIMES, FPT_KIND_SOMETIMES, >=, left, right, message)
#define FPT_SOMETIMES_LESS_THAN(left, right, message) \
  FPT_NUMERIC(FPT_CATALOG_SOMETIMES, FPT_KIND_SOMETIMES, <, left, right, message)
#define FPT_SOMETIMES_LESS_THAN_OR_EQUAL_TO(left, right, message) \
  FPT_NUMERIC(FPT_CATALOG_SOMETIMES, FPT_KIND_SOMETIMES, <=, left, right, message)

/* Report a named assertion over the propositions after `message`, each evaluated once: whether
 * all held (`need_all`) or any did, under `probe_kind`, then which held as guidance. The mask
 * is built in two 32-bit words, so no 64-bit shift needs a runtime helper. */
#define FPT_PROPOSITIONS(catalog_kind, probe_kind, need_all, message, ...)                \
  do {                                                                                    \
    FPT_CATALOG_RECORD(catalog_kind, message);                                            \
    const int fpt_held[] = {__VA_ARGS__};                                                 \
    uint32_t fpt_low = 0u, fpt_high = 0u;                                                 \
    int fpt_all = 1, fpt_any = 0;                                                         \
    for (unsigned fpt_at = 0u; fpt_at < sizeof fpt_held / sizeof fpt_held[0]; fpt_at++) { \
      if (!fpt_held[fpt_at]) {                                                            \
        fpt_all = 0;                                                                      \
        continue;                                                                         \
      }                                                                                   \
      fpt_any = 1;                                                                        \
      if (fpt_at < 32u) {                                                                 \
        fpt_low |= 1u << fpt_at;                                                          \
      } else if (fpt_at < 64u) {                                                          \
        fpt_high |= 1u << (fpt_at - 32u);                                                 \
      }                                                                                   \
    }                                                                                     \
    uint64_t fpt_id = fpt_message_id(message);                                            \
    fpt_probe(probe_kind, fpt_id, ((need_all) ? fpt_all : fpt_any) ? 1u : 0u);            \
    fpt_probe(FPT_KIND_GUIDANCE_BOOLEAN, fpt_id, (uint64_t)fpt_high << 32 | fpt_low);     \
  } while (0)

/* Every proposition holds at least once, together. */
#define FPT_SOMETIMES_ALL(message, ...) \
  FPT_PROPOSITIONS(FPT_CATALOG_SOMETIMES, FPT_KIND_SOMETIMES, 1, message, __VA_ARGS__)
/* At least one proposition holds every time, and this is reached at least once. */
#define FPT_ALWAYS_SOME(message, ...) \
  FPT_PROPOSITIONS(FPT_CATALOG_ALWAYS, FPT_KIND_ALWAYS, 0, message, __VA_ARGS__)

/* Details for the assertion named `message`, reported after it: a value a reader of the trace
 * should see beside it. */
#define FPT_DETAILS(message, details) \
  fpt_probe(FPT_KIND_DETAILS, fpt_message_id(message), (uint64_t)(details))

#else /* !FPT_ENABLE */

static inline uint32_t fpt_hostcall_version(void) { return 0u; }

static inline int fpt_hostcall_present(void) { return 0; }

static inline uint64_t fpt_get_random(void) { return fpt_fallback_random(); }

static inline void fpt_setup_complete(uint64_t details) { (void)details; }

static inline void fpt_send_event(const char *name, uint64_t details) {
  (void)name;
  (void)details;
}

static inline void fpt_probe(uint32_t kind, uint64_t id, uint64_t value) {
  (void)kind;
  (void)id;
  (void)value;
}

#define FPT_ALWAYS(condition, message) \
  do {                                 \
  } while (0)
#define FPT_SOMETIMES(condition, message) \
  do {                                    \
  } while (0)
#define FPT_REACHABLE(message) \
  do {                         \
  } while (0)
#define FPT_UNREACHABLE(message) \
  do {                           \
  } while (0)
#define FPT_ALWAYS_OR_UNREACHABLE(condition, message) \
  do {                                                \
  } while (0)
#define FPT_ALWAYS_GREATER_THAN(left, right, message) \
  do {                                                \
  } while (0)
#define FPT_ALWAYS_GREATER_THAN_OR_EQUAL_TO(left, right, message) \
  do {                                                            \
  } while (0)
#define FPT_ALWAYS_LESS_THAN(left, right, message) \
  do {                                             \
  } while (0)
#define FPT_ALWAYS_LESS_THAN_OR_EQUAL_TO(left, right, message) \
  do {                                                         \
  } while (0)
#define FPT_SOMETIMES_GREATER_THAN(left, right, message) \
  do {                                                   \
  } while (0)
#define FPT_SOMETIMES_GREATER_THAN_OR_EQUAL_TO(left, right, message) \
  do {                                                               \
  } while (0)
#define FPT_SOMETIMES_LESS_THAN(left, right, message) \
  do {                                                \
  } while (0)
#define FPT_SOMETIMES_LESS_THAN_OR_EQUAL_TO(left, right, message) \
  do {                                                            \
  } while (0)
#define FPT_SOMETIMES_ALL(message, ...) \
  do {                                  \
  } while (0)
#define FPT_ALWAYS_SOME(message, ...) \
  do {                                \
  } while (0)
#define FPT_DETAILS(message, details) \
  do {                                \
  } while (0)

#endif /* FPT_ENABLE */

#ifdef __cplusplus
}
#endif

#endif /* FORKPOINT_HOSTCALL_H */
