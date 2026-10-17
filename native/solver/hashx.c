/*
 * HashX proof-of-work for the Anubis anti-bot solver.
 *
 * This is a self-contained C port of the `hashx` crate (v0.8.0, the Tor
 * Project's re-implementation of tevador's HashX).  The core algorithm below
 * is vendored almost verbatim from tevador/hashx (LGPL-3.0):
 *
 *     https://github.com/tevador/hashx
 *     Copyright (c) 2020 tevador <tevador@gmail.com>
 *
 * It has been merged into a single translation unit and wrapped with the small
 * public interface declared in hashx.h.  Only the interpreted runtime is
 * included (no x86/ARM JIT compiler), which keeps the port portable and
 * dependency-free.
 *
 * The seed handling and output format match the Anubis wasm module
 * (anubis/wasm/pow/hashx/src/lib.rs) exactly:
 *
 *   - build the instance from the decoded `randomData` bytes; if the program
 *     generator rejects the seed (`ProgramConstraints`), retry with
 *     `randomData || counter_u32_le` for counter = 0,1,2,... until accepted;
 *   - hash_to_bytes(nonce) is 32 bytes;
 *   - the caller checks the leading zero bits and formats the nonce/response.
 */
#include "hashx.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

/* ===== force_inline.h ===== */
#ifndef FORCE_INLINE
#if defined(_MSC_VER)
#define FORCE_INLINE __inline
#elif defined(__GNUC__) || defined(__clang__)
#define FORCE_INLINE __inline__
#else
#define FORCE_INLINE
#endif
#endif

/* ===== unreachable.h ===== */
#ifndef UNREACHABLE
#ifdef __GNUC__
#define UNREACHABLE __builtin_unreachable()
#elif _MSC_VER
#define UNREACHABLE __assume(0)
#else
#define UNREACHABLE
#endif
#endif

/* tevador's private-header linkage macro; everything is file-local here. */
#define HASHX_PRIVATE

/* ---------------------------------------------------------------- *
 * Inlined private headers (verbatim from tevador/hashx, LGPL-3.0)
 * ---------------------------------------------------------------- */

/* ===== force_inline.h ===== */
#ifndef FORCE_INLINE
#if defined(_MSC_VER)
#define FORCE_INLINE __inline
#elif defined(__GNUC__) || defined(__clang__)
#define FORCE_INLINE __inline__
#else
#define FORCE_INLINE
#endif
#endif
/* ===== unreachable.h ===== */
#ifndef UNREACHABLE
#ifdef __GNUC__
#define UNREACHABLE __builtin_unreachable()
#elif _MSC_VER
#define UNREACHABLE __assume(0)
#else
#define UNREACHABLE
#endif
#endif

/* ===== blake2.h ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

/* Original code from Argon2 reference source code package used under CC0 Licence
 * https://github.com/P-H-C/phc-winner-argon2
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
*/

#ifndef PORTABLE_BLAKE2_H
#define PORTABLE_BLAKE2_H

#include <stdint.h>
#include <limits.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

enum blake2b_constant {
	BLAKE2B_BLOCKBYTES = 128,
	BLAKE2B_OUTBYTES = 64,
	BLAKE2B_KEYBYTES = 64,
	BLAKE2B_SALTBYTES = 16,
	BLAKE2B_PERSONALBYTES = 16
};

#pragma pack(push, 1)
typedef struct blake2b_param {
	uint8_t digest_length;                   /* 1 */
	uint8_t key_length;                      /* 2 */
	uint8_t fanout;                          /* 3 */
	uint8_t depth;                           /* 4 */
	uint32_t leaf_length;                    /* 8 */
	uint64_t node_offset;                    /* 16 */
	uint8_t node_depth;                      /* 17 */
	uint8_t inner_length;                    /* 18 */
	uint8_t reserved[14];                    /* 32 */
	uint8_t salt[BLAKE2B_SALTBYTES];         /* 48 */
	uint8_t personal[BLAKE2B_PERSONALBYTES]; /* 64 */
} blake2b_param;
#pragma pack(pop)

typedef struct blake2b_state {
	uint64_t h[8];
	uint64_t t[2];
	uint64_t f[2];
	uint8_t buf[BLAKE2B_BLOCKBYTES];
	unsigned buflen;
	unsigned outlen;
	uint8_t last_node;
} blake2b_state;

/* Ensure param structs have not been wrongly padded */
/* Poor man's static_assert */
enum {
	blake2_size_check_0 = 1 / !!(CHAR_BIT == 8),
	blake2_size_check_2 =
	1 / !!(sizeof(blake2b_param) == sizeof(uint64_t) * CHAR_BIT)
};

HASHX_PRIVATE int hashx_blake2b_init_param(blake2b_state* S, const blake2b_param* P);
HASHX_PRIVATE int hashx_blake2b_update(blake2b_state* S, const void* in, size_t inlen);
HASHX_PRIVATE int hashx_blake2b_final(blake2b_state* S, void* out, size_t outlen);
HASHX_PRIVATE void hashx_blake2b_4r(const blake2b_param* P, const void* in, size_t inlen, void* out);

#if defined(__cplusplus)
}
#endif

#endif

/* ===== hashx_endian.h ===== */
#ifndef ENDIAN_H
#define ENDIAN_H

#include <stdint.h>
#include <string.h>

/* Argon2 Team - Begin Code */
/*
   Not an exhaustive list, but should cover the majority of modern platforms
   Additionally, the code will always be correct---this is only a performance
   tweak.
*/
#if (defined(__BYTE_ORDER__) &&                                                \
     (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) ||                           \
    defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || defined(__MIPSEL__) || \
    defined(__AARCH64EL__) || defined(__amd64__) || defined(__i386__) ||       \
    defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64) ||                \
    defined(_M_ARM)
#define NATIVE_LITTLE_ENDIAN
#endif
/* Argon2 Team - End Code */

static FORCE_INLINE uint32_t load32(const void* src) {
#if defined(NATIVE_LITTLE_ENDIAN)
	uint32_t w;
	memcpy(&w, src, sizeof w);
	return w;
#else
	const uint8_t* p = (const uint8_t*)src;
	uint32_t w = *p++;
	w |= (uint32_t)(*p++) << 8;
	w |= (uint32_t)(*p++) << 16;
	w |= (uint32_t)(*p++) << 24;
	return w;
#endif
}

static FORCE_INLINE uint64_t load64_native(const void* src) {
	uint64_t w;
	memcpy(&w, src, sizeof w);
	return w;
}

static FORCE_INLINE uint64_t load64(const void* src) {
#if defined(NATIVE_LITTLE_ENDIAN)
	return load64_native(src);
#else
	const uint8_t* p = (const uint8_t*)src;
	uint64_t w = *p++;
	w |= (uint64_t)(*p++) << 8;
	w |= (uint64_t)(*p++) << 16;
	w |= (uint64_t)(*p++) << 24;
	w |= (uint64_t)(*p++) << 32;
	w |= (uint64_t)(*p++) << 40;
	w |= (uint64_t)(*p++) << 48;
	w |= (uint64_t)(*p++) << 56;
	return w;
#endif
}

static FORCE_INLINE void store32(void* dst, uint32_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
	memcpy(dst, &w, sizeof w);
#else
	uint8_t* p = (uint8_t*)dst;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
#endif
}

static FORCE_INLINE void store64_native(void* dst, uint64_t w) {
	memcpy(dst, &w, sizeof w);
}

static FORCE_INLINE void store64(void* dst, uint64_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
	store64_native(dst, w);
#else
	uint8_t* p = (uint8_t*)dst;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
	w >>= 8;
	*p++ = (uint8_t)w;
#endif
}
#endif

/* ===== siphash.h ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#ifndef SIPHASH_H
#define SIPHASH_H

#include <stdint.h>

#define ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND(v0, v1, v2, v3) \
  do { \
    v0 += v1; v2 += v3; v1 = ROTL(v1, 13);   \
    v3 = ROTL(v3, 16); v1 ^= v0; v3 ^= v2;   \
    v0 = ROTL(v0, 32); v2 += v1; v0 += v3;   \
    v1 = ROTL(v1, 17);  v3 = ROTL(v3, 21);   \
    v1 ^= v2; v3 ^= v0; v2 = ROTL(v2, 32);   \
  } while (0)

typedef struct siphash_state {
    uint64_t v0, v1, v2, v3;
} siphash_state;

#ifdef __cplusplus
extern "C" {
#endif

HASHX_PRIVATE uint64_t hashx_siphash13_ctr(uint64_t input, const siphash_state* keys);
HASHX_PRIVATE void hashx_siphash24_ctr_state512(const siphash_state* keys, uint64_t input, uint64_t state_out[8]);

#ifdef __cplusplus
}
#endif

#endif

/* ===== siphash_rng.h ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#ifndef SIPHASH_GENERATOR_H
#define SIPHASH_GENERATOR_H

#include <stdint.h>

typedef struct siphash_rng {
	siphash_state keys;
	uint64_t counter;
	uint64_t buffer8, buffer32;
	unsigned count8, count32;
} siphash_rng;

#ifdef __cplusplus
extern "C" {
#endif

HASHX_PRIVATE void hashx_siphash_rng_init(siphash_rng* gen, const siphash_state* state);
HASHX_PRIVATE uint32_t hashx_siphash_rng_u32(siphash_rng* gen);
HASHX_PRIVATE uint8_t hashx_siphash_rng_u8(siphash_rng* gen);

#ifdef __cplusplus
}
#endif

#endif

/* ===== instruction.h ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include <stdint.h>

typedef enum instr_type {
	INSTR_UMULH_R,   /* unsigned high multiplication by a register */
	INSTR_SMULH_R,   /* signed high multiplication by a register */
	INSTR_MUL_R,     /* multiplication by a register */
	INSTR_SUB_R,     /* subtraction of a register */
	INSTR_XOR_R,     /* xor with a register */
	INSTR_ADD_RS,    /* addition of a shifted register */
	INSTR_ROR_C,     /* rotation by a constant */
	INSTR_ADD_C,     /* addition of a constant */
	INSTR_XOR_C,     /* xor with a constant */
	INSTR_TARGET,    /* branch instruction target */
	INSTR_BRANCH,    /* conditional branch */
} instr_type;

typedef struct instruction {
	instr_type opcode;
	int src;
	int dst;
	uint32_t imm32;
	uint32_t op_par;
} instruction;

#endif

/* ===== program.h ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#ifndef PROGRAM_H
#define PROGRAM_H

#include <stdint.h>
#include <stdbool.h>

#define HASHX_PROGRAM_MAX_SIZE 512

typedef struct hashx_program {
	instruction code[HASHX_PROGRAM_MAX_SIZE];
	size_t code_size;
#ifdef HASHX_PROGRAM_STATS
	unsigned counter;
	double ipc;
	int x86_size;
	int cpu_latency;
	int asic_latency;
	int mul_count;
	int wide_mul_count;
	int cpu_latencies[8];
	int asic_latencies[8];
	int branch_count;
	int branches[16];
#endif
} hashx_program;

#ifdef __cplusplus
extern "C" {
#endif

HASHX_PRIVATE bool hashx_program_generate(const siphash_state* key, hashx_program* program);

HASHX_PRIVATE void hashx_program_execute(const hashx_program* program, uint64_t r[8]);

HASHX_PRIVATE void hashx_program_asm_x86(const hashx_program* program);

#ifdef __cplusplus
}
#endif

#endif

/* ---------------------------------------------------------------- *
 * Inlined implementation (verbatim from tevador/hashx, LGPL-3.0)
 * ---------------------------------------------------------------- */

/* ===== blake2.c ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

/* Original code from Argon2 reference source code package used under CC0
 * https://github.com/P-H-C/phc-winner-argon2
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


static const uint64_t blake2b_IV[8] = {
	UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
	UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
	UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
	UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179) };

#define BLAKE2_SIGMA_0_0 0
#define BLAKE2_SIGMA_0_1 1
#define BLAKE2_SIGMA_0_2 2
#define BLAKE2_SIGMA_0_3 3
#define BLAKE2_SIGMA_0_4 4
#define BLAKE2_SIGMA_0_5 5
#define BLAKE2_SIGMA_0_6 6
#define BLAKE2_SIGMA_0_7 7
#define BLAKE2_SIGMA_0_8 8
#define BLAKE2_SIGMA_0_9 9
#define BLAKE2_SIGMA_0_10 10
#define BLAKE2_SIGMA_0_11 11
#define BLAKE2_SIGMA_0_12 12
#define BLAKE2_SIGMA_0_13 13
#define BLAKE2_SIGMA_0_14 14
#define BLAKE2_SIGMA_0_15 15

#define BLAKE2_SIGMA_1_0 14
#define BLAKE2_SIGMA_1_1 10
#define BLAKE2_SIGMA_1_2 4
#define BLAKE2_SIGMA_1_3 8
#define BLAKE2_SIGMA_1_4 9
#define BLAKE2_SIGMA_1_5 15
#define BLAKE2_SIGMA_1_6 13
#define BLAKE2_SIGMA_1_7 6
#define BLAKE2_SIGMA_1_8 1
#define BLAKE2_SIGMA_1_9 12
#define BLAKE2_SIGMA_1_10 0
#define BLAKE2_SIGMA_1_11 2
#define BLAKE2_SIGMA_1_12 11
#define BLAKE2_SIGMA_1_13 7
#define BLAKE2_SIGMA_1_14 5
#define BLAKE2_SIGMA_1_15 3

#define BLAKE2_SIGMA_2_0 11
#define BLAKE2_SIGMA_2_1 8
#define BLAKE2_SIGMA_2_2 12
#define BLAKE2_SIGMA_2_3 0
#define BLAKE2_SIGMA_2_4 5
#define BLAKE2_SIGMA_2_5 2
#define BLAKE2_SIGMA_2_6 15
#define BLAKE2_SIGMA_2_7 13
#define BLAKE2_SIGMA_2_8 10
#define BLAKE2_SIGMA_2_9 14
#define BLAKE2_SIGMA_2_10 3
#define BLAKE2_SIGMA_2_11 6
#define BLAKE2_SIGMA_2_12 7
#define BLAKE2_SIGMA_2_13 1
#define BLAKE2_SIGMA_2_14 9
#define BLAKE2_SIGMA_2_15 4

#define BLAKE2_SIGMA_3_0 7
#define BLAKE2_SIGMA_3_1 9
#define BLAKE2_SIGMA_3_2 3
#define BLAKE2_SIGMA_3_3 1
#define BLAKE2_SIGMA_3_4 13
#define BLAKE2_SIGMA_3_5 12
#define BLAKE2_SIGMA_3_6 11
#define BLAKE2_SIGMA_3_7 14
#define BLAKE2_SIGMA_3_8 2
#define BLAKE2_SIGMA_3_9 6
#define BLAKE2_SIGMA_3_10 5
#define BLAKE2_SIGMA_3_11 10
#define BLAKE2_SIGMA_3_12 4
#define BLAKE2_SIGMA_3_13 0
#define BLAKE2_SIGMA_3_14 15
#define BLAKE2_SIGMA_3_15 8

#define BLAKE2_SIGMA_4_0 9
#define BLAKE2_SIGMA_4_1 0
#define BLAKE2_SIGMA_4_2 5
#define BLAKE2_SIGMA_4_3 7
#define BLAKE2_SIGMA_4_4 2
#define BLAKE2_SIGMA_4_5 4
#define BLAKE2_SIGMA_4_6 10
#define BLAKE2_SIGMA_4_7 15
#define BLAKE2_SIGMA_4_8 14
#define BLAKE2_SIGMA_4_9 1
#define BLAKE2_SIGMA_4_10 11
#define BLAKE2_SIGMA_4_11 12
#define BLAKE2_SIGMA_4_12 6
#define BLAKE2_SIGMA_4_13 8
#define BLAKE2_SIGMA_4_14 3
#define BLAKE2_SIGMA_4_15 13

#define BLAKE2_SIGMA_5_0 2
#define BLAKE2_SIGMA_5_1 12
#define BLAKE2_SIGMA_5_2 6
#define BLAKE2_SIGMA_5_3 10
#define BLAKE2_SIGMA_5_4 0
#define BLAKE2_SIGMA_5_5 11
#define BLAKE2_SIGMA_5_6 8
#define BLAKE2_SIGMA_5_7 3
#define BLAKE2_SIGMA_5_8 4
#define BLAKE2_SIGMA_5_9 13
#define BLAKE2_SIGMA_5_10 7
#define BLAKE2_SIGMA_5_11 5
#define BLAKE2_SIGMA_5_12 15
#define BLAKE2_SIGMA_5_13 14
#define BLAKE2_SIGMA_5_14 1
#define BLAKE2_SIGMA_5_15 9

#define BLAKE2_SIGMA_6_0 12
#define BLAKE2_SIGMA_6_1 5
#define BLAKE2_SIGMA_6_2 1
#define BLAKE2_SIGMA_6_3 15
#define BLAKE2_SIGMA_6_4 14
#define BLAKE2_SIGMA_6_5 13
#define BLAKE2_SIGMA_6_6 4
#define BLAKE2_SIGMA_6_7 10
#define BLAKE2_SIGMA_6_8 0
#define BLAKE2_SIGMA_6_9 7
#define BLAKE2_SIGMA_6_10 6
#define BLAKE2_SIGMA_6_11 3
#define BLAKE2_SIGMA_6_12 9
#define BLAKE2_SIGMA_6_13 2
#define BLAKE2_SIGMA_6_14 8
#define BLAKE2_SIGMA_6_15 11

#define BLAKE2_SIGMA_7_0 13
#define BLAKE2_SIGMA_7_1 11
#define BLAKE2_SIGMA_7_2 7
#define BLAKE2_SIGMA_7_3 14
#define BLAKE2_SIGMA_7_4 12
#define BLAKE2_SIGMA_7_5 1
#define BLAKE2_SIGMA_7_6 3
#define BLAKE2_SIGMA_7_7 9
#define BLAKE2_SIGMA_7_8 5
#define BLAKE2_SIGMA_7_9 0
#define BLAKE2_SIGMA_7_10 15
#define BLAKE2_SIGMA_7_11 4
#define BLAKE2_SIGMA_7_12 8
#define BLAKE2_SIGMA_7_13 6
#define BLAKE2_SIGMA_7_14 2
#define BLAKE2_SIGMA_7_15 10

#define BLAKE2_SIGMA_8_0 6
#define BLAKE2_SIGMA_8_1 15
#define BLAKE2_SIGMA_8_2 14
#define BLAKE2_SIGMA_8_3 9
#define BLAKE2_SIGMA_8_4 11
#define BLAKE2_SIGMA_8_5 3
#define BLAKE2_SIGMA_8_6 0
#define BLAKE2_SIGMA_8_7 8
#define BLAKE2_SIGMA_8_8 12
#define BLAKE2_SIGMA_8_9 2
#define BLAKE2_SIGMA_8_10 13
#define BLAKE2_SIGMA_8_11 7
#define BLAKE2_SIGMA_8_12 1
#define BLAKE2_SIGMA_8_13 4
#define BLAKE2_SIGMA_8_14 10
#define BLAKE2_SIGMA_8_15 5

#define BLAKE2_SIGMA_9_0 10
#define BLAKE2_SIGMA_9_1 2
#define BLAKE2_SIGMA_9_2 8
#define BLAKE2_SIGMA_9_3 4
#define BLAKE2_SIGMA_9_4 7
#define BLAKE2_SIGMA_9_5 6
#define BLAKE2_SIGMA_9_6 1
#define BLAKE2_SIGMA_9_7 5
#define BLAKE2_SIGMA_9_8 15
#define BLAKE2_SIGMA_9_9 11
#define BLAKE2_SIGMA_9_10 9
#define BLAKE2_SIGMA_9_11 14
#define BLAKE2_SIGMA_9_12 3
#define BLAKE2_SIGMA_9_13 12
#define BLAKE2_SIGMA_9_14 13
#define BLAKE2_SIGMA_9_15 0

#define BLAKE2_SIGMA_10_0 0
#define BLAKE2_SIGMA_10_1 1
#define BLAKE2_SIGMA_10_2 2
#define BLAKE2_SIGMA_10_3 3
#define BLAKE2_SIGMA_10_4 4
#define BLAKE2_SIGMA_10_5 5
#define BLAKE2_SIGMA_10_6 6
#define BLAKE2_SIGMA_10_7 7
#define BLAKE2_SIGMA_10_8 8
#define BLAKE2_SIGMA_10_9 9
#define BLAKE2_SIGMA_10_10 10
#define BLAKE2_SIGMA_10_11 11
#define BLAKE2_SIGMA_10_12 12
#define BLAKE2_SIGMA_10_13 13
#define BLAKE2_SIGMA_10_14 14
#define BLAKE2_SIGMA_10_15 15

#define BLAKE2_SIGMA_11_0 14
#define BLAKE2_SIGMA_11_1 10
#define BLAKE2_SIGMA_11_2 4
#define BLAKE2_SIGMA_11_3 8
#define BLAKE2_SIGMA_11_4 9
#define BLAKE2_SIGMA_11_5 15
#define BLAKE2_SIGMA_11_6 13
#define BLAKE2_SIGMA_11_7 6
#define BLAKE2_SIGMA_11_8 1
#define BLAKE2_SIGMA_11_9 12
#define BLAKE2_SIGMA_11_10 0
#define BLAKE2_SIGMA_11_11 2
#define BLAKE2_SIGMA_11_12 11
#define BLAKE2_SIGMA_11_13 7
#define BLAKE2_SIGMA_11_14 5
#define BLAKE2_SIGMA_11_15 3

static FORCE_INLINE uint64_t rotr64(const uint64_t w, const unsigned c) {
	return (w >> c) | (w << (64 - c));
}

static FORCE_INLINE void blake2b_set_lastblock(blake2b_state* S) {
	S->f[0] = (uint64_t)-1;
}

static FORCE_INLINE void blake2b_increment_counter(blake2b_state* S,
	uint64_t inc) {
	S->t[0] += inc;
	S->t[1] += (S->t[0] < inc);
}

static FORCE_INLINE void blake2b_invalidate_state(blake2b_state* S) {
	//clear_internal_memory(S, sizeof(*S));      /* wipe */
	blake2b_set_lastblock(S); /* invalidate for further use */
}

static FORCE_INLINE void blake2b_init0(blake2b_state* S) {
	memset(S, 0, sizeof(*S));
	memcpy(S->h, blake2b_IV, sizeof(S->h));
}

int hashx_blake2b_init_param(blake2b_state* S, const blake2b_param* P) {
	const unsigned char* p = (const unsigned char*)P;
	unsigned int i;

	if (NULL == P || NULL == S) {
		return -1;
	}

	blake2b_init0(S);
	/* IV XOR Parameter Block */
	for (i = 0; i < 8; ++i) {
		S->h[i] ^= load64(&p[i * sizeof(S->h[i])]);
	}
	S->outlen = P->digest_length;
	return 0;
}

#define SIGMA(r, k) BLAKE2_SIGMA_ ## r ## _ ## k

#define G(r, i, j, a, b, c, d)                                               \
    do {                                                                     \
        a = a + b + m[SIGMA(r, i)];                                          \
        d = rotr64(d ^ a, 32);                                               \
        c = c + d;                                                           \
        b = rotr64(b ^ c, 24);                                               \
        a = a + b + m[SIGMA(r, j)];                                          \
        d = rotr64(d ^ a, 16);                                               \
        c = c + d;                                                           \
        b = rotr64(b ^ c, 63);                                               \
    } while ((void)0, 0)

#define ROUND_INNER(r)                                                       \
    do {                                                                     \
        G(r,  0,  1, v[0], v[4], v[8], v[12]);                               \
        G(r,  2,  3, v[1], v[5], v[9], v[13]);                               \
        G(r,  4,  5, v[2], v[6], v[10], v[14]);                              \
        G(r,  6,  7, v[3], v[7], v[11], v[15]);                              \
        G(r,  8,  9, v[0], v[5], v[10], v[15]);                              \
        G(r, 10, 11, v[1], v[6], v[11], v[12]);                              \
        G(r, 12, 13, v[2], v[7], v[8], v[13]);                               \
        G(r, 14, 15, v[3], v[4], v[9], v[14]);                               \
    } while ((void)0, 0)

#define ROUND(r) ROUND_INNER(r)

static void blake2b_compress(blake2b_state* S, const uint8_t* block) {
	uint64_t m[16];
	uint64_t v[16];
	unsigned int i;

	for (i = 0; i < 16; ++i) {
		m[i] = load64(block + i * sizeof(m[i]));
	}

	for (i = 0; i < 8; ++i) {
		v[i] = S->h[i];
	}

	v[8] = blake2b_IV[0];
	v[9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ S->t[0];
	v[13] = blake2b_IV[5] ^ S->t[1];
	v[14] = blake2b_IV[6] ^ S->f[0];
	v[15] = blake2b_IV[7] ^ S->f[1];

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (i = 0; i < 8; ++i) {
		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
	}
}

static void blake2b_compress_4r(blake2b_state* S, const uint8_t* block) {
	uint64_t m[16];
	uint64_t v[16];
	unsigned int i;

	for (i = 0; i < 16; ++i) {
		m[i] = load64(block + i * sizeof(m[i]));
	}

	for (i = 0; i < 8; ++i) {
		v[i] = S->h[i];
	}

	v[8] = blake2b_IV[0];
	v[9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ S->t[0];
	v[13] = blake2b_IV[5] ^ S->t[1];
	v[14] = blake2b_IV[6] ^ S->f[0];
	v[15] = blake2b_IV[7] ^ S->f[1];

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);

	for (i = 0; i < 8; ++i) {
		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
	}
}

int hashx_blake2b_update(blake2b_state* S, const void* in, size_t inlen) {
	const uint8_t* pin = (const uint8_t*)in;

	if (inlen == 0) {
		return 0;
	}

	/* Sanity check */
	if (S == NULL || in == NULL) {
		return -1;
	}

	/* Is this a reused state? */
	if (S->f[0] != 0) {
		return -1;
	}

	if (S->buflen + inlen > BLAKE2B_BLOCKBYTES) {
		/* Complete current block */
		size_t left = S->buflen;
		size_t fill = BLAKE2B_BLOCKBYTES - left;
		memcpy(&S->buf[left], pin, fill);
		blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
		blake2b_compress(S, S->buf);
		S->buflen = 0;
		inlen -= fill;
		pin += fill;
		/* Avoid buffer copies when possible */
		while (inlen > BLAKE2B_BLOCKBYTES) {
			blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
			blake2b_compress(S, pin);
			inlen -= BLAKE2B_BLOCKBYTES;
			pin += BLAKE2B_BLOCKBYTES;
		}
	}
	memcpy(&S->buf[S->buflen], pin, inlen);
	S->buflen += (unsigned int)inlen;
	return 0;
}

int hashx_blake2b_final(blake2b_state* S, void* out, size_t outlen) {
	uint8_t buffer[BLAKE2B_OUTBYTES] = { 0 };
	unsigned int i;

	/* Sanity checks */
	if (S == NULL || out == NULL || outlen < S->outlen) {
		return -1;
	}

	/* Is this a reused state? */
	if (S->f[0] != 0) {
		return -1;
	}

	blake2b_increment_counter(S, S->buflen);
	blake2b_set_lastblock(S);
	memset(&S->buf[S->buflen], 0, BLAKE2B_BLOCKBYTES - S->buflen); /* Padding */
	blake2b_compress(S, S->buf);

	for (i = 0; i < 8; ++i) { /* Output full hash to temp buffer */
		store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
	}

	memcpy(out, buffer, S->outlen);

	return 0;
}

/* 4-round version of Blake2b */
void hashx_blake2b_4r(const blake2b_param* params, const void* in, 
	size_t inlen, void* out) {

	blake2b_state state;
	const uint8_t* p = (const uint8_t*)params;

	blake2b_init0(&state);
	/* IV XOR Parameter Block */
	for (unsigned i = 0; i < 8; ++i) {
		state.h[i] ^= load64(&p[i * sizeof(state.h[i])]);
	}
	//state.outlen = blake_params.digest_length;

	const uint8_t* pin = (const uint8_t*)in;

	while (inlen > BLAKE2B_BLOCKBYTES) {
		blake2b_increment_counter(&state, BLAKE2B_BLOCKBYTES);
		blake2b_compress_4r(&state, pin);
		inlen -= BLAKE2B_BLOCKBYTES;
		pin += BLAKE2B_BLOCKBYTES;
	}

	memcpy(state.buf, pin, inlen);
	blake2b_increment_counter(&state, inlen);
	blake2b_set_lastblock(&state);
	blake2b_compress_4r(&state, state.buf);

	/* Output hash */
	memcpy(out, state.h, sizeof(state.h));
}

/* ===== siphash.c ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */


uint64_t hashx_siphash13_ctr(uint64_t input, const siphash_state* keys) {
    uint64_t v0 = keys->v0;
    uint64_t v1 = keys->v1;
    uint64_t v2 = keys->v2;
    uint64_t v3 = keys->v3;

    v3 ^= input;

    SIPROUND(v0, v1, v2, v3);

    v0 ^= input;
    v2 ^= 0xff;

    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);

    return (v0 ^ v1) ^ (v2 ^ v3);
}

void hashx_siphash24_ctr_state512(const siphash_state* keys, uint64_t input,
    uint64_t state_out[8]) {

    uint64_t v0 = keys->v0;
    uint64_t v1 = keys->v1;
    uint64_t v2 = keys->v2;
    uint64_t v3 = keys->v3;

    v1 ^= 0xee;
    v3 ^= input;

    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);

    v0 ^= input;
    v2 ^= 0xee;

    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);

    state_out[0] = v0;
    state_out[1] = v1;
    state_out[2] = v2;
    state_out[3] = v3;

    v1 ^= 0xdd;

    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);

    state_out[4] = v0;
    state_out[5] = v1;
    state_out[6] = v2;
    state_out[7] = v3;
}

/* ===== siphash_rng.c ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */


void hashx_siphash_rng_init(siphash_rng* gen, const siphash_state* state) {
	gen->keys = *state;
	gen->counter = 0;
	gen->count8 = 0;
	gen->count32 = 0;
}

uint8_t hashx_siphash_rng_u8(siphash_rng* gen) {
	if (gen->count8 == 0) {
		gen->buffer8 = hashx_siphash13_ctr(gen->counter, &gen->keys);
		gen->counter++;
		gen->count8 = sizeof(gen->buffer8);
	}
	gen->count8--;
	return gen->buffer8 >> (gen->count8 * 8);
}

uint32_t hashx_siphash_rng_u32(siphash_rng* gen) {
	if (gen->count32 == 0) {
		gen->buffer32 = hashx_siphash13_ctr(gen->counter, &gen->keys);
		gen->counter++;
		gen->count32 = sizeof(gen->buffer32) / sizeof(uint32_t);
	}
	gen->count32--;
	return gen->buffer32 >> (gen->count32 * 32);
}

/* ===== program.c ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* instructions are generated until this CPU cycle */
#define TARGET_CYCLE 192

/* requirements for the program to be acceptable */
#define REQUIREMENT_SIZE 512
#define REQUIREMENT_MUL_COUNT 192
#define REQUIREMENT_LATENCY 195

/* R5 (x86 = r13) register cannot be used as the destination of INSTR_ADD_RS */
#define REGISTER_NEEDS_DISPLACEMENT 5

#define PORT_MAP_SIZE (TARGET_CYCLE + 4)
#define NUM_PORTS 3
#define MAX_RETRIES 1
#define LOG2_BRANCH_PROB 4
#define BRANCH_MASK 0x80000000

#define TRACE false
#define TRACE_PRINT(...) do { if (TRACE) printf(__VA_ARGS__); } while (false)

#define MAX(a,b) ((a) > (b) ? (a) : (b))

/* If the instruction is a multiplication.  */
static inline bool is_mul(instr_type type) {
	return type <= INSTR_MUL_R;
}

/* If the instruction is a 64x64->128 bit multiplication.  */
static inline bool is_wide_mul(instr_type type) {
	return type < INSTR_MUL_R;
}

/* Ivy Bridge integer execution ports: P0, P1, P5 */
typedef enum execution_port {
	PORT_NONE = 0,
	PORT_P0 = 1,
	PORT_P1 = 2,
	PORT_P5 = 4,
	PORT_P01 = PORT_P0 | PORT_P1,
	PORT_P05 = PORT_P0 | PORT_P5,
	PORT_P015 = PORT_P0 | PORT_P1 | PORT_P5
} execution_port;

static const char* execution_port_names[] = {
	"PORT_NONE", "PORT_P0", "PORT_P1", "PORT_P01", "PORT_P5", "PORT_P05", "PORT_P15", "PORT_P015"
};

typedef struct instr_template {
	instr_type type;          /* instruction type */
	const char* x86_asm;      /* x86 assembly */
	int x86_size;             /* x86 code size */
	int latency;              /* latency in cycles */
	execution_port uop1;      /* ex. ports for the 1st uop */
	execution_port uop2;      /* ex. ports for the 2nd uop */
	uint32_t immediate_mask;  /* mask for imm32 */
	instr_type group;         /* instruction group */
	bool imm_can_be_0;        /* if imm32 can be zero */
	bool distinct_dst;        /* if dst and src must be distinct */
	bool op_par_src;          /* operation parameter is equal to src */
	bool has_src;             /* if the instruction has a source operand */
	bool has_dst;             /* if the instr. has a destination operand */
} instr_template;

typedef struct register_info {
	int latency;              /* cycle when the register value will be ready */
	instr_type last_op;       /* last op applied to the register */
	int last_op_par;          /* parameter of the last op (-1 = constant) */
} register_info;

typedef struct program_item {
	const instr_template** templates;
	uint32_t mask0;
	uint32_t mask1;
	bool duplicates;
} program_item;

typedef struct generator_ctx {
	int cycle;
	int sub_cycle;
	int mul_count;
	bool chain_mul;
	int latency;
	siphash_rng gen;
	register_info registers[8];
	execution_port ports[PORT_MAP_SIZE][NUM_PORTS];
} generator_ctx;

static const instr_template tpl_umulh_r = {
	.type = INSTR_UMULH_R,
	.x86_asm = "mul r",
	.x86_size = 9, /* mov, mul, mov */
	.latency = 4,
	.uop1 = PORT_P1,
	.uop2 = PORT_P5,
	.immediate_mask = 0,
	.group = INSTR_UMULH_R,
	.imm_can_be_0 = false,
	.distinct_dst = false,
	.op_par_src = false,
	.has_src = true,
	.has_dst = true,
};

static const instr_template tpl_smulh_r = {
	.type = INSTR_SMULH_R,
	.x86_asm = "imul r",
	.x86_size = 9, /* mov, mul, mov */
	.latency = 4,
	.uop1 = PORT_P1,
	.uop2 = PORT_P5,
	.immediate_mask = 0,
	.group = INSTR_SMULH_R,
	.imm_can_be_0 = false,
	.distinct_dst = false,
	.op_par_src = false,
	.has_src = true,
	.has_dst = true,
};

static const instr_template tpl_mul_r = {
	.type = INSTR_MUL_R,
	.x86_asm = "imul r,r",
	.x86_size = 4,
	.latency = 3,
	.uop1 = PORT_P1,
	.uop2 = PORT_NONE,
	.immediate_mask = 0,
	.group = INSTR_MUL_R,
	.imm_can_be_0 = false,
	.distinct_dst = true,
	.op_par_src = true,
	.has_src = true,
	.has_dst = true,
};

static const instr_template tpl_sub_r = {
	.type = INSTR_SUB_R,
	.x86_asm = "sub r,r",
	.x86_size = 3,
	.latency = 1,
	.uop1 = PORT_P015,
	.uop2 = PORT_NONE,
	.immediate_mask = 0,
	.group = INSTR_ADD_RS,
	.imm_can_be_0 = false,
	.distinct_dst = true,
	.op_par_src = true,
	.has_src = true,
	.has_dst = true,
};

static const instr_template tpl_xor_r = {
	.type = INSTR_XOR_R,
	.x86_asm = "xor r,r",
	.x86_size = 3,
	.latency = 1,
	.uop1 = PORT_P015,
	.uop2 = PORT_NONE,
	.immediate_mask = 0,
	.group = INSTR_XOR_R,
	.imm_can_be_0 = false,
	.distinct_dst = true,
	.op_par_src = true,
	.has_src = true,
	.has_dst = true,
};

static const instr_template tpl_add_rs = {
	.type = INSTR_ADD_RS,
	.x86_asm = "lea r,r+r*s",
	.x86_size = 4,
	.latency = 1,
	.uop1 = PORT_P01,
	.uop2 = PORT_NONE,
	.immediate_mask = 3,
	.group = INSTR_ADD_RS,
	.imm_can_be_0 = true,
	.distinct_dst = true,
	.op_par_src = true,
	.has_src = true,
	.has_dst = true,
};

static const instr_template tpl_ror_c = {
	.type = INSTR_ROR_C,
	.x86_asm = "ror r,i",
	.x86_size = 4,
	.latency = 1,
	.uop1 = PORT_P05,
	.uop2 = PORT_NONE,
	.immediate_mask = 63,
	.group = INSTR_ROR_C,
	.imm_can_be_0 = false,
	.distinct_dst = true,
	.op_par_src = false,
	.has_src = false,
	.has_dst = true,
};

static const instr_template tpl_add_c = {
	.type = INSTR_ADD_C,
	.x86_asm = "add r,i",
	.x86_size = 7,
	.latency = 1,
	.uop1 = PORT_P015,
	.uop2 = PORT_NONE,
	.immediate_mask = UINT32_MAX,
	.group = INSTR_ADD_C,
	.imm_can_be_0 = false,
	.distinct_dst = true,
	.op_par_src = false,
	.has_src = false,
	.has_dst = true,
};

static const instr_template tpl_xor_c = {
	.type = INSTR_XOR_C,
	.x86_asm = "xor r,i",
	.x86_size = 7,
	.latency = 1,
	.uop1 = PORT_P015,
	.uop2 = PORT_NONE,
	.immediate_mask = UINT32_MAX,
	.group = INSTR_XOR_C,
	.imm_can_be_0 = false,
	.distinct_dst = true,
	.op_par_src = false,
	.has_src = false,
	.has_dst = true,
};


static const instr_template tpl_target = {
	.type = INSTR_TARGET,
	.x86_asm = "cmovz esi, edi",
	.x86_size = 5, /* test, cmovz */
	.latency = 1,
	.uop1 = PORT_P015,
	.uop2 = PORT_P015,
	.immediate_mask = 0,
	.group = INSTR_TARGET,
	.imm_can_be_0 = false,
	.distinct_dst = true,
	.op_par_src = false,
	.has_src = false,
	.has_dst = false,
};

static const instr_template tpl_branch = {
	.type = INSTR_BRANCH,
	.x86_asm = "jz target",
	.x86_size = 10, /* or, test, jz */
	.latency = 1,
	.uop1 = PORT_P015,
	.uop2 = PORT_P015,
	.immediate_mask = BRANCH_MASK,
	.group = INSTR_BRANCH,
	.imm_can_be_0 = false,
	.distinct_dst = true,
	.op_par_src = false,
	.has_src = false,
	.has_dst = false,
};

static const instr_template* instr_lookup[] = {
	&tpl_ror_c,
	&tpl_xor_c,
	&tpl_add_c,
	&tpl_add_c,
	&tpl_sub_r,
	&tpl_xor_r,
	&tpl_xor_c,
	&tpl_add_rs,
};

static const instr_template* wide_mul_lookup[] = {
	&tpl_smulh_r,
	&tpl_umulh_r
};

static const instr_template* mul_lookup = &tpl_mul_r;
static const instr_template* target_lookup = &tpl_target;
static const instr_template* branch_lookup = &tpl_branch;

static const program_item item_mul = {
	.templates = &mul_lookup,
	.mask0 = 0,
	.mask1 = 0,
	.duplicates = true
};

static const program_item item_target = {
	.templates = &target_lookup,
	.mask0 = 0,
	.mask1 = 0,
	.duplicates = true
};

static const program_item item_branch = {
	.templates = &branch_lookup,
	.mask0 = 0,
	.mask1 = 0,
	.duplicates = true
};

static const program_item item_wide_mul = {
	.templates = wide_mul_lookup,
	.mask0 = 1,
	.mask1 = 1,
	.duplicates = true
};

static const program_item item_any = {
	.templates = instr_lookup,
	.mask0 = 7,
	.mask1 = 3, /* instructions that don't need a src register */
	.duplicates = false
};

static const program_item* program_layout[] = {
	&item_mul,
	&item_target,
	&item_any,
	&item_mul,
	&item_any,
	&item_any,
	&item_mul,
	&item_any,
	&item_any,
	&item_mul,
	&item_any,
	&item_any,
	&item_wide_mul,
	&item_any,
	&item_any,
	&item_mul,
	&item_any,
	&item_any,
	&item_mul,
	&item_branch,
	&item_any,
	&item_mul,
	&item_any,
	&item_any,
	&item_wide_mul,
	&item_any,
	&item_any,
	&item_mul,
	&item_any,
	&item_any,
	&item_mul,
	&item_any,
	&item_any,
	&item_mul,
	&item_any,
	&item_any,
};

static const instr_template* select_template(generator_ctx* ctx, instr_type last_instr, int attempt) {
	const program_item* item = program_layout[ctx->sub_cycle % 36];
	const instr_template* tpl;
	do {
		int index = item->mask0 ? hashx_siphash_rng_u8(&ctx->gen) & (attempt > 0 ? item->mask1 : item->mask0) : 0;
		tpl = item->templates[index];
	} while (!item->duplicates && tpl->group == last_instr);
	return tpl;
}

static uint32_t branch_mask(siphash_rng* gen) {
	uint32_t mask = 0;
	int popcnt = 0;
	while (popcnt < LOG2_BRANCH_PROB) {
		int bit = hashx_siphash_rng_u8(gen) % 32;
		uint32_t bitmask = 1U << bit;
		if (!(mask & bitmask)) {
			mask |= bitmask;
			popcnt++;
		}
	}
	return mask;
}

static void instr_from_template(const instr_template* tpl, siphash_rng* gen, instruction* instr) {
	instr->opcode = tpl->type;
	if (tpl->immediate_mask) {
		if (tpl->immediate_mask == BRANCH_MASK) {
			instr->imm32 = branch_mask(gen);
		}
		else do {
			instr->imm32 = hashx_siphash_rng_u32(gen) & tpl->immediate_mask;
		} while (instr->imm32 == 0 && !tpl->imm_can_be_0);
	}
	if (!tpl->op_par_src) {
		if (tpl->distinct_dst) {
			instr->op_par = UINT32_MAX;
		}
		else {
			instr->op_par = hashx_siphash_rng_u32(gen);
		}
	}
	if (!tpl->has_src) {
		instr->src = -1;
	}
	if (!tpl->has_dst) {
		instr->dst = -1;
	}
}

static bool select_register(int available_regs[8], int regs_count, siphash_rng* gen, int* reg_out) {
	if (regs_count == 0)
		return false;

	int index;

	if (regs_count > 1) {
		index = hashx_siphash_rng_u32(gen) % regs_count;
	}
	else {
		index = 0;
	}
	*reg_out = available_regs[index];
	return true;
}

static bool select_destination(const instr_template* tpl, instruction* instr, generator_ctx* ctx, int cycle) {
	int available_regs[8];
	int regs_count = 0;
	/* Conditions for the destination register:
	// * value must be ready at the required cycle
	// * cannot be the same as the source register unless the instruction allows it
	//   - this avoids optimizable instructions such as "xor r, r" or "sub r, r"
	// * register cannot be multiplied twice in a row unless chain_mul is true
	//   - this avoids accumulation of trailing zeroes in registers due to excessive multiplication
	//   - allowChainedMul is set to true if an attempt to find source/destination registers failed (this is quite rare, but prevents a catastrophic failure of the generator)
	// * either the last instruction applied to the register or its source must be different than this instruction
	//   - this avoids optimizable instruction sequences such as "xor r1, r2; xor r1, r2" or "ror r, C1; ror r, C2" or "add r, C1; add r, C2"
	// * register r5 cannot be the destination of the IADD_RS instruction (limitation of the x86 lea instruction) */
	for (int i = 0; i < 8; ++i) {
		bool available = ctx->registers[i].latency <= cycle;
		available &= ((!tpl->distinct_dst) | (i != instr->src));
		available &= (ctx->chain_mul | (tpl->group != INSTR_MUL_R) | (ctx->registers[i].last_op != INSTR_MUL_R));
		available &= ((ctx->registers[i].last_op != tpl->group) | ((uint32_t)ctx->registers[i].last_op_par != instr->op_par));
		available &= ((instr->opcode != INSTR_ADD_RS) | (i != REGISTER_NEEDS_DISPLACEMENT));
		available_regs[regs_count] = available ? i : 0;
		regs_count += available;
	}
	return select_register(available_regs, regs_count, &ctx->gen, &instr->dst);
}

static bool select_source(const instr_template* tpl, instruction* instr, generator_ctx* ctx, int cycle) {
	int available_regs[8];
	int regs_count = 0;
	/* all registers that are ready at the cycle */
	for (int i = 0; i < 8; ++i) {
		if (ctx->registers[i].latency <= cycle)
			available_regs[regs_count++] = i;
	}
	/* if there are only 2 available registers for ADD_RS and one of them is r5, select it as the source because it cannot be the destination */
	if (regs_count == 2 && instr->opcode == INSTR_ADD_RS) {
		if (available_regs[0] == REGISTER_NEEDS_DISPLACEMENT || available_regs[1] == REGISTER_NEEDS_DISPLACEMENT) {
			instr->op_par = instr->src = REGISTER_NEEDS_DISPLACEMENT;
			return true;
		}
	}
	if (select_register(available_regs, regs_count, &ctx->gen, &instr->src)) {
		if (tpl->op_par_src)
			instr->op_par = instr->src;
		return true;
	}
	return false;
}

static int schedule_uop(execution_port uop, generator_ctx* ctx, int cycle, bool commit) {
	/* The scheduling here is done optimistically by checking port availability in order P5 -> P0 -> P1 to not overload
	   port P1 (multiplication) by instructions that can go to any port. */
	for (; cycle < PORT_MAP_SIZE; ++cycle) {
		if ((uop & PORT_P5) && !ctx->ports[cycle][2]) {
			if (commit) {
				ctx->ports[cycle][2] = uop;
			}
			TRACE_PRINT("%s scheduled to port P5 at cycle %i (commit = %i)\n", execution_port_names[uop], cycle, commit);
			return cycle;
		}
		if ((uop & PORT_P0) && !ctx->ports[cycle][0]) {
			if (commit) {
				ctx->ports[cycle][0] = uop;
			}
			TRACE_PRINT("%s scheduled to port P0 at cycle %i (commit = %i)\n", execution_port_names[uop], cycle, commit);
			return cycle;
		}
		if ((uop & PORT_P1) != 0 && !ctx->ports[cycle][1]) {
			if (commit) {
				ctx->ports[cycle][1] = uop;
			}
			TRACE_PRINT("%s scheduled to port P1 at cycle %i (commit = %i)\n", execution_port_names[uop], cycle, commit);
			return cycle;
		}
	}
	return -1;
}

static int schedule_instr(const instr_template* tpl, generator_ctx* ctx, bool commit) {
	if (tpl->uop2 == PORT_NONE) {
		/* this instruction has only one uOP */
		return schedule_uop(tpl->uop1, ctx, ctx->cycle, commit);
	}
	else {
		/* instructions with 2 uOPs are scheduled conservatively by requiring both uOPs to execute in the same cycle */
		for (int cycle = ctx->cycle; cycle < PORT_MAP_SIZE; ++cycle) {

			int cycle1 = schedule_uop(tpl->uop1, ctx, cycle, false);
			int cycle2 = schedule_uop(tpl->uop2, ctx, cycle, false);

			if (cycle1 >= 0 && cycle1 == cycle2) {
				if (commit) {
					schedule_uop(tpl->uop1, ctx, cycle, true);
					schedule_uop(tpl->uop2, ctx, cycle, true);
				}
				return cycle1;
			}
		}
	}

	return -1;
}

static void print_registers(const generator_ctx* ctx) {
	for (int i = 0; i < 8; ++i) {
		printf("   R%i = %i\n", i, ctx->registers[i].latency);
	}
}

bool hashx_program_generate(const siphash_state* key, hashx_program* program) {
	generator_ctx ctx = {
		.cycle = 0,
		.sub_cycle = 0, /* 3 sub-cycles = 1 cycle */
		.mul_count = 0,
		.chain_mul = false,
		.latency = 0,
		.ports = {{ 0 }}
	};
	hashx_siphash_rng_init(&ctx.gen, key);
	for (int i = 0; i < 8; ++i) {
		ctx.registers[i].last_op = -1;
		ctx.registers[i].latency = 0;
		ctx.registers[i].last_op_par = -1;
	}
	program->code_size = 0;

	int attempt = 0;
	instr_type last_instr = -1;
#ifdef HASHX_PROGRAM_STATS
	program->x86_size = 0;
#endif

	while (program->code_size < HASHX_PROGRAM_MAX_SIZE) {
		instruction* instr = &program->code[program->code_size];
		TRACE_PRINT("CYCLE: %i/%i\n", ctx.sub_cycle, ctx.cycle);

		/* select an instruction template */
		const instr_template* tpl = select_template(&ctx, last_instr, attempt);
		last_instr = tpl->group;

		TRACE_PRINT("Template: %s\n", tpl->x86_asm);

		instr_from_template(tpl, &ctx.gen, instr);

		/* calculate the earliest cycle when this instruction (all of its uOPs) can be scheduled for execution */
		int scheduleCycle = schedule_instr(tpl, &ctx, false);
		if (scheduleCycle < 0) {
			TRACE_PRINT("Unable to map operation '%s' to execution port (cycle %i)\n", tpl->x86_asm, ctx.cycle);
			/* __debugbreak(); */
			break;
		}

		ctx.chain_mul = attempt > 0;

		/* find a source register (if applicable) that will be ready when this instruction executes */
		if (tpl->has_src) {
			if (!select_source(tpl, instr, &ctx, scheduleCycle)) {
				TRACE_PRINT("; src STALL (attempt %i)\n", attempt);
				if (attempt++ < MAX_RETRIES) {
					continue;
				}
				if (TRACE) {
					printf("; select_source FAILED at cycle %i\n", ctx.cycle);
					print_registers(&ctx);
					/* __debugbreak(); */
				}
				ctx.sub_cycle += 3;
				ctx.cycle = ctx.sub_cycle / 3;
				attempt = 0;
				continue;
			}
			TRACE_PRINT("; src = r%i\n", instr->src);
		}

		/* find a destination register that will be ready when this instruction executes */
		if (tpl->has_dst) {
			if (!select_destination(tpl, instr, &ctx, scheduleCycle)) {
				TRACE_PRINT("; dst STALL (attempt %i)\n", attempt);
				if (attempt++ < MAX_RETRIES) {
					continue;
				}
				if (TRACE) {
					printf("; select_destination FAILED at cycle %i\n", ctx.cycle);
					print_registers(&ctx);
					/* __debugbreak(); */
				}
				ctx.sub_cycle += 3;
				ctx.cycle = ctx.sub_cycle / 3;
				attempt = 0;
				continue;
			}
			TRACE_PRINT("; dst = r%i\n", instr->dst);
		}
		attempt = 0;

		/* recalculate when the instruction can be scheduled for execution based on operand availability */
		scheduleCycle = schedule_instr(tpl, &ctx, true);

		if (scheduleCycle < 0) {
			TRACE_PRINT("Unable to map operation '%s' to execution port (cycle %i)\n", tpl->x86_asm, ctx.cycle);
			break;
		}

		/* terminating condition */
		if (scheduleCycle >= TARGET_CYCLE) {
			break;
		}

		if (tpl->has_dst) {
			register_info* ri = &ctx.registers[instr->dst];
			int retireCycle = scheduleCycle + tpl->latency;
			ri->latency = retireCycle;
			ri->last_op = tpl->group;
			ri->last_op_par = instr->op_par;
			ctx.latency = MAX(retireCycle, ctx.latency);
			TRACE_PRINT("; RETIRED at cycle %i\n", retireCycle);
		}

		program->code_size++;
#ifdef HASHX_PROGRAM_STATS
		program->x86_size += tpl->x86_size;
#endif

		ctx.mul_count += is_mul(instr->opcode);

		++ctx.sub_cycle;
		ctx.sub_cycle += (tpl->uop2 != PORT_NONE);
		ctx.cycle = ctx.sub_cycle / 3;
	}

#ifdef HASHX_PROGRAM_STATS
	memset(program->asic_latencies, 0, sizeof(program->asic_latencies));

	program->counter = ctx.gen.counter;
	program->wide_mul_count = 0;
	program->mul_count = ctx.mul_count;

	/* Calculate ASIC latency:
	   Assumes 1 cycle latency for all operations and unlimited parallelization. */
	for (int i = 0; i < program->code_size; ++i) {
		instruction* instr = &program->code[i];
		if (instr->dst < 0)
			continue;
		int last_dst = program->asic_latencies[instr->dst] + 1;
		int lat_src = instr->dst != instr->src ? program->asic_latencies[instr->src] + 1 : 0;
		program->asic_latencies[instr->dst] = MAX(last_dst, lat_src);
		program->wide_mul_count += is_wide_mul(instr->opcode);
	}

	program->asic_latency = 0;
	program->cpu_latency = 0;
	for (int i = 0; i < 8; ++i) {
		program->asic_latency = MAX(program->asic_latency, program->asic_latencies[i]);
		program->cpu_latencies[i] = ctx.registers[i].latency;
		program->cpu_latency = MAX(program->cpu_latency, program->cpu_latencies[i]);
	}

	program->ipc = program->code_size / (double)program->cpu_latency;
	program->branch_count = 0;
	memset(program->branches, 0, sizeof(program->branches));

	if (TRACE) {
		printf("; ALU port utilization:\n");
		printf("; (* = in use, _ = idle)\n");
		for (int i = 0; i < PORT_MAP_SIZE; ++i) {
			printf("; %3i ", i);
			for (int j = 0; j < NUM_PORTS; ++j) {
				printf("%c", (ctx.ports[i][j] ? '*' : '_'));
			}
			printf("\n");
		}
	}
#endif

	/* reject programs that don't meet the uniform complexity requirements */
	/* this happens in less than 1 seed out of 10000 */
	return
		(program->code_size == REQUIREMENT_SIZE) &
		(ctx.mul_count == REQUIREMENT_MUL_COUNT) &
		(ctx.latency == REQUIREMENT_LATENCY - 1); /* cycles are numbered from 0 */
}

static const char* x86_reg_map[] = { "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

void hashx_program_asm_x86(const hashx_program* program) {
	int target = 0;
	for (unsigned i = 0; i < program->code_size; ++i) {
		const instruction* instr = &program->code[i];
		switch (instr->opcode)
		{
		case INSTR_SUB_R:
			printf("sub %s, %s\n", x86_reg_map[instr->dst], x86_reg_map[instr->src]);
			break;
		case INSTR_XOR_R:
			printf("xor %s, %s\n", x86_reg_map[instr->dst], x86_reg_map[instr->src]);
			break;
		case INSTR_ADD_RS:
			printf("lea %s, [%s+%s*%u]\n", x86_reg_map[instr->dst], x86_reg_map[instr->dst], x86_reg_map[instr->src], 1 << instr->imm32);
			break;
		case INSTR_MUL_R:
			printf("imul %s, %s\n", x86_reg_map[instr->dst], x86_reg_map[instr->src]);
			break;
		case INSTR_ROR_C:
			printf("ror %s, %u\n", x86_reg_map[instr->dst], instr->imm32);
			break;
		case INSTR_ADD_C:
			printf("add %s, %i\n", x86_reg_map[instr->dst], instr->imm32);
			break;
		case INSTR_XOR_C:
			printf("xor %s, %i\n", x86_reg_map[instr->dst], instr->imm32);
			break;
		case INSTR_UMULH_R:
			printf("mov rax, %s\n", x86_reg_map[instr->dst]);
			printf("mul %s\n", x86_reg_map[instr->src]);
			printf("mov %s, rdx\n", x86_reg_map[instr->dst]);
			break;
		case INSTR_SMULH_R:
			printf("mov rax, %s\n", x86_reg_map[instr->dst]);
			printf("imul %s\n", x86_reg_map[instr->src]);
			printf("mov %s, rdx\n", x86_reg_map[instr->dst]);
			break;
		case INSTR_TARGET:
			printf("test edi, edi\n");
			printf("target_%i: cmovz esi, edi\n", i);
			target = i;
			break;
		case INSTR_BRANCH:
			printf("or edx, esi\n");
			printf("test edx, %i\n", instr->imm32);
			printf("jz target_%i\n", target);
			break;
		default:
			UNREACHABLE;
		}
	}
}

/* ===== program_exec.c ===== */
/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */


#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
static FORCE_INLINE uint64_t umulh(uint64_t a, uint64_t b) {
	return ((uint128_t)a * b) >> 64;
	}
static FORCE_INLINE int64_t smulh(int64_t a, int64_t b) {
	return ((int128_t)a * b) >> 64;
}
#define HAVE_UMULH
#define HAVE_SMULH
#endif

#if defined(_MSC_VER)
#pragma warning (disable : 4146) /* unary minus applied to unsigned type */
#define HAS_VALUE(X) X ## 0
#define EVAL_DEFINE(X) HAS_VALUE(X)
#include <intrin.h>
#include <stdlib.h>

static FORCE_INLINE uint64_t rotr64(uint64_t x, unsigned int c) {
	return _rotr64(x, c);
}

#define HAVE_ROTR

#if EVAL_DEFINE(__MACHINEARM64_X64(1))
static FORCE_INLINE uint64_t umulh(uint64_t a, uint64_t b) {
	return __umulh(a, b);
}
#define HAVE_UMULH
#endif

#if EVAL_DEFINE(__MACHINEX64(1))
static FORCE_INLINE int64_t smulh(int64_t a, int64_t b) {
	int64_t hi;
	_mul128(a, b, &hi);
	return hi;
}
#define HAVE_SMULH
#endif

#endif


#ifndef HAVE_UMULH
#define LO(x) ((x)&0xffffffff)
#define HI(x) ((x)>>32)
uint64_t umulh(uint64_t a, uint64_t b) {
	uint64_t ah = HI(a), al = LO(a);
	uint64_t bh = HI(b), bl = LO(b);
	uint64_t x00 = al * bl;
	uint64_t x01 = al * bh;
	uint64_t x10 = ah * bl;
	uint64_t x11 = ah * bh;
	uint64_t m1 = LO(x10) + LO(x01) + HI(x00);
	uint64_t m2 = HI(x10) + HI(x01) + LO(x11) + HI(m1);
	uint64_t m3 = HI(x11) + HI(m2);

	return (m3 << 32) + LO(m2);
}
#undef LO
#undef HI
#define HAVE_UMULH
#endif

#ifndef HAVE_SMULH
int64_t smulh(int64_t a, int64_t b) {
	int64_t hi = umulh(a, b);
	if (a < 0LL) hi -= b;
	if (b < 0LL) hi -= a;
	return hi;
}
#define HAVE_SMULH
#endif

static FORCE_INLINE uint64_t sign_extend_2s_compl(uint32_t x) {
	return (-1 == ~0) ?
		(uint64_t)(int64_t)(int32_t)(x) :
		(x > INT32_MAX ? (x | 0xffffffff00000000ULL) : (uint64_t)x);
}

void hashx_program_execute(const hashx_program* program, uint64_t r[8]) {
	int target = 0;
	bool branch_enable = true;
	uint32_t result = 0;
	for (int i = 0; i < (int)program->code_size; ++i) {
		const instruction* instr = &program->code[i];
		switch (instr->opcode)
		{
		case INSTR_UMULH_R:
			result = r[instr->dst] = umulh(r[instr->dst], r[instr->src]);
			break;
		case INSTR_SMULH_R:
			result = r[instr->dst] = smulh(r[instr->dst], r[instr->src]);
			break;
		case INSTR_MUL_R:
			r[instr->dst] *= r[instr->src];
			break;
		case INSTR_SUB_R:
			r[instr->dst] -= r[instr->src];
			break;
		case INSTR_XOR_R:
			r[instr->dst] ^= r[instr->src];
			break;
		case INSTR_ADD_RS:
			r[instr->dst] += r[instr->src] << instr->imm32;
			break;
		case INSTR_ROR_C:
			r[instr->dst] = rotr64(r[instr->dst], instr->imm32);
			break;
		case INSTR_ADD_C:
			r[instr->dst] += sign_extend_2s_compl(instr->imm32);
			break;
		case INSTR_XOR_C:
			r[instr->dst] ^= sign_extend_2s_compl(instr->imm32);
			break;
		case INSTR_TARGET:
			target = i;
			break;
		case INSTR_BRANCH:
			if (branch_enable && (result & instr->imm32) == 0) {
				i = target;
				branch_enable = false;
#ifdef HASHX_PROGRAM_STATS
				((hashx_program*)program)->branch_count++;
				((hashx_program*)program)->branches[branch_idx]++;
#endif
			}
			break;
		default:
			UNREACHABLE;
		}
	}
}

/* ---------------------------------------------------------------- *
 * Public interface
 * ---------------------------------------------------------------- */

/* Blake2b parameters used to derive the two SipHash keys from the seed.
 * The salt "HashX v1" is the same domain-separation value the wasm module and
 * the `hashx` crate use (SipState::pair_from_seed). */
static const blake2b_param hashx_blake2_params = {
	.digest_length = 64,
	.key_length = 0,
	.fanout = 1,
	.depth = 1,
	.leaf_length = 0,
	.node_offset = 0,
	.node_depth = 0,
	.inner_length = 0,
	.reserved = { 0 },
	.salt = "HashX v1",
	.personal = { 0 }
};

typedef struct hashx_state {
	siphash_state keys;      /* register_key = Blake2b(seed)[32..64]  */
	hashx_program program;   /* the generated interpreted program    */
} hashx_state;

/* Derive the two SipHash keys from `seed` and try to generate a program.
 * Returns 1 on success (keys + program filled in), 0 if the program fails
 * the uniform-complexity requirements. */
static int hashx_build(const unsigned char *seed, size_t slen,
                       siphash_state keys[2], hashx_program *program) {
	blake2b_state hs;
	hashx_blake2b_init_param(&hs, &hashx_blake2_params);
	hashx_blake2b_update(&hs, seed, slen);
	hashx_blake2b_final(&hs, keys, sizeof(siphash_state) * 2);
	return hashx_program_generate(&keys[0], program);
}

int hashx_init(const unsigned char *data, size_t dlen, void **state_out,
               size_t *state_size) {
	hashx_state *st;
	siphash_state keys[2];

	if (!state_out) return 1;
	st = (hashx_state *)malloc(sizeof *st);
	if (!st) return 1;

	/* Common case: the challenge bytes are accepted as-is. */
	if (hashx_build(data, dlen, keys, &st->program)) {
		st->keys = keys[1];
		*state_out = st;
		if (state_size) *state_size = sizeof *st;
		return 0;
	}

	/* Rejected: append an incrementing little-endian counter until the
	 * generator accepts the seed (identical to make_hashx() in lib.rs). */
	{
		unsigned char *seed = (unsigned char *)malloc(dlen + 4);
		uint32_t counter = 0;
		if (!seed) { free(st); return 1; }
		for (;;) {
			memcpy(seed, data, dlen);
			seed[dlen + 0] = (unsigned char)(counter);
			seed[dlen + 1] = (unsigned char)(counter >> 8);
			seed[dlen + 2] = (unsigned char)(counter >> 16);
			seed[dlen + 3] = (unsigned char)(counter >> 24);
			if (hashx_build(seed, dlen + 4, keys, &st->program)) {
				st->keys = keys[1];
				*state_out = st;
				if (state_size) *state_size = sizeof *st;
				free(seed);
				return 0;
			}
			counter++;
		}
	}
}

void hashx_hash(const void *state, size_t state_size,
                unsigned long long n, unsigned char out[32]) {
	const hashx_state *st = (const hashx_state *)state;
	uint64_t r[8];

	(void)state_size;

	/* initial register file from the register key + nonce */
	hashx_siphash24_ctr_state512(&st->keys, (uint64_t)n, r);

	/* run the generated program */
	hashx_program_execute(&st->program, r);

	/* finalization: mix the key back in and run one SipRound per half */
	r[0] += st->keys.v0;
	r[1] += st->keys.v1;
	r[6] += st->keys.v2;
	r[7] += st->keys.v3;
	SIPROUND(r[0], r[1], r[2], r[3]);
	SIPROUND(r[4], r[5], r[6], r[7]);

	/* 32-byte output, little-endian words */
	store64(out + 0,  r[0] ^ r[4]);
	store64(out + 8,  r[1] ^ r[5]);
	store64(out + 16, r[2] ^ r[6]);
	store64(out + 24, r[3] ^ r[7]);
}

void hashx_free(void *state) {
	free(state);
}

/* ------------------------------------------------------------------ *
 * Convenience wrapper used by the Anubis solver.
 *
 * The solver calls this once per candidate nonce with the same challenge
 * bytes.  Generating the HashX program is comparatively expensive, so the
 * instance is cached (thread-local, since http_req() may run concurrently),
 * keyed on the exact (data,dlen) pair.
 * ------------------------------------------------------------------ */
static _Thread_local unsigned char *tl_seed;
static _Thread_local size_t tl_seedlen;
static _Thread_local void *tl_state;
static _Thread_local size_t tl_statesize;

int hashx_hash_to_bytes(const unsigned char *data, size_t dlen,
                        unsigned long long n, unsigned char out[32]) {
	if (!tl_state || tl_seedlen != dlen ||
	    (dlen && memcmp(tl_seed, data, dlen) != 0)) {
		if (tl_state) {
			hashx_free(tl_state);
			tl_state = NULL;
		}
		free(tl_seed);
		tl_seed = NULL;
		tl_seedlen = 0;

		tl_seed = (unsigned char *)malloc(dlen ? dlen : 1);
		if (!tl_seed) return 0;
		if (dlen) memcpy(tl_seed, data, dlen);
		tl_seedlen = dlen;

		if (hashx_init(data, dlen, &tl_state, &tl_statesize) != 0) {
			free(tl_seed);
			tl_seed = NULL;
			tl_seedlen = 0;
			return 0;
		}
	}
	hashx_hash(tl_state, tl_statesize, n, out);
	return 1;
}

void hashx_thread_cleanup(void) {
	if (tl_state) {
		hashx_free(tl_state);
		tl_state = NULL;
	}
	tl_statesize = 0;
	free(tl_seed);
	tl_seed = NULL;
	tl_seedlen = 0;
}
