#ifndef FB_HASHX_H
#define FB_HASHX_H

/* HashX proof-of-work (Anubis algorithm "hashx").
 *
 * Self-contained C port of the `hashx` crate v0.8.0 (Tor Project's
 * re-implementation of tevador's HashX); see hashx.c for provenance and
 * licensing.  Output and seed handling match Anubis'
 * wasm/pow/hashx/src/lib.rs byte-for-byte. */

#include <stddef.h>

/* Build a HashX instance from the challenge bytes `data`/`dlen`.
 *
 * `data` is the hex-decoded `randomData` field.  If the program generator
 * rejects those bytes, a little-endian u32 counter is appended and the seed
 * retried (counter = 0,1,2,...) until accepted — exactly what the wasm
 * module does, so client and server agree on the program.
 *
 * On success returns 0 and stores a malloc'd opaque state in *state_out
 * with its size in *state_size (free it with hashx_free()).  Returns
 * non-zero on allocation failure. */
int hashx_init(const unsigned char *data, size_t dlen,
               void **state_out, size_t *state_size);

/* Fill out[32] with the HashX output for nonce `n`. */
void hashx_hash(const void *state, size_t state_size,
                unsigned long long n, unsigned char out[32]);

/* Release a state returned by hashx_init(). */
void hashx_free(void *state);

/* Convenience wrapper for the solver: compute the 32-byte hash of nonce `n`
 * for the challenge bytes `data`/`dlen`, building and caching the HashX
 * instance on first use (the cache is thread-local and keyed on the exact
 * challenge bytes).  Returns 1 on success, 0 on allocation failure. */
int hashx_hash_to_bytes(const unsigned char *data, size_t dlen,
                        unsigned long long n, unsigned char out[32]);

/* Free the calling thread's cached HashX instance. Call this before a worker
   thread exits, otherwise every short-lived solver thread leaks its state. */
void hashx_thread_cleanup(void);

#endif /* FB_HASHX_H */
