/* Anubis proof-of-work solver (TecharoHQ/anubis) — ported to C.
 *
 * Every algorithm the server can issue is handled here:
 *
 *   fast / slow : response = hex(sha256( randomData_ASCII + decimal_nonce ))
 *                 valid when the hash has `difficulty` leading '0' HEX digits.
 *
 *   sha256      : response = hex(sha256( data_bytes || nonce_u32_[le|be] ))
 *                 valid when the hash has `difficulty` leading zero BITS.
 *
 *   argon2id    : response = hex(argon2id( password=data_bytes,
 *                                          salt=nonce_u64_[le|be], 32 bytes ))
 *                 valid when the hash has `difficulty` leading zero BITS.
 *
 *   hashx       : HashX program of the challenge (ported in hashx.c).
 *
 *   metarefresh : no proof of work at all. The page (or its Refresh header) points at
 *                 a pass-challenge URL carrying `challenge`/`id`; the server accepts it
 *                 once difficulty*800ms have elapsed since the challenge was issued.
 *                 We rebuild that URL and the caller waits (anubis_pass_delay_ms).
 *
 * The `css-load` challenge extension additionally requires the client to GET
 * /.within.website/x/cmd/anubis/ext/css-load/<id> before submitting (see anubis_css_url),
 * otherwise validation fails even though the hash was correct.
 *
 * The [le|be] byte order for the WASM algorithms is chosen by the last byte of the
 * decoded challenge: >= 0x80 -> little-endian, else big-endian (see the Rust sources).
 *
 * After solving: GET <base-prefix>/.within.website/x/cmd/anubis/api/pass-challenge
 * ?id=..&response=..&nonce=..&redir=..&elapsedTime=..  with the challenge page's
 * cookies — the server sets the auth cookie and redirects back to `redir`.
 */
#include "anubis.h"
#include "hashx.h"
#include "util.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

enum { ALG_FAST, ALG_SHA256, ALG_ARGON2ID, ALG_HASHX, ALG_UNKNOWN };

int anubis_is_challenge(const char *body){
    if(!body) return 0;
    return (strstr(body,"anubis_challenge")!=NULL) &&
           (strstr(body,"cmd/anubis")!=NULL || strstr(body,"not a bot")!=NULL);
}

/* ---- helpers ---- */
static int hexval(int c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static size_t hex_decode(const char *hex, unsigned char *out, size_t max){
    size_t n=0;
    for(const char *p=hex; p[0] && p[1] && n<max; p+=2){
        int a=hexval(p[0]), b=hexval(p[1]);
        if(a<0||b<0) break;
        out[n++]=(unsigned char)((a<<4)|b);
    }
    return n;
}
static int check_hex(const unsigned char *h, int nibbles){
    for(int i=0;i<nibbles;i++){
        int nib = (i&1)? (h[i>>1]&0x0f) : (h[i>>1]>>4);
        if(nib) return 0;
    }
    return 1;
}
static int check_bits(const unsigned char *h, int bits){    /* mirrors wasm validate() */
    int remaining=bits;
    for(int i=0;i<SHA256_DIGEST_LENGTH && remaining>0;i++){
        if(remaining>=8){ if(h[i]!=0) return 0; remaining-=8; }
        else { unsigned mask=0xFFu << (8-remaining); if(h[i]&mask) return 0; remaining=0; }
    }
    return 1;
}
/* Argon2's KDF context is built once per worker and reused for every candidate.
   The old code did EVP_KDF_fetch()+EVP_KDF_CTX_new() per nonce, which dominated
   the solve time (~140ms per attempt instead of ~15ms). */
static EVP_KDF_CTX *argon2id_ctx_new(void){
    EVP_KDF *kdf = EVP_KDF_fetch(NULL,"ARGON2ID",NULL);
    if(!kdf) return NULL;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    return ctx;
}
static int argon2id_derive(EVP_KDF_CTX *ctx,
                           const unsigned char *pwd,size_t pwdlen,
                           const unsigned char *salt,size_t saltlen,
                           unsigned char *out,size_t outlen){
    uint32_t lanes=1, memcost=19456, iter=2;             /* argon2 crate Argon2::default() */
    OSSL_PARAM params[6]; int i=0;
    params[i++]=OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,(void*)pwd,pwdlen);
    params[i++]=OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,(void*)salt,saltlen);
    params[i++]=OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,&lanes);
    params[i++]=OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST,&memcost);
    params[i++]=OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER,&iter);
    params[i++]=OSSL_PARAM_construct_end();
    EVP_KDF_CTX_reset(ctx);
    return EVP_KDF_derive(ctx,out,outlen,params)>0;
}

/* ---- multi-threaded nonce search ---- */
#define ANUBIS_DEFAULT_THREADS 8
#define ANUBIS_MAX_THREADS     64

typedef struct {
    unsigned long long nonce;
    unsigned char hash[SHA256_DIGEST_LENGTH];
} solve_result;

typedef struct {
    int alg;
    const char *randomData;
    const unsigned char *data;
    size_t dlen;
    size_t randomLen;
    const SHA256_CTX *mid;   /* state after the constant prefix (fast/sha256) */
    size_t prefix;           /* bytes of the message already folded into mid */
    int difficulty;
    unsigned tid, nthreads;
    unsigned long long limit, stride;
    _Atomic int *found;
    pthread_mutex_t *mu;
    solve_result *result;
    unsigned long long attempts;
    int error;
} solve_job;

static int anubis_threads(void){
    const char *e = getenv("FB_ANUBIS_THREADS");
    int n = ANUBIS_DEFAULT_THREADS;
    if(e && *e){
        char *end = NULL;
        long v = strtol(e, &end, 10);
        if(end && end != e) n = (int)v;
    }
    if(n < 1) n = 1;
    if(n > ANUBIS_MAX_THREADS) n = ANUBIS_MAX_THREADS;
    return n;
}

/* Hash one candidate. Returns 0 on failure (bad input / KDF / allocation). */
static int compute_candidate(const solve_job *j, unsigned long long n,
                             unsigned char h[SHA256_DIGEST_LENGTH],
                             unsigned char nb[8],
                             EVP_KDF_CTX *actx, int use_le){
    switch(j->alg){
    case ALG_FAST: {
        /* randomData + decimal nonce. The randomData prefix is folded into the
           shared midstate once per challenge; per candidate we only hash the
           remaining tail plus the nonce (one SHA-256 block in the common case).
           Also avoid the one-shot SHA256(): OpenSSL 3's provider path does not
           scale across threads. */
        size_t tl = j->randomLen - j->prefix;
        char digits[21];
        char *p = digits + sizeof digits;
        unsigned long long v = n;
        do { *--p = (char)('0' + v % 10); v /= 10; } while(v);
        SHA256_CTX c = *j->mid;
        if(tl) SHA256_Update(&c, j->randomData + j->prefix, tl);
        SHA256_Update(&c, p, (size_t)(digits + sizeof digits - p));
        SHA256_Final(h, &c);
        return 1; }
    case ALG_SHA256: {
        uint32_t n32 = (uint32_t)n;
        size_t tl = j->dlen - j->prefix;
        SHA256_CTX c = *j->mid;                 /* state after the fixed data prefix */
        if(tl) SHA256_Update(&c, j->data + j->prefix, tl);
        if(use_le){ nb[0]=n32; nb[1]=n32>>8; nb[2]=n32>>16; nb[3]=n32>>24; }
        else      { nb[0]=n32>>24; nb[1]=n32>>16; nb[2]=n32>>8; nb[3]=n32; }
        SHA256_Update(&c, nb, 4); SHA256_Final(h, &c);
        return 1; }
    case ALG_ARGON2ID: {
        uint64_t n64 = n;
        for(int i=0;i<8;i++) nb[i] = use_le ? (unsigned char)(n64>>(8*i))
                                            : (unsigned char)(n64>>(8*(7-i)));
        return argon2id_derive(actx, j->data, j->dlen, nb, 8, h, 32); }
    case ALG_HASHX:
        return hashx_hash_to_bytes(j->data, j->dlen, n, h);
    default:
        return 0;
    }
}

static int candidate_ok(int alg, const unsigned char *h, int difficulty){
    return (alg == ALG_FAST) ? check_hex(h, difficulty) : check_bits(h, difficulty);
}

static void *solve_worker(void *vp){
    solve_job *j = vp;
    unsigned char h[SHA256_DIGEST_LENGTH], nb[8];
    int use_le = (j->dlen > 0 && j->data[j->dlen-1] >= 128);
    EVP_KDF_CTX *actx = NULL;

    if(j->alg == ALG_ARGON2ID){
        actx = argon2id_ctx_new();
        if(!actx){ j->error = -1; return NULL; }
    }

    unsigned long long attempts = 0;
    for(unsigned long long n = j->tid; n < j->limit; n += j->stride){
        if(atomic_load_explicit(j->found, memory_order_relaxed)) break;
        if(!compute_candidate(j, n, h, nb, actx, use_le)){
            j->error = -1;
            break;
        }
        attempts++;                       /* local: never touch shared cache lines here */
        if(candidate_ok(j->alg, h, j->difficulty)){
            pthread_mutex_lock(j->mu);
            if(!atomic_load_explicit(j->found, memory_order_relaxed)){
                j->result->nonce = n;
                memcpy(j->result->hash, h, SHA256_DIGEST_LENGTH);
                atomic_store_explicit(j->found, 1, memory_order_relaxed);
            }
            pthread_mutex_unlock(j->mu);
            break;
        }
    }

    j->attempts = attempts;
    if(actx) EVP_KDF_CTX_free(actx);
    if(j->alg == ALG_HASHX) hashx_thread_cleanup();
    return NULL;
}

/* returns 1 solved, 0 gave up, -1 error, -2 unsupported algorithm */
static int solve_alg(int alg,const char *randomData,const unsigned char *data,size_t dlen,
                     int difficulty,unsigned long long *nonce_out,unsigned char *hash_out){
    if(difficulty < 0) difficulty = 0;
    if(alg == ALG_UNKNOWN) return -2;

    int nthreads = anubis_threads();
    if(difficulty == 0 && nthreads > 1) nthreads = 1;   /* one hash is enough */

    /* fast's nonce is a decimal string (server parses it as int64); the WASM
       algorithms take a uint32 nonce. */
    unsigned long long limit = (alg == ALG_FAST)
        ? (0x7fffffffffffffffULL - (unsigned long long)nthreads)
        : 0x100000000ULL;

    _Atomic int found = 0;
    pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    solve_result result;
    solve_job jobs[ANUBIS_MAX_THREADS];
    pthread_t tids[ANUBIS_MAX_THREADS];
    int started[ANUBIS_MAX_THREADS];

    /* Fold the constant part of the message (full SHA-256 blocks) into a
       midstate that every lane copies. randomData/data never change while the
       challenge is being solved. */
    SHA256_CTX mid;
    size_t prefix = 0;
    int have_mid = 0;
    if(alg == ALG_FAST || alg == ALG_SHA256){
        const unsigned char *msg = (alg == ALG_FAST)
            ? (const unsigned char*)randomData : data;
        size_t mlen = (alg == ALG_FAST)
            ? (randomData ? strlen(randomData) : 0) : dlen;
        prefix = (mlen / SHA256_CBLOCK) * SHA256_CBLOCK;
        SHA256_Init(&mid);
        if(prefix) SHA256_Update(&mid, msg, prefix);
        have_mid = 1;
    }

    memset(&result, 0, sizeof result);
    for(int i = 0; i < nthreads; i++){
        solve_job *j = &jobs[i];
        memset(j, 0, sizeof *j);
        j->alg        = alg;
        j->randomData = randomData;
        j->data       = data;
        j->dlen       = dlen;
        j->randomLen  = randomData ? strlen(randomData) : 0;
        j->mid        = have_mid ? &mid : NULL;
        j->prefix     = prefix;
        j->difficulty = difficulty;
        j->tid        = (unsigned)i;
        j->nthreads   = (unsigned)nthreads;
        j->stride     = (unsigned long long)nthreads;
        j->limit      = limit;
        j->found      = &found;
        j->mu         = &mu;
        j->result     = &result;
        started[i]    = 0;
    }

    for(int i = 1; i < nthreads; i++){
        if(pthread_create(&tids[i], NULL, solve_worker, &jobs[i]) == 0)
            started[i] = 1;
    }

    solve_worker(&jobs[0]);                          /* lane 0 on the caller */
    for(int i = 1; i < nthreads; i++)
        if(started[i]) pthread_join(tids[i], NULL);

    /* Extremely unlikely: pthread_create failed. Run those lanes serially so
       the challenge still gets solved (just slower). */
    for(int i = 1; i < nthreads; i++)
        if(!started[i] && !atomic_load_explicit(&found, memory_order_relaxed))
            solve_worker(&jobs[i]);

    int err = 0;
    for(int i = 0; i < nthreads; i++) err |= jobs[i].error;

    if(atomic_load_explicit(&found, memory_order_relaxed)){
        if(getenv("FB_DEBUG")){
            unsigned long long total = 0;
            for(int i = 0; i < nthreads; i++) total += jobs[i].attempts;
            fprintf(stderr,"[anubis] threads=%d candidates=%llu nonce=%llu lane=%llu\n",
                    nthreads, total, result.nonce,
                    result.nonce % (unsigned long long)nthreads);
        }
        *nonce_out = result.nonce;
        memcpy(hash_out, result.hash, SHA256_DIGEST_LENGTH);
        return 1;
    }
    return err ? -1 : 0;
}

/* pull out the JSON inside <script id="anubis_challenge" ...> ... </script> */
static char *challenge_json(const char *body){
    const char *p = strstr(body, "anubis_challenge");
    if(!p) return NULL;
    p = strchr(p, '>'); if(!p) return NULL; p++;
    const char *e = strstr(p, "</script>");
    if(!e) return NULL;
    return xstrndup(p, (size_t)(e-p));
}
static char *url_origin(const char *url){
    const char *p = strstr(url, "://"); if(!p) return NULL;
    const char *host = p+3;
    const char *slash = strchr(host, '/');
    size_t n = slash? (size_t)(slash-url) : strlen(url);
    return xstrndup(url, n);
}
static char *url_redir(const char *url){
    const char *p = strstr(url, "://");
    const char *rest = p? strchr(p+3,'/') : (url[0]=='/'? url : NULL);
    if(!rest || !*rest) return xstrdup("/");
    return xstrdup(rest);
}

/* Does JSON array `key` contain the string `val`? (e.g. extensions:["css-load"]) */
static int json_array_has(const char *json, const char *key, const char *val){
    if(!json) return 0;
    char k[64], v[64];
    snprintf(k, sizeof k, "\"%s\"", key);
    snprintf(v, sizeof v, "\"%s\"", val);
    const char *p = strstr(json, k);
    if(!p) return 0;
    p = strchr(p, '[');
    if(!p) return 0;
    const char *e = strchr(p, ']');
    if(!e) return 0;
    const char *m = strstr(p, v);
    return m && m < e;
}

/* Value of a `<script id="ID" type="application/json">...</script>` block. */
static char *script_value(const char *body, const char *id){
    if(!body) return NULL;
    char needle[64];
    snprintf(needle, sizeof needle, "\"%s\"", id);
    const char *p = strstr(body, needle);
    if(!p) return NULL;
    p = strchr(p, '>');
    if(!p) return NULL;
    p++;
    const char *e = strstr(p, "</script>");
    if(!e) return NULL;
    while(p < e && (*p==' '||*p=='\t'||*p=='\n'||*p=='\r')) p++;
    while(e > p && (e[-1]==' '||e[-1]=='\t'||e[-1]=='\n'||e[-1]=='\r')) e--;
    if(p < e && *p=='"'){
        Str s; str_init(&s);
        for(const char *q=p+1; q<e && *q!='"'; q++){
            if(*q=='\\' && q+1<e){
                q++;
                switch(*q){
                case 'n': str_putc(&s,'\n'); break;
                case 't': str_putc(&s,'\t'); break;
                case 'r': str_putc(&s,'\r'); break;
                default:  str_putc(&s,*q); break;
                }
            } else str_putc(&s,*q);
        }
        return s.buf ? s.buf : xstrdup("");
    }
    return xstrndup(p, (size_t)(e-p));
}

/* css-load extension: the server records a challenge as "seen" only after the client
   fetches this route, and refuses the pass-challenge request otherwise. */
char *anubis_css_url(const char *request_url, const char *body){
    if(!anubis_is_challenge(body)) return NULL;
    char *json = challenge_json(body);
    if(!json) return NULL;
    int has = json_array_has(json, "extensions", "css-load");
    char *id = has? json_get_str(json, "id") : NULL;
    free(json);
    if(!id) return NULL;

    char *origin = url_origin(request_url);
    char *prefix = script_value(body, "anubis_base_prefix");
    if(!origin){ free(id); free(prefix); return NULL; }

    Str u; str_init(&u);
    str_printf(&u, "%s%s/.within.website/x/cmd/anubis/ext/css-load/%s",
               origin, prefix?prefix:"", id);
    free(origin); free(prefix); free(id);
    return u.buf;
}

/* metarefresh validates elapsed time, not a hash: the pass request is accepted once
   difficulty*800ms have passed since issuance. We only have the page (not its issue
   time), so wait that long plus a small margin from now. */
long anubis_pass_delay_ms(const char *body){
    if(!anubis_is_challenge(body)) return 0;
    char *json = challenge_json(body);
    if(!json) return 0;
    char *algo = json_get_str(json, "algorithm");
    long diff  = json_get_int(json, "difficulty", 0);
    free(json);
    long ms = 0;
    if(algo && !strcmp(algo, "metarefresh")){
        if(diff < 0) diff = 0;
        if(diff > 60) diff = 60;
        ms = diff * 800 + 300;
    }
    free(algo);
    return ms;
}

char *anubis_pass_url(const char *request_url, const char *body, int *difficulty_out){
    if(!anubis_is_challenge(body)) return NULL;
    char *json = challenge_json(body);
    if(!json) return NULL;
    char *randomData = json_get_str(json,"randomData");
    char *id         = json_get_str(json,"id");
    char *algo       = json_get_str(json,"algorithm");
    int difficulty   = (int)json_get_int(json,"difficulty",0);
    free(json);
    if(!randomData || !id){ free(randomData); free(id); free(algo); return NULL; }
    if(difficulty_out) *difficulty_out = difficulty;

    char *origin = url_origin(request_url);
    char *prefix = script_value(body, "anubis_base_prefix");
    char *redir  = url_redir(request_url);
    if(!origin || !redir){
        free(origin); free(prefix); free(redir);
        free(randomData); free(id); free(algo);
        return NULL;
    }
    char *er = url_escape(redir);

    Str u; str_init(&u);

    if(algo && !strcmp(algo,"metarefresh")){
        /* No hash: the pass URL just carries the challenge token and id. The caller
           waits anubis_pass_delay_ms() first so the server's clock check passes. */
        str_printf(&u, "%s%s/.within.website/x/cmd/anubis/api/pass-challenge"
                       "?challenge=%s&id=%s&redir=%s",
                   origin, prefix?prefix:"", randomData, id, er?er:redir);
        free(origin); free(prefix); free(redir); free(er);
        free(randomData); free(id); free(algo);
        return u.buf;
    }

    int alg = ALG_FAST;
    if(algo){
        if(!strcmp(algo,"fast")||!strcmp(algo,"slow")) alg=ALG_FAST;
        else if(!strcmp(algo,"sha256"))   alg=ALG_SHA256;
        else if(!strcmp(algo,"argon2id")) alg=ALG_ARGON2ID;
        else if(!strcmp(algo,"hashx"))    alg=ALG_HASHX;
        else                              alg=ALG_UNKNOWN;
    }

    unsigned char data[4096];
    size_t dlen = hex_decode(randomData, data, sizeof data);

    unsigned long long nonce=0; unsigned char hash[SHA256_DIGEST_LENGTH];
    int rc = solve_alg(alg, randomData, data, dlen, difficulty, &nonce, hash);
    if(rc!=1){
        fprintf(stderr,"[anubis] can't solve algorithm '%s' (rc=%d)%s\n",
                algo?algo:"fast", rc,
                rc==-2? " — not implemented in C (unknown algorithm)" : "");
        free(origin); free(prefix); free(redir); free(er);
        free(randomData); free(id); free(algo);
        return NULL;
    }

    static const char *HX="0123456789abcdef";
    char hex[2*SHA256_DIGEST_LENGTH+1];
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){ hex[i*2]=HX[hash[i]>>4]; hex[i*2+1]=HX[hash[i]&0x0f]; }
    hex[2*SHA256_DIGEST_LENGTH]=0;

    str_printf(&u, "%s%s/.within.website/x/cmd/anubis/api/pass-challenge"
                   "?id=%s&response=%s&nonce=%llu&redir=%s&elapsedTime=1200",
               origin, prefix?prefix:"", id, hex, nonce, er?er:redir);
    free(origin); free(prefix); free(redir); free(er); free(randomData); free(id); free(algo);
    return u.buf;
}
