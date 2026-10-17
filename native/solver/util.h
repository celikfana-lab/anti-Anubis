#ifndef FB_UTIL_H
#define FB_UTIL_H
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define FB_VERSION "0.1"

/* Runtime debug logging. Production builds (`make prod`, AppImage) define
   FB_NO_DEBUG, so the checks and format strings are compiled out entirely;
   default and `make debug` builds keep FB_DEBUG=1. */
#if defined(FB_NO_DEBUG)
#define FB_DEBUG_ON() 0
#define FB_DEBUG_LOG(...) ((void)0)
#else
#define FB_DEBUG_ON() (getenv("FB_DEBUG") != NULL)
#define FB_DEBUG_LOG(...) do { if(getenv("FB_DEBUG")) fprintf(stderr, __VA_ARGS__); } while (0)
#endif

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

/* growable string */
typedef struct { char *buf; size_t len, cap; } Str;
void  str_init(Str *s);
void  str_free(Str *s);
void  str_put(Str *s, const char *data, size_t n);
void  str_puts(Str *s, const char *c);
void  str_putc(Str *s, char c);
void  str_printf(Str *s, const char *fmt, ...);

/* growable pointer vector */
typedef struct { void **item; size_t len, cap; } PtrVec;
void pv_init(PtrVec *v);
void pv_push(PtrVec *v, void *p);
void pv_free(PtrVec *v);

int   str_starts(const char *s, const char *pre);
int   str_contains(const char *s, const char *sub);

/* tiny JSON helpers (first occurrence) */
char *json_get_str(const char *json, const char *key);
long  json_get_int(const char *json, const char *key, long dflt);
/* same, but only matches the key on the ROOT object (skips nested objects/arrays).
   Needed for API payloads whose keys are sorted, e.g. a TMDB TV response carries
   created_by[0].name before its own top-level name. */
char *json_get_str_top(const char *json, const char *key);
/* first attr="value" (single or double quotes) from html/text */
char *html_attr(const char *html, const char *attr);
/* resolve a possibly-relative ref against an absolute base URL */
char *url_join(const char *base, const char *ref);
/* percent-encode a string for use in a query value */
char *url_escape(const char *s);

#endif
