/*
 * Native messaging host for the Anubis Native Solver WebExtension.
 *
 * Reads framed JSON from stdin, solves the Anubis challenge with the same
 * code flixbrute uses, and writes framed JSON to stdout.  All diagnostics go
 * to stderr (Firefox forwards them to the browser console).
 *
 * Request:  {"type":"solve","url":"...","challenge":"<raw JSON>","basePrefix":""}
 * Response: {"ok":true,"passUrl":"...","cssUrl":null|"...","delayMs":0,"difficulty":N}
 *           {"ok":false,"error":"..."}
 */
#include "anubis.h"
#include "util.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_MSG (8u * 1024u * 1024u)

static int read_full(void *buf, size_t n) {
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(STDIN_FILENO, p + got, n - got);
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    return 1;
}

static int write_full(const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t put = 0;
    while (put < n) {
        ssize_t w = write(STDOUT_FILENO, p + put, n - put);
        if (w <= 0) return 0;
        put += (size_t)w;
    }
    return 1;
}

static void write_frame(const char *s) {
    uint32_t n = (uint32_t)strlen(s);
    if (!write_full(&n, sizeof n)) return;
    write_full(s, n);
}

static char *json_escape(const char *s) {
    Str out;
    str_init(&out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  str_put(&out, "\\\"", 2); break;
        case '\\': str_put(&out, "\\\\", 2); break;
        case '\n': str_put(&out, "\\n", 2); break;
        case '\r': str_put(&out, "\\r", 2); break;
        case '\t': str_put(&out, "\\t", 2); break;
        default:
            if (*p < 0x20) {
                char tmp[8];
                snprintf(tmp, sizeof tmp, "\\u%04x", *p);
                str_put(&out, tmp, strlen(tmp));
            } else {
                str_putc(&out, (char)*p);
            }
        }
    }
    return out.buf ? out.buf : xstrdup("");
}

/* Append a timing line to ~/anubis-native.log (the host runs as the user, and
   HOME is shared with the snap).  Tiny, synchronous, and useful for demos. */
static void log_timing(const char *url, const char *algo, int diff,
                       double solve_ms, int ok) {
    const char *home = getenv("HOME");
    if (!home) return;
    char path[1024];
    snprintf(path, sizeof path, "%s/anubis-native.log", home);
    FILE *f = fopen(path, "a");
    if (!f) return;
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char tbuf[32];
    strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(f, "%s url=%s algo=%s diff=%d solve_ms=%.1f ok=%d\n",
            tbuf, url, algo ? algo : "?", diff, solve_ms, ok);
    fclose(f);
}

static void fail(const char *msg) {
    char *e = json_escape(msg);
    Str s;
    str_init(&s);
    str_printf(&s, "{\"ok\":false,\"error\":\"%s\"}", e);
    write_frame(s.buf ? s.buf : "{\"ok\":false}");
    str_free(&s);
    free(e);
}

int main(void) {
    uint32_t len;
    while (read_full(&len, sizeof len)) {
        if (len == 0 || len > MAX_MSG) break;

        char *msg = malloc((size_t)len + 1);
        if (!msg) break;
        if (!read_full(msg, len)) {
            free(msg);
            break;
        }
        msg[len] = 0;

        char *challenge = json_get_str(msg, "challenge");
        char *base      = json_get_str(msg, "basePrefix");
        char *url       = json_get_str(msg, "url");

        if (!challenge || !url) {
            fail("missing challenge or url");
            free(challenge); free(base); free(url); free(msg);
            continue;
        }

        /* Rebuild a minimal challenge page so the existing solver/parser can be
           reused unchanged.  "cmd/anubis" makes anubis_is_challenge() happy. */
        size_t cap = strlen(challenge) + strlen(base ? base : "") + 256;
        char *body = malloc(cap);
        if (!body) {
            fail("out of memory");
            free(challenge); free(base); free(url); free(msg);
            continue;
        }
        snprintf(body, cap,
                 "<script id=\"anubis_challenge\" type=\"application/json\">%s</script>\n"
                 "<script id=\"anubis_base_prefix\" type=\"application/json\">\"%s\"</script>\n"
                 "<!-- cmd/anubis not a bot -->\n",
                 challenge, base ? base : "");

        int difficulty = 0;
        char *algo = json_get_str(challenge, "algorithm");
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        char *pass = anubis_pass_url(url, body, &difficulty);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double solve_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                          (t1.tv_nsec - t0.tv_nsec) / 1e6;
        log_timing(url, algo, difficulty, solve_ms, pass != NULL);
        free(algo);

        if (!pass) {
            fail("solve failed (unsupported algorithm?)");
        } else {
            long delay_ms = anubis_pass_delay_ms(body);
            char *css = anubis_css_url(url, body);
            char *p = json_escape(pass);
            char *c = css ? json_escape(css) : NULL;

            Str s;
            str_init(&s);
            if (c) {
                str_printf(&s, "{\"ok\":true,\"passUrl\":\"%s\",\"cssUrl\":\"%s\","
                               "\"delayMs\":%ld,\"difficulty\":%d}",
                           p, c, delay_ms, difficulty);
            } else {
                str_printf(&s, "{\"ok\":true,\"passUrl\":\"%s\",\"cssUrl\":null,"
                               "\"delayMs\":%ld,\"difficulty\":%d}",
                           p, delay_ms, difficulty);
            }
            write_frame(s.buf ? s.buf : "{\"ok\":false}");
            str_free(&s);
            free(p); free(c); free(css); free(pass);
        }

        free(body);
        free(challenge); free(base); free(url); free(msg);
    }
    return 0;
}
