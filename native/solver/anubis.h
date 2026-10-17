#ifndef FB_ANUBIS_H
#define FB_ANUBIS_H

/* 1 if the body is an Anubis anti-bot challenge page */
int anubis_is_challenge(const char *body);

/* If `body` is an Anubis challenge for `request_url`, return the malloc'd URL of the
   css-load probe that must be fetched before the pass-challenge request (the `css-load`
   challenge extension refuses clients that never hit it); NULL when the extension is
   not enabled. */
char *anubis_css_url(const char *request_url, const char *body);

/* Milliseconds to wait before hitting the pass-challenge URL. Non-zero only for the
   `metarefresh` challenge, which validates elapsed time instead of a hash. */
long anubis_pass_delay_ms(const char *body);

/* If `body` is an Anubis challenge for `request_url`, solve the proof-of-work (or
   prepare the timed metarefresh pass) and return the malloc'd pass-challenge URL to GET
   (with the same cookie jar); NULL otherwise.
   `difficulty_out` (optional) receives the challenge difficulty. */
char *anubis_pass_url(const char *request_url, const char *body, int *difficulty_out);

#endif
