#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

void *xmalloc(size_t n){ void *p = malloc(n?n:1); if(!p){ fprintf(stderr,"oom\n"); exit(1);} return p; }
void *xcalloc(size_t n, size_t sz){ void *p = calloc(n?n:1, sz?sz:1); if(!p){ fprintf(stderr,"oom\n"); exit(1);} return p; }
void *xrealloc(void *p, size_t n){ void *q = realloc(p, n?n:1); if(!q){ fprintf(stderr,"oom\n"); exit(1);} return q; }
char *xstrdup(const char *s){ if(!s) return NULL; size_t n=strlen(s); char *p=xmalloc(n+1); memcpy(p,s,n+1); return p; }
char *xstrndup(const char *s, size_t n){ char *p=xmalloc(n+1); memcpy(p,s,n); p[n]='\0'; return p; }

void str_init(Str *s){ s->buf=NULL; s->len=0; s->cap=0; }
void str_free(Str *s){ free(s->buf); s->buf=NULL; s->len=s->cap=0; }
static void str_reserve(Str *s, size_t extra){
    if (s->len + extra + 1 <= s->cap) return;
    size_t nc = s->cap? s->cap : 64;
    while (nc < s->len + extra + 1) nc *= 2;
    s->buf = xrealloc(s->buf, nc); s->cap = nc;
}
void str_put(Str *s, const char *d, size_t n){ str_reserve(s,n); memcpy(s->buf+s->len,d,n); s->len+=n; s->buf[s->len]='\0'; }
void str_puts(Str *s, const char *c){ if(c) str_put(s,c,strlen(c)); }
void str_putc(Str *s, char c){ str_put(s,&c,1); }
void str_printf(Str *s, const char *fmt, ...){
    va_list ap; va_start(ap,fmt);
    va_list ap2; va_copy(ap2,ap);
    int n = vsnprintf(NULL,0,fmt,ap); va_end(ap);
    if(n<0){ va_end(ap2); return; }
    str_reserve(s,(size_t)n);
    vsnprintf(s->buf+s->len,(size_t)n+1,fmt,ap2); va_end(ap2);
    s->len += (size_t)n;
}

void pv_init(PtrVec *v){ v->item=NULL; v->len=0; v->cap=0; }
void pv_push(PtrVec *v, void *p){
    if(v->len==v->cap){ v->cap = v->cap? v->cap*2 : 8; v->item = xrealloc(v->item, v->cap*sizeof(void*)); }
    v->item[v->len++] = p;
}
void pv_free(PtrVec *v){ free(v->item); v->item=NULL; v->len=v->cap=0; }

int str_starts(const char *s, const char *pre){ return strncmp(s,pre,strlen(pre))==0; }
int str_contains(const char *s, const char *sub){ return s && strstr(s,sub)!=NULL; }

/* ---- minimal JSON ---- */
static const char *json_find_key(const char *json, const char *key){
    if(!json) return NULL;
    size_t klen = strlen(key);
    const char *p = json;
    while((p = strchr(p,'"'))!=NULL){
        p++;
        if(strncmp(p,key,klen)==0 && p[klen]=='"'){
            const char *q = p + klen + 1;
            while(*q==' '||*q=='\t'||*q=='\n'||*q=='\r') q++;
            if(*q==':') return q+1;
        }
    }
    return NULL;
}
char *json_get_str(const char *json, const char *key){
    const char *p = json_find_key(json,key);
    if(!p) return NULL;
    while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r') p++;
    if(*p=='"'){
        p++;
        Str s; str_init(&s);
        while(*p && *p!='"'){
            if(*p=='\\' && p[1]){
                p++;
                switch(*p){ case 'n': str_putc(&s,'\n'); break; case 't': str_putc(&s,'\t'); break;
                            case 'r': str_putc(&s,'\r'); break; default: str_putc(&s,*p); }
            } else str_putc(&s,*p);
            p++;
        }
        return s.buf ? s.buf : xstrdup("");
    }
    /* literal (number / true / false / null) */
    const char *q = p;
    while(*q && *q!=',' && *q!='}' && *q!=']' && *q!=' ') q++;
    return xstrndup(p, (size_t)(q-p));
}
long json_get_int(const char *json, const char *key, long dflt){
    char *s = json_get_str(json,key);
    if(!s) return dflt;
    long v = strtol(s,NULL,10);
    free(s);
    return v;
}

/* locate `key` belonging to the root object of `json` (depth 1). Nested objects
   and arrays are skipped, so a key that also appears deeper in the document (or a
   sibling object's field) won't win by appearing first. Returns a pointer just
   past the ':' of a matched root-level key, or NULL. */
static const char *json_find_key_top(const char *json, const char *key){
    if(!json) return NULL;
    const char *p = json;
    while(*p && *p!='{' && *p!='[') p++;
    if(*p!='{') return NULL;
    size_t klen = strlen(key);
    int depth = 0;
    for(; *p; p++){
        char c = *p;
        if(c=='"'){
            const char *ks = p+1;                       /* start of the string body */
            const char *e = ks;
            while(*e){ if(*e=='\\' && e[1]){ e+=2; continue; } if(*e=='"') break; e++; }
            const char *q = e+1;
            while(*q==' '||*q=='\t'||*q=='\n'||*q=='\r') q++;
            if(depth==1 && *q==':' && (size_t)(e-ks)==klen && strncmp(ks,key,klen)==0)
                return q+1;
            p = e;                                      /* continue after the string */
            continue;
        }
        if(c=='{'||c=='[') depth++;
        else if(c=='}'||c==']'){ depth--; if(depth<=0) break; }
    }
    return NULL;
}
char *json_get_str_top(const char *json, const char *key){
    const char *p = json_find_key_top(json,key);
    if(!p) return NULL;
    while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r') p++;
    if(*p=='"'){
        p++;
        Str s; str_init(&s);
        while(*p && *p!='"'){
            if(*p=='\\' && p[1]){
                p++;
                switch(*p){ case 'n': str_putc(&s,'\n'); break; case 't': str_putc(&s,'\t'); break;
                            case 'r': str_putc(&s,'\r'); break; default: str_putc(&s,*p); }
            } else str_putc(&s,*p);
            p++;
        }
        return s.buf ? s.buf : xstrdup("");
    }
    const char *q = p;
    while(*q && *q!=',' && *q!='}' && *q!=']' && *q!=' ') q++;
    return xstrndup(p, (size_t)(q-p));
}

char *html_attr(const char *html, const char *attr){
    if(!html) return NULL;
    size_t alen = strlen(attr);
    const char *p = html;
    while((p = strstr(p, attr))!=NULL){
        const char *q = p + alen;
        /* must be followed by optional ws then '=' ; ensure not part of a longer name */
        if(p>html && (isalnum((unsigned char)p[-1])||p[-1]=='-'||p[-1]=='_')){ p=q; continue; }
        while(*q==' '||*q=='\t') q++;
        if(*q!='='){ p=q; continue; }
        q++;
        while(*q==' '||*q=='\t') q++;
        char quote = 0;
        if(*q=='"'||*q=='\''){ quote=*q; q++; }
        if(quote){
            const char *e = strchr(q,quote);
            if(!e) return NULL;
            return xstrndup(q,(size_t)(e-q));
        } else {
            const char *e=q; while(*e && *e!=' ' && *e!='>' && *e!='\t') e++;
            return xstrndup(q,(size_t)(e-q));
        }
    }
    return NULL;
}

char *url_join(const char *base, const char *ref){
    if(!ref) return NULL;
    if(str_starts(ref,"http://")||str_starts(ref,"https://")) return xstrdup(ref);
    if(str_starts(ref,"//")){
        const char *s = strstr(base,"://");
        if(!s) return xstrdup(ref);
        size_t sl = (size_t)(s-base);
        Str o; str_init(&o); str_put(&o,base,sl); str_puts(&o,":"); str_puts(&o,ref); return o.buf;
    }
    /* scheme://host */
    const char *s = strstr(base,"://");
    if(!s) return xstrdup(ref);
    const char *host = s+3;
    const char *slash = strchr(host,'/');
    size_t hostlen = slash ? (size_t)(slash-host) : strlen(host);
    Str o; str_init(&o);
    if(*ref=='/'){
        str_put(&o, base, (size_t)(host-base)+hostlen);
        str_puts(&o, ref);
        return o.buf;
    }
    const char *pathstart = host + hostlen;
    const char *lastslash = strrchr(pathstart, '/');
    if(lastslash){
        size_t n = (size_t)(lastslash - base) + 1;
        if(n > strlen(base)) n = strlen(base);
        str_put(&o, base, n);
    } else { str_put(&o, base, (size_t)(host-base)+hostlen); str_putc(&o,'/'); }
    str_puts(&o, ref);
    return o.buf;
}

char *url_escape(const char *s){
    static const char *hex="0123456789ABCDEF";
    Str o; str_init(&o);
    for(const unsigned char *p=(const unsigned char*)s; p && *p; p++){
        unsigned char c=*p;
        if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~')
            str_putc(&o,(char)c);
        else { char e[3]={'%',hex[c>>4],hex[c&15]}; str_put(&o,e,3); }
    }
    return o.buf ? o.buf : xstrdup("");
}
