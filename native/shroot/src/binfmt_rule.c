#include "binfmt_rule.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int hex(unsigned char c) {
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return -1;
}
static int decode(const char *s,unsigned char *out,size_t capacity) {
    unsigned n=0;
    while (*s) {
        unsigned char c=(unsigned char)*s++;
        if (c=='\\' && s[0]=='x') {
            if (!s[1] || !s[2] || hex(s[1])<0 || hex(s[2])<0) return -EINVAL;
            c=(unsigned char)((hex(s[1])<<4)|hex(s[2])); s+=3;
        }
        if (n==capacity) return -EINVAL;
        out[n++]=c;
    }
    return (int)n;
}
int md_binfmt_rule_parse(const void *data,size_t size,struct md_binfmt_rule *out) {
    if (!data || !size || size>MD_BINFMT_REGISTER_MAX || memchr(data,0,size)) return -EINVAL;
    char text[MD_BINFMT_REGISTER_MAX+1];
    memcpy(text,data,size); text[size]=0;
    if (text[size-1]=='\n') text[--size]=0;
    if (!size) return -EINVAL;
    unsigned char delimiter=text[0];
    if (!delimiter || delimiter=='\n') return -EINVAL;
    char *fields[7], *cursor=text+1;
    for (unsigned i=0;i<7;++i) {
        fields[i]=cursor;
        if (i==6) break;
        char *next=strchr(cursor,delimiter);
        if (!next) return -EINVAL;
        *next=0; cursor=next+1;
    }
    struct md_binfmt_rule r={0};
    size_t name=strlen(fields[0]), interpreter=strlen(fields[5]);
    if (!name || name>NAME_MAX || strchr(fields[0],'/') || !strcmp(fields[0],".")
            || !strcmp(fields[0],"..") || !interpreter || fields[5][0]!='/'
            || interpreter>=sizeof(r.interpreter)) return -EINVAL;
    if (fields[1][1] || (fields[1][0]!='M' && fields[1][0]!='E')) return -EINVAL;
    memcpy(r.name,fields[0],name+1); memcpy(r.interpreter,fields[5],interpreter+1);
    r.extension=fields[1][0]=='E';
    if (r.extension) {
        size_t n=strlen(fields[3]);
        if (!n || n>=sizeof(r.magic) || strchr(fields[3],'/')) return -EINVAL;
        memcpy(r.magic,fields[3],n+1); r.size=(unsigned)n;
    } else {
        for (const char *p=fields[2];*p;++p) {
            if (*p<'0' || *p>'9' || r.offset>=MD_BINFMT_HEADER) return -EINVAL;
            r.offset=r.offset*10+(unsigned)(*p-'0');
        }
        int n=decode(fields[3],r.magic,sizeof(r.magic));
        if (n<=0 || r.offset+(unsigned)n>MD_BINFMT_HEADER) return -EINVAL;
        r.size=(unsigned)n;
        memset(r.mask,255,r.size);
        if (*fields[4] && decode(fields[4],r.mask,sizeof(r.mask))!=n) return -EINVAL;
    }
    for (const char *p=fields[6];*p;++p) {
        unsigned flag=*p=='P' ? MD_BINFMT_PRESERVE : *p=='O' ? MD_BINFMT_OPEN
            : *p=='C' ? MD_BINFMT_CREDENTIALS : *p=='F' ? MD_BINFMT_FIXED : 0;
        if (!flag || (r.flags&flag)) return -EINVAL;
        r.flags|=flag;
    }
    if (r.flags&MD_BINFMT_CREDENTIALS) r.flags|=MD_BINFMT_OPEN;
    *out=r; return 0;
}
int md_binfmt_rule_matches(const struct md_binfmt_rule *r,const char *path,const void *header,size_t size) {
    if (r->extension) {
        const char *base=strrchr(path,'/'); base=base ? base+1 : path;
        const char *dot=strrchr(base,'.');
        return dot && !strcmp(dot+1,(const char *)r->magic);
    }
    if (r->offset+r->size>size) return 0;
    const unsigned char *p=(const unsigned char *)header+r->offset;
    for (unsigned i=0;i<r->size;++i) if ((p[i]^r->magic[i])&r->mask[i]) return 0;
    return 1;
}
int md_binfmt_rule_format(const struct md_binfmt_rule *r,int enabled,char *out,size_t capacity) {
    char flags[5],magic[MD_BINFMT_HEADER*2+1],mask[MD_BINFMT_HEADER*2+1];
    unsigned n=0;
    if (r->flags&MD_BINFMT_PRESERVE) flags[n++]='P';
    if (r->flags&MD_BINFMT_OPEN) flags[n++]='O';
    if (r->flags&MD_BINFMT_CREDENTIALS) flags[n++]='C';
    if (r->flags&MD_BINFMT_FIXED) flags[n++]='F';
    flags[n]=0;
    static const char digits[]="0123456789abcdef";
    for (unsigned i=0;i<r->size;++i) {
        magic[i*2]=digits[r->magic[i]>>4]; magic[i*2+1]=digits[r->magic[i]&15];
        mask[i*2]=digits[r->mask[i]>>4]; mask[i*2+1]=digits[r->mask[i]&15];
    }
    magic[r->size*2]=mask[r->size*2]=0;
    int written=snprintf(out,capacity,"%s\ninterpreter %s\nflags: %s\n",enabled ? "enabled" : "disabled",r->interpreter,flags);
    if (written<0 || (size_t)written>=capacity) return -ENOSPC;
    int tail=r->extension ? snprintf(out+written,capacity-(size_t)written,"extension .%s\n",r->magic)
        : snprintf(out+written,capacity-(size_t)written,"offset %u\nmagic %s\nmask %s\n",r->offset,magic,mask);
    if (tail<0 || (size_t)tail>=capacity-(size_t)written) return -ENOSPC;
    return written+tail;
}
