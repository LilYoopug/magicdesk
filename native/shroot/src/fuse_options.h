#ifndef MD_FUSE_OPTIONS_H
#define MD_FUSE_OPTIONS_H
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
enum { MD_FUSE_IO_SIZE=16384 };
struct md_fuse_options {
    int descriptor;
    uint32_t rootmode,uid,gid,max_read;
    int allow_other,default_permissions;
};
/* Shared with the freestanding syscall adapter: no allocation or libc calls. */
static inline int md_fuse_option_key(const char *text,size_t length,const char *key) {
    for (size_t i=0;i<length;++i) if (!key[i] || text[i]!=key[i]) return 0;
    return !key[length];
}
static inline int md_fuse_options_parse(const char *text,struct md_fuse_options *out) {
    *out=(struct md_fuse_options){.descriptor=-1,.max_read=MD_FUSE_IO_SIZE};
    unsigned seen=0;
    if (!text || !*text) return -EINVAL;
    for (const char *at=text;*at;) {
        const char *end=at,*equal=NULL;
        while (*end && *end!=',') { if (*end=='=' && !equal) equal=end; ++end; }
        size_t length=(size_t)(end-at);
        if (!equal) {
            if (md_fuse_option_key(at,length,"allow_other")) out->allow_other=1;
            else if (md_fuse_option_key(at,length,"default_permissions")) out->default_permissions=1;
            else return -EINVAL;
        } else {
            size_t key=(size_t)(equal-at); unsigned field;
            if (md_fuse_option_key(at,key,"fd")) field=0;
            else if (md_fuse_option_key(at,key,"rootmode")) field=1;
            else if (md_fuse_option_key(at,key,"user_id")) field=2;
            else if (md_fuse_option_key(at,key,"group_id")) field=3;
            else if (md_fuse_option_key(at,key,"max_read")) field=4;
            else return -EINVAL;
            unsigned base=field==1 ? 8 : 10; uint32_t value=0;
            if (equal+1==end) return -EINVAL;
            for (const char *p=equal+1;p<end;++p) {
                unsigned digit=(unsigned char)*p-'0';
                if (digit>=base || value>(UINT32_MAX-digit)/base) return -EINVAL;
                value=value*base+digit;
            }
            switch (field) {
            case 0: if (value>INT_MAX) return -EINVAL; out->descriptor=(int)value; break;
            case 1: if ((value&S_IFMT)!=S_IFDIR || value&~(S_IFMT|07777U)) return -EINVAL; out->rootmode=value; break;
            case 2: out->uid=value; break;
            case 3: out->gid=value; break;
            case 4: out->max_read=value && value<MD_FUSE_IO_SIZE ? value : MD_FUSE_IO_SIZE; break;
            }
            seen|=1U<<field;
        }
        at=*end ? end+1 : end;
        if (*end && !*at) return -EINVAL;
    }
    return (seen&15)==15 ? 0 : -EINVAL;
}
#endif
