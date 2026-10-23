#ifndef MD_BINFMT_RULE_H
#define MD_BINFMT_RULE_H
#include <stddef.h>
#include <limits.h>

enum { MD_BINFMT_REGISTER_MAX=1920, MD_BINFMT_HEADER=256 };
enum { MD_BINFMT_PRESERVE=1, MD_BINFMT_OPEN=2, MD_BINFMT_CREDENTIALS=4, MD_BINFMT_FIXED=8 };
/* Immutable, fully decoded registration. Neither matching nor argv assembly
 * interprets the registration language a second time. */
struct md_binfmt_rule {
    char name[NAME_MAX+1], interpreter[MD_BINFMT_REGISTER_MAX];
    unsigned flags, offset, size;
    int extension;
    unsigned char magic[MD_BINFMT_HEADER], mask[MD_BINFMT_HEADER];
};
int md_binfmt_rule_parse(const void *,size_t,struct md_binfmt_rule *);
int md_binfmt_rule_matches(const struct md_binfmt_rule *,const char *path,const void *,size_t);
int md_binfmt_rule_format(const struct md_binfmt_rule *,int enabled,char *,size_t);
#endif
