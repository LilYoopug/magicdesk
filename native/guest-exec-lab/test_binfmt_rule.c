#include "binfmt_rule.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int parse(const char *text,struct md_binfmt_rule *r) { return md_binfmt_rule_parse(text,strlen(text),r); }
int main(void) {
    struct md_binfmt_rule r;
    assert(!parse(":elf:M:1:ELF:\\xff\\xff\\xfe:/usr/bin/qemu:POCF\n",&r));
    assert(r.offset==1 && r.size==3 && r.flags==15);
    assert(md_binfmt_rule_matches(&r,"a","\177ELG",4));
    assert(!md_binfmt_rule_matches(&r,"a","\177ELF",3));
    assert(!md_binfmt_rule_matches(&r,"a","\177ELD",4));
    char output[4096];
    assert(md_binfmt_rule_format(&r,1,output,sizeof(output))>0);
    assert(strstr(output,"flags: POCF\n") && strstr(output,"magic 454c46\n"));
    assert(!parse(":ext:E::exe::/bin/loader:C",&r));
    assert(r.flags==(MD_BINFMT_OPEN|MD_BINFMT_CREDENTIALS));
    assert(md_binfmt_rule_matches(&r,"/a.b/c.exe",NULL,0));
    assert(!md_binfmt_rule_matches(&r,"/a.exe/c",NULL,0));
    assert(!md_binfmt_rule_matches(&r,"/a.EXE",NULL,0));
    const char *bad[]={"",":a:M:256:a::/bin/x:",":a:M:255:ab::/bin/x:",
        ":a:M:-1:a::/bin/x:",":a:M:99999999999:a::/bin/x:",":a:M::a:ab:/bin/x:",
        ":a:M::::/bin/x:",":a:M::\\xg0::/bin/x:",":a:M::\\x0::/bin/x:",
        ":a:M::a::/bin/x:Z",":a:M::a::/bin/x:PP",":.:M::a::/bin/x:",
        ":../x:E::exe::/bin/x:",":a:E::x/y::/bin/x:",":a:M::a:::",":a:MM::a::/bin/x:"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(*bad);++i) assert(parse(bad[i],&r)==-EINVAL);
    assert(md_binfmt_rule_parse(":a\0b",5,&r)==-EINVAL);
    puts("PASS binfmt registration grammar, masks, flags, extension and bounded formatting");
}
