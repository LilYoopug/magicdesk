#define _GNU_SOURCE
#include "network_resolver.h"
#include "network_profile.h"
#include "fs_service.h"
#include "fs_mounts.h"
#include "fs_mount_internal.h"
#include "file_open.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int md_network_resolver_prepare(struct md_filesystem *fs,const struct md_network_profile *profile) {
    if (!profile || (!profile->dns_count && profile->policy!=MD_NETWORK_BRIDGE)) return 0;
    char contents[16384];
    size_t size=0;
    if (profile->dns_count) {
        for (unsigned i=0;i<profile->dns_count;++i)
            size+=(size_t)snprintf(contents+size,sizeof(contents)-size,"nameserver %s\n",profile->dns[i]);
    } else {
        struct md_view_location source;
        int error=md_view_walk(fs,MD_INODE_ROOT,NULL,"/etc/resolv.conf",1,0,0,&source);
        if (error) return error;
        struct stat st;
        if (fstat(source.fd,&st)) error=-errno;
        else if (!S_ISREG(st.st_mode)) error=-EINVAL;
        struct md_open_completion completion;
        int fd=error ? error : md_reopen_file(source.fd,O_RDONLY|O_CLOEXEC,&completion);
        md_view_location_close(&source);
        if (fd<0) return fd;
        char original[sizeof(contents)];
        ssize_t n;
        do { n=pread(fd,original,sizeof(original)-1,0); } while (n<0 && errno==EINTR);
        error=n<0 ? -errno : n==(ssize_t)sizeof(original)-1 ? -E2BIG : 0;
        close(fd);
        if (error) return error;
        original[n]=0;
        unsigned servers=0;
        for (char *line=original;*line;) {
            char *end=strchr(line,'\n');
            size_t length=end ? (size_t)(end-line)+1 : strlen(line);
            char *word=line;
            while (*word==' ' || *word=='\t') ++word;
            int keep=1;
            if (!strncmp(word,"nameserver",10) && (word[10]==' ' || word[10]=='\t')) {
                word+=10;
                while (*word==' ' || *word=='\t') ++word;
                char ip[16]; size_t count=strcspn(word," \t\r\n#;");
                uint32_t address=0;
                keep=count && count<sizeof(ip);
                if (keep) {
                    memcpy(ip,word,count); ip[count]=0;
                    keep=!md_network_profile_ipv4(ip,&address);
                    unsigned first=((unsigned char *)&address)[0];
                    keep=keep && first && first!=127 && first<224;
                }
                if (keep) ++servers;
            }
            if (keep) { memcpy(contents+size,line,length); size+=length; }
            line+=length;
        }
        /* A loopback stub in a different launch cannot serve this namespace.
         * Never silently fall back to a public third-party DNS service. */
        if (!servers) return -EDESTADDRREQ;
    }
    return md_fs_mount_contents(fs,"/etc/resolv.conf",contents,size);
}
