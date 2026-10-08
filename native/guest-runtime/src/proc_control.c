#define _GNU_SOURCE
#include "proc_control.h"
#include "proc_file.h"
#include "fd_filter.h"
#include "adapter_buffer.h"
#include "interception.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <linux/stat.h>
#include <linux/magic.h>
#include <linux/nsfs.h>

long md_proc_control_known(int fd) {
#ifdef MD_USE_LIBC
    (void)fd; return 0;
#else
    return RAW4(prctl,MD_GUEST_PROC_FILE,MD_PROC_FILE_KIND,fd,0);
#endif
}
static long control_open(unsigned operation, int process, int selector, int flags) {
    long memory=0;
#ifndef MD_USE_LIBC
    if (flags&O_PATH) {
        memory=md_adapter_buffer_take();
        if (memory<0) return memory;
    }
#endif
    long fd=RAW5(prctl,MD_GUEST_PROC_FILE,operation,process,selector,flags);
#ifndef MD_USE_LIBC
    if (memory) {
        if (fd>=0) fd=md_adapter_receive_fd((void *)memory,(unsigned)flags,MD_BUFFER_PROC_RIGHTS);
        long released=md_adapter_buffer_release();
        if (released<0) { if (fd>=0) RAW1(close,fd); return released; }
    }
#else
    (void)memory;
#endif
    if (fd<0) return fd;
    long result=md_fd_filter_arm(MD_FD_SELECTOR_PROC,(int)fd);
    if (result<0) { RAW1(close,fd); return result; }
    return fd;
}
long md_proc_control_open(int process, enum md_proc_kind kind, int flags) {
    return control_open(MD_PROC_FILE_OPEN,process,kind,flags);
}
long md_proc_control_reopen(int process, int fd, int flags) {
    return control_open(MD_PROC_FILE_REOPEN,process,fd,flags);
}
long md_proc_control_metadata(int process, enum md_proc_kind kind, int fd, long nr, const unsigned long *a) {
#ifdef MD_USE_LIBC
    (void)process; (void)kind; (void)fd; (void)nr; (void)a; return -ENOTSUP;
#else
    struct md_proc_metadata_request query={.process=process,.descriptor=fd,.kind=kind,.effective=1};
    int access=nr==SYS_faccessat || nr==SYS_faccessat2;
    if (access) {
        if (a[2]&~7UL || (nr==SYS_faccessat2 && a[3]&~(AT_EACCESS|AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW))) return -EINVAL;
        query.access=(uint32_t)a[2]; query.effective=nr==SYS_faccessat2 && (a[3]&AT_EACCESS);
    } else if (nr==SYS_statx) {
        if (a[2]&~(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT|AT_STATX_SYNC_TYPE)
                || (a[2]&AT_STATX_SYNC_TYPE)==AT_STATX_SYNC_TYPE || (a[3]&STATX__RESERVED)) return -EINVAL;
    } else if (nr==SYS_newfstatat && (a[3]&~(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT))) return -EINVAL;
    query.nofollow=(nr==SYS_newfstatat || nr==SYS_faccessat2) ? !!(a[3]&AT_SYMLINK_NOFOLLOW)
        : nr==SYS_statx ? !!(a[2]&AT_SYMLINK_NOFOLLOW) : 0;
    long memory=md_adapter_buffer_take();
    if (memory<0) return memory;
    memcpy((void *)memory,&query,sizeof(query));
    long result=md_guest_buffer_control(MD_BUFFER_PROC_META,0,0);
    if (!result && !access) {
        struct md_proc_metadata_result metadata; memcpy(&metadata,(void *)memory,sizeof(metadata));
        struct stat st=metadata.value;
        int namespace=md_proc_file_namespace(metadata.kind);
        if (nr==SYS_fstat || nr==SYS_newfstatat)
            result=md_write_memory((void *)a[nr==SYS_fstat ? 1 : 2],&st,sizeof(st));
        else if (nr==SYS_statx) {
            struct statx value={.stx_mask=STATX_BASIC_STATS,.stx_blksize=(uint32_t)st.st_blksize,
                .stx_nlink=(uint32_t)st.st_nlink,.stx_uid=st.st_uid,.stx_gid=st.st_gid,
                .stx_mode=(uint16_t)st.st_mode,.stx_ino=st.st_ino,.stx_size=(uint64_t)st.st_size,
                .stx_dev_major=major(st.st_dev),.stx_dev_minor=minor(st.st_dev),
                .stx_atime={st.st_atim.tv_sec,(uint32_t)st.st_atim.tv_nsec,0},
                .stx_mtime={st.st_mtim.tv_sec,(uint32_t)st.st_mtim.tv_nsec,0},
                .stx_ctime={st.st_ctim.tv_sec,(uint32_t)st.st_ctim.tv_nsec,0}};
            result=md_write_memory((void *)a[4],&value,sizeof(value));
        } else if (nr==SYS_statfs || nr==SYS_fstatfs) {
            struct statfs value={.f_type=namespace ? NSFS_MAGIC : PROC_SUPER_MAGIC,
                .f_bsize=md_page_size,.f_namelen=255,.f_frsize=md_page_size};
            result=md_write_memory((void *)a[1],&value,sizeof(value));
        } else if (nr==SYS_readlinkat) {
            if (!namespace || !a[3]) result=-EINVAL;
            else {
                char label[64]; md_copy(label,sizeof(label),md_proc_file_namespace_name(metadata.kind));
                md_append(label,sizeof(label),":["); md_decimal(label+md_length(label),st.st_ino);
                md_append(label,sizeof(label),"]");
                size_t length=md_length(label); if (length>a[3]) length=a[3];
                result=md_write_memory((void *)a[2],label,length);
                if (!result) result=(long)length;
            }
        }
        else if (nr==SYS_fchdir && md_proc_file_directory(metadata.kind)) result=RAW1(fchdir,fd);
        else if (nr==SYS_chdir && md_proc_file_directory(metadata.kind)) {
            char path[64]="/proc/"; md_decimal(path+md_length(path),(unsigned)process);
            if (metadata.kind==MD_PROC_FILE_NS_DIRECTORY) md_append(path,sizeof(path),"/ns");
            result=RAW1(chdir,path);
        }
        else if (nr==SYS_getdents64 || nr==SYS_chdir || nr==SYS_fchdir) result=-ENOTDIR;
        else result=-EPERM;
    }
    long released=md_adapter_buffer_release();
    return result ? result : released;
#endif
}
long md_proc_control_call(long nr, const unsigned long *a) {
#ifdef MD_USE_LIBC
    (void)nr; (void)a; return MD_WATCH_NATIVE;
#else
    long active=md_guest_buffer_control(MD_BUFFER_PROC_CHECK,0,0);
    if (active<=0) return active<0 ? active : MD_WATCH_NATIVE;
    if (nr==SYS_ioctl) {
        if (!md_proc_file_namespace((enum md_proc_file_kind)(active-1))) return -ENOTTY;
        long value=RAW5(prctl,MD_GUEST_PROC_FILE,MD_PROC_FILE_NAMESPACE_QUERY,a[0],a[1],0);
        if (value>=0 && a[1]==NS_GET_OWNER_UID) {
            uint32_t uid=(uint32_t)value;
            return md_write_memory((void *)a[2],&uid,sizeof(uid));
        }
        if (value>=0 && (a[1]==NS_GET_USERNS || a[1]==NS_GET_PARENT)) {
            long armed=md_fd_filter_arm(MD_FD_SELECTOR_PROC,(int)value);
            if (armed<0) { RAW1(close,value); return armed; }
        }
        return value;
    }
    int sysctl=md_proc_file_sysctl((enum md_proc_file_kind)(active-1));
    struct md_proc_io_spec spec;
    long decoded=md_proc_io_decode(nr,a,&spec);
    if (decoded) return decoded;
    int writing=spec.writing, vector=spec.vector;
    struct iovec vectors[1024]; unsigned count=1;
    if (nr==SYS_lseek) count=0;
    else if (!vector) vectors[0]=(struct iovec){(void *)a[1],a[2]};
    else {
        if (a[2]>1024) return -EINVAL;
        count=(unsigned)a[2];
        long result=md_read_memory(vectors,(void *)a[1],count*sizeof(*vectors));
        if (result) return result;
    }
    size_t total=0;
    for (unsigned i=0;i<count;++i) {
        if (vectors[i].iov_len>(size_t)PTRDIFF_MAX-total) return -EINVAL;
        total+=vectors[i].iov_len;
    }
    if (vector && !total) return 0;
    /* Legacy proc writev calls the write method for each vector. A successful
     * map write consumes its one publication; another vector cannot be joined
     * into the same map or replay that publication. */
    if (writing && vector && total && !sysctl) {
        unsigned first=0;
        while (first<count && !vectors[first].iov_len) ++first;
        vectors[0]=vectors[first]; count=1; total=vectors[0].iov_len;
    }
    if (writing && !sysctl && total>=md_page_size) return -EINVAL;
    long memory=md_adapter_buffer_take();
    if (memory<0) return memory;
    long result=0; size_t copied=0;
    if (writing) for (unsigned i=0;i<count;++i) {
        if (!sysctl) {
            result=md_read_memory((char *)memory+copied,vectors[i].iov_base,vectors[i].iov_len);
            if (result) break;
            copied+=vectors[i].iov_len;
        } else {
            /* The string handler uses at most 64 bytes, but Linux validates
             * every input vector before publishing a truncated sysctl value. */
            char chunk[512];
            for (size_t offset=0;offset<vectors[i].iov_len;) {
                size_t size=vectors[i].iov_len-offset;
                if (size>sizeof(chunk)) size=sizeof(chunk);
                result=md_read_memory(chunk,(char *)vectors[i].iov_base+offset,size);
                if (result) break;
                size_t retained=copied<64 ? 64-copied : 0;
                if (retained>size) retained=size;
                if (retained) memcpy((char *)memory+copied,chunk,retained);
                copied+=size; offset+=size;
            }
            if (result) break;
        }
    }
    if (!result) result=md_guest_buffer_control(MD_BUFFER_PROC_IO,total,0);
    long offered=result;
    copied=0;
    if (!writing && nr!=SYS_lseek && result>0) {
        size_t remaining=(size_t)result;
        for (unsigned i=0;i<count && remaining;++i) {
            size_t n=vectors[i].iov_len<remaining ? vectors[i].iov_len : remaining;
            long error=md_write_memory(vectors[i].iov_base,(char *)memory+copied,n);
            if (error) { result=copied ? (long)copied : error; break; }
            copied+=n; remaining-=n;
        }
    }
    if (offered>=0) {
        long finished=md_guest_buffer_control(MD_BUFFER_PROC_ACK,
            writing || nr==SYS_lseek ? 0 : (unsigned long)result,0);
        if (finished) result=finished;
    }
    long released=md_adapter_buffer_release();
    return result<0 ? result : released<0 ? released : result;
#endif
}
