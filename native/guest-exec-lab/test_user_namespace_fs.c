#define _GNU_SOURCE
#include "fs_engine.h"
#include "inode_internal.h"
#include "posix_acl.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void test_user_namespace_fs(const char *base) {
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/user-ns-fs",base);
    struct md_inode_store *store=NULL;
    assert(!md_inode_store_open(path,1,&store));
    int root=md_inode_open(store,-1,"/",O_PATH|O_DIRECTORY,0); assert(root>=0);
    assert(!md_inode_import_metadata(store,root,0,0,0777)); close(root);
    int fd=md_inode_create(store,-1,"/owned",0600); assert(fd>=0);
    assert(!md_inode_import_metadata(store,fd,1000,2000,0600));
    int outside=md_inode_create(store,-1,"/outside",0600); assert(outside>=0);
    assert(!md_inode_import_metadata(store,outside,9000,9000,0600)); close(outside);

    struct md_identity actor=md_identity_new(1000,2000);
    assert(!md_identity_enter_user_namespace(&actor));
    struct md_user_authority parent={.caps=UINT64_MAX};
    struct md_id_extent users[]={{0,1000,1},{1,5000,1},{2,4000,1}};
    struct md_id_extent groups[]={{0,2000,1},{1,6000,1},{2,3000,1}};
    assert(!md_user_namespace_map(actor.user_namespace,0,&parent,&parent,users,3));
    assert(!md_user_namespace_map(actor.user_namespace,1,&parent,&parent,groups,3));
    store->identity=&actor;
    struct md_filesystem fs={.store=store};
    struct md_fs_result out;
    struct md_fs_request q={.operation=MD_FS_STAT,.directory={-1,-1},.path={"/owned",NULL}};
    md_fs_execute(&fs,&q,&out,NULL);
    assert(!out.error && !out.info.uid && !out.info.gid);
    q.mode=MD_FS_STAT_CANONICAL;
    assert(!md_fs_request_validate(&q));
    md_fs_execute(&fs,&q,&out,NULL);
    assert(!out.error && out.info.uid==1000 && out.info.gid==2000);
    q.mode=0;
    q.operation=MD_FS_FSTAT; q.directory[0]=fd; q.path[0]=NULL;
    md_fs_execute(&fs,&q,&out,NULL);
    assert(!out.error && !out.info.uid && !out.info.gid);
    q.mode=MD_FS_STAT_CANONICAL;
    assert(!md_fs_request_validate(&q));
    md_fs_execute(&fs,&q,&out,NULL);
    assert(!out.error && out.info.uid==1000 && out.info.gid==2000);
    q.mode=0;
    q.operation=MD_FS_CHOWN; q.attributes.uid=0; q.attributes.gid=0;
    md_fs_execute(&fs,&q,&out,NULL); assert(!out.error);
    q.attributes.uid=UINT32_MAX; q.attributes.gid=UINT32_MAX;
    md_fs_execute(&fs,&q,&out,NULL); assert(!out.error);
    q.attributes.uid=3;
    md_fs_execute(&fs,&q,&out,NULL); assert(out.error==-EINVAL);
    q.attributes.uid=1;
    uint64_t effective=actor.caps.effective;
    actor.caps.effective&=~(UINT64_C(1)<<CAP_CHOWN);
    md_fs_execute(&fs,&q,&out,NULL); assert(out.error==-EPERM);
    actor.caps.effective=effective;
    md_fs_execute(&fs,&q,&out,NULL); assert(!out.error);
    struct stat changed; assert(!md_inode_fstat(store,fd,&changed) && changed.st_uid==5000);
    q.attributes.uid=0;
    md_fs_execute(&fs,&q,&out,NULL); assert(!out.error);
    struct stat st; assert(!md_inode_fstat(store,fd,&st) && st.st_uid==1000 && st.st_gid==2000);
    assert(md_identity_file_capable(&actor,5000,6000,CAP_DAC_OVERRIDE));
    assert(!md_identity_file_capable(&actor,5000,9000,CAP_DAC_OVERRIDE));
    assert(md_identity_file_capable(&actor,5000,9000,CAP_FOWNER));
    assert(!md_identity_file_capable(&actor,9000,2000,CAP_FOWNER));
    q=(struct md_fs_request){.operation=MD_FS_CHMOD,.directory={fd,-1},.mode=0000};
    md_fs_execute(&fs,&q,&out,NULL); assert(!out.error);
    int denied=md_inode_open(store,-1,"/owned",O_RDONLY,0); assert(denied>=0); close(denied);
    actor.caps.effective=0;
    assert(md_inode_open(store,-1,"/owned",O_RDONLY,0)==-EACCES);
    actor.caps.effective=UINT64_C(1)<<CAP_DAC_READ_SEARCH;
    denied=md_inode_open(store,-1,"/owned",O_RDONLY,0); assert(denied>=0); close(denied);
    assert(md_inode_open(store,-1,"/owned",O_WRONLY,0)==-EACCES);
    actor.caps.effective=effective;
    q.mode=0600; md_fs_execute(&fs,&q,&out,NULL); assert(!out.error);
    q=(struct md_fs_request){.operation=MD_FS_STAT,.directory={-1,-1},.path={"/outside",NULL}};
    md_fs_execute(&fs,&q,&out,NULL); assert(!out.error && out.info.uid==65534 && out.info.gid==65534);
    q.operation=MD_FS_OPEN; q.flags=O_RDONLY;
    md_fs_execute(&fs,&q,&out,NULL); assert(out.error==-EACCES);

    struct { uint32_t version; struct md_acl_entry entries[8]; } acl={2,{
        {MD_ACL_USER_OBJ,6,UINT32_MAX},{MD_ACL_USER,4,1},{MD_ACL_USER,2,2},
        {MD_ACL_GROUP_OBJ,0,UINT32_MAX},{MD_ACL_GROUP,4,1},{MD_ACL_GROUP,2,2},
        {MD_ACL_MASK,6,UINT32_MAX},{MD_ACL_OTHER,0,UINT32_MAX}}}, bytes;
    q=(struct md_fs_request){.operation=MD_FS_FXATTR,.directory={fd,-1},
        .path={NULL,MD_ACL_ACCESS_NAME},.mode=MD_FS_XATTR_SET,.value=&acl,
        .value_size=sizeof(acl),.capacity=sizeof(acl)};
    md_fs_execute(&fs,&q,&out,NULL); assert(!out.error);
    assert(acl.entries[1].id==1 && acl.entries[2].id==2);
    q.mode=MD_FS_XATTR_GET; q.value=NULL; q.value_size=0;
    struct md_fs_output output={.data=&bytes,.capacity=sizeof(bytes)};
    md_fs_execute(&fs,&q,&out,&output);
    assert(!out.error && out.size==sizeof(acl) && !memcmp(&acl,&bytes,sizeof(acl)));
    struct md_identity initial=md_identity_new(0,0); store->identity=&initial;
    md_fs_execute(&fs,&q,&out,&output); assert(!out.error);
    assert(bytes.entries[1].id==4000 && bytes.entries[1].permissions==2
        && bytes.entries[2].id==5000 && bytes.entries[2].permissions==4
        && bytes.entries[4].id==3000 && bytes.entries[5].id==6000);
    store->identity=&actor; acl.entries[2].id=3;
    q.mode=MD_FS_XATTR_SET; q.value=&acl; q.value_size=sizeof(acl);
    md_fs_execute(&fs,&q,&out,NULL); assert(out.error==-EINVAL);
    acl.entries[2].id=2;
    q.mode=MD_FS_XATTR_GET; q.value=NULL; q.value_size=0;
    md_fs_execute(&fs,&q,&out,&output);
    assert(!out.error && !memcmp(&acl,&bytes,sizeof(acl)));
    store->identity=NULL; md_identity_release(&initial); md_identity_release(&actor);
    close(fd); md_inode_store_close(store);
    puts("PASS user namespace filesystem ABI: canonical storage, mapped stat/chown/ACL, unmapped IDs and nonmonotonic extents");
}
