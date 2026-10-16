#define _GNU_SOURCE
#include "mount_copy_service.h"
#include "fs_worker.h"
#include "event_wait.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned count=0;
    for (struct dirent *entry;(entry=readdir(dir));)
        if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ++count;
    closedir(dir); return count;
}
static void unexpected_completion(struct md_mount_copy_request *request,int actor,int error) {
    (void)request; (void)actor; (void)error;
    assert(!"stopped worker must not dispatch completions");
}
void md_test_mount_copy_service(const char *store) {
    unsigned before=descriptors();
    for (unsigned cancel=0;cancel<2;++cancel) {
        char endpoint[80]; snprintf(endpoint,sizeof(endpoint),"md-mount-copy-%d-%u",getpid(),cancel);
        struct md_fs_worker *worker=NULL;
        assert(!md_fs_worker_start(store,endpoint,NULL,NULL,NULL,NULL,&worker));
        struct md_fs_worker_pause pause={0};
        assert(!md_fs_worker_pause_begin(worker,&pause));
        int64_t deadline=md_event_now()+5000000000LL;
        /* EVENT_WAIT: acknowledged worker pause makes pending cancellation
         * deterministic; expiry fails before any namespace request is sent. */
        while (!md_fs_worker_pause_state(&pause)) {
            assert(md_event_wait_fd(md_fs_worker_fd(worker),POLLIN,deadline)>=0);
            assert(!md_fs_worker_dispatch(worker));
        }
        assert(md_fs_worker_pause_state(&pause)==1);
        struct md_mount_copy_service *service=NULL;
        assert(!md_mount_copy_service_create(worker,unexpected_completion,&service));
        struct md_guest_domain *domain=md_domain_new(); assert(domain);
        struct md_mount_copy_request *requests[8]={0};
        struct md_mount_namespace *source=md_fs_worker_mounts(worker); assert(source);
        for (unsigned i=0;i<8;++i) {
            assert(!(i&1 ? md_mount_join_submit(service,getpid(),source,&requests[i])
                : md_mount_copy_submit(service,getpid(),source,domain,NULL,1,1,&requests[i])));
            if (cancel) md_mount_copy_cancel(&requests[i]);
        }
        assert(!md_fs_worker_stop(worker) && !pause.owner);
        md_mount_copy_service_destroy(service); md_domain_release(domain);
        assert(descriptors()==before);
    }
    puts("PASS mount work shutdown: copy/join, cancelled and pending requests, no callback or FD leak");
}
