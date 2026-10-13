#define _GNU_SOURCE
#include "input_session.h"
#include "input_devices.h"
#include "fs_mounts.h"
#include "fs_storage.h"
#include "event_wait.h"
#include "task_registry.h"
#include "device_events.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/joystick.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>

struct server { int listener,connection,ready; pthread_t thread; };
static void write_all(int fd,const void *data,size_t size) {
    const char *p=data;
    while (size) { ssize_t n=send(fd,p,size,MSG_NOSIGNAL); assert(n>0); p+=n; size-=(size_t)n; }
}
static void send_frame(int fd,unsigned type,const void *payload,size_t size) {
    uint32_t header[]={0x4d444750,1,type,0,(uint32_t)size};
    write_all(fd,header,sizeof(header)); if (size) write_all(fd,payload,size);
}
static void *serve(void *context) {
    struct server *s=context;
    s->connection=accept4(s->listener,NULL,NULL,SOCK_CLOEXEC); assert(s->connection>=0);
    struct md_input_description d={.name="Gamepad fixture",.id={.bustype=6,.vendor=0x45e,.product=0xb20},.rumble=1};
    d.keys[BTN_A/8]|=1U<<(BTN_A%8); d.axes[ABS_X/8]|=1U<<(ABS_X%8);
    d.abs[ABS_X]=(struct input_absinfo){.minimum=-32767,.maximum=32767};
    send_frame(s->connection,1,&d,sizeof(d)); send_frame(s->connection,5,NULL,0);
    uint64_t one=1; assert(write(s->ready,&one,8)==8); return NULL;
}
static int capture(void *context,const struct md_control_file_ops *ops,void *node,const struct md_identity *id,int flags) {
    (void)id;
    struct md_control_file *file=context;
    void *opened=flags&O_PATH ? ops->retain(node) : ops->open(node,flags);
    if (!opened) return -errno;
    *file=(struct md_control_file){ops,opened}; return 0;
}
static struct md_fs_result request(struct md_filesystem *fs,unsigned operation,const char *path,unsigned flags,
        struct md_control_file *file,struct md_fs_anchor **anchor) {
    struct md_fs_request q={.operation=operation,.flags=flags,.directory={-1,-1},.path={path,NULL}};
    struct md_fs_output output={.control=capture,.control_context=file,.origin=anchor};
    struct md_fs_result result; md_fs_execute(fs,&q,&result,&output); return result;
}
void md_test_input_session(const char *path) {
    alarm(30); setbuf(stdout,NULL);
    struct md_inode_store *store=NULL; assert(!md_inode_store_open(path,1,&store));
    assert(!md_inode_runtime_prepare(store));
    int made=md_inode_mkdir(store,-1,"/sys",0755); assert(!made || made==-EEXIST);
    struct md_fs_storage_cache storage={0};
    struct md_filesystem fs={.store=store,.storage=&storage}; assert(!md_fs_mounts_open(&fs,NULL,0));
    struct server server={.connection=-1,.ready=eventfd(0,EFD_CLOEXEC)};
    server.listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); assert(server.listener>=0 && server.ready>=0);
    char name[64]; snprintf(name,sizeof(name),"md-input-fixture-%d",getpid());
    struct sockaddr_un address={.sun_family=AF_UNIX}; strcpy(address.sun_path+1,name);
    assert(!bind(server.listener,(void *)&address,offsetof(struct sockaddr_un,sun_path)+strlen(name)+1));
    assert(!listen(server.listener,1)); assert(!pthread_create(&server.thread,NULL,serve,&server));
    int wake=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK); assert(wake>=0);
    struct md_input_launch launch={.endpoint=name,.wake_fd=wake};
    struct md_input_session *session=NULL;
    struct md_device_events *bus=md_device_events_new(); assert(bus);
    assert(!md_input_session_start(&fs,NULL,bus,&session) && !session);
    fs.tasks=md_task_registry_create(); assert(fs.tasks);
    int error=md_input_session_start(&fs,&launch,bus,&session);
    md_task_registry_destroy(fs.tasks); fs.tasks=NULL;
    if (error) fprintf(stderr,"input startup: %d (%s)\n",error,strerror(-error));
    assert(!error); assert(!pthread_join(server.thread,NULL));
    struct md_fs_result st=request(&fs,MD_FS_STAT,"/dev/input/event0",0,NULL,NULL);
    assert(!st.error && S_ISCHR(st.info.mode) && major(st.info.rdev)==13 && minor(st.info.rdev)==64);
    struct md_control_file file={0}; struct md_fs_anchor *origin=NULL;
    struct md_fs_result opened=request(&fs,MD_FS_OPEN,"/dev/input/event0",O_RDWR|O_NONBLOCK,&file,&origin);
    assert(!opened.error && opened.fd>=0 && file.ops && origin); close(opened.fd);
    char name_read[128]={0};
    assert(file.ops->ioctl(file.context,NULL,EVIOCGNAME(sizeof(name_read)),0,name_read,sizeof(name_read))>0);
    assert(!strcmp(name_read,"Gamepad fixture"));
    uint64_t drain; while (read(wake,&drain,8)==8) { }
    struct { uint16_t type,code; int32_t value; } event={EV_KEY,BTN_A,1};
    send_frame(server.connection,3,&event,sizeof(event));
    /* EVENT_WAIT: producer publication wakes the descriptor owner. */
    assert(md_event_wait_fd(wake,POLLIN,md_event_now()+1000000000LL)>=0);
    struct input_event events[8]; long count=file.ops->read(file.context,NULL,events,sizeof(events),0);
    assert(count==2*(long)sizeof(*events) && events[0].code==BTN_A && events[0].value==1 && events[1].type==EV_SYN);
    file.ops->read_commit(file.context,(size_t)count);
    const char *files[]={"/sys/class/input/event0/device/name","/sys/dev/char/13:64/dev","/run/udev/data/c13:64"};
    for (unsigned i=0;i<3;++i) {
        struct md_fs_result info=request(&fs,MD_FS_OPEN,files[i],O_RDONLY,NULL,NULL);
        if (info.error) fprintf(stderr,"open %s: %d\n",files[i],info.error);
        assert(!info.error && info.fd>=0); char bytes[512]; assert(read(info.fd,bytes,sizeof(bytes))>0); close(info.fd);
    }
    struct md_fs_result bad=request(&fs,MD_FS_OPEN,"/sys/class/input/event0/dev",O_WRONLY,NULL,NULL);
    assert(bad.error==-EROFS);
    bad=request(&fs,MD_FS_UNLINK,"/dev/input/event0",0,NULL,NULL); assert(bad.error==-EROFS);
    const char *host_only[]={"/sys/devices/system","/sys/bus/pci","/sys/class/drm"};
    for (unsigned i=0;i<sizeof(host_only)/sizeof(*host_only);++i) {
        struct md_fs_result hidden=request(&fs,MD_FS_STAT,host_only[i],0,NULL,NULL);
        assert(hidden.error==-ENOENT);
    }
    struct md_fs_result shared=request(&fs,MD_FS_OPEN,"/dev/shm/gamepad-test",O_CREAT|O_RDWR,NULL,NULL);
    assert(!shared.error && shared.fd>=0); assert(write(shared.fd,"ok",2)==2); close(shared.fd);
    struct md_fs_result null=request(&fs,MD_FS_OPEN,"/dev/null",O_WRONLY,NULL,NULL);
    if (null.error) fprintf(stderr,"null: %d host=%u\n",null.error,null.host_path);
    assert(!null.error && null.fd>=0); assert(write(null.fd,"ok",2)==2); close(null.fd);
    md_control_file_release(file); file=(struct md_control_file){0};
    md_fs_anchor_release(origin); origin=NULL;
    struct md_fs_result js=request(&fs,MD_FS_OPEN,"/dev/input/js0",O_RDONLY|O_NONBLOCK,&file,&origin);
    /* Release the independently captured open description below. */
    assert(!js.error); close(js.fd);
    md_control_file_release(file); md_fs_anchor_release(origin);
    struct md_fd_object *monitor=NULL; int monitor_fd=-1;
    assert(!md_device_events_socket(bus,SOCK_RAW|SOCK_NONBLOCK,&monitor,&monitor_fd));
    struct sockaddr_nl address_nl={.nl_family=AF_NETLINK,.nl_groups=2};
    unsigned long args[6]={0};
    assert(!md_device_events_call(monitor,SYS_bind,args,&address_nl,sizeof(address_nl),sizeof(address_nl),getpid()));
    send_frame(server.connection,2,NULL,0);
    /* EVENT_WAIT: removal is published only after device metadata is retired. */
    assert(md_event_wait_fd(monitor_fd,POLLIN,md_event_now()+1000000000LL)>=0);
    char notification[4096]; ssize_t n=recv(monitor_fd,notification,sizeof(notification),0);
    assert(n>40 && !memcmp(notification,"libudev",8));
    assert(memmem(notification,(size_t)n,"ACTION=remove",14));
    assert(memmem(notification,(size_t)n,"DEVNAME=/dev/input/event0",25));
    assert(md_device_events_call(monitor,SYS_getsockname,args,&address_nl,sizeof(address_nl),0,getpid())==sizeof(address_nl));
    assert(address_nl.nl_groups==2 && address_nl.nl_pid==(unsigned)getpid());
    close(server.connection); close(server.listener); close(server.ready);
    md_input_session_stop(session); close(wake);
    while (recv(monitor_fd,notification,sizeof(notification),MSG_DONTWAIT)>0) {}
    assert(errno==EAGAIN);
    assert(!md_device_events_publish(bus,"change","/devices/virtual/test","test",NULL,0));
    n=recv(monitor_fd,notification,sizeof(notification),MSG_DONTWAIT);
    assert(n>40 && memmem(notification,(size_t)n,"SUBSYSTEM=test",15));
    md_device_events_stop(bus); md_device_events_release(bus);
    close(monitor_fd); md_fd_object_release(monitor);
    md_fs_mounts_close(&fs); md_fs_storage_close(&storage); md_inode_store_close(store);
    puts("PASS input transport, discovery, controlled opens, sysfs composition and cleanup");
}
