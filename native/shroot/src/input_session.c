#define _GNU_SOURCE
#include "input_session.h"
#include "input_devices.h"
#include "input_uinput.h"
#include "device_events.h"
#include "device_tree.h"
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "event_wait.h"
#include "sysfs_view.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include "event_signal.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum { MAGIC=0x4d444750, VERSION=1, ADD=1, REMOVE=2, FRAME=3, NEUTRAL=4, READY=5, RUMBLE=6,
    MAX_PAYLOAD=4096, FEEDBACK_QUEUE=128 };
struct header { uint32_t magic,version,type,slot,size; };
struct feedback { struct header header; uint32_t effect,strong,weak,duration,delay,repeats; };
struct md_input_session {
    struct md_input_bus *bus;
    struct md_uinput *uinput;
    struct md_device_events *events;
    struct md_provider_tree *dev,*sys,*udev;
    int socket,wake,ready;
    atomic_int stopping,error;
    pthread_t thread;
    int started;
    pthread_mutex_t lock;
    struct feedback feedback[FEEDBACK_QUEUE];
    unsigned head,count;
};
_Static_assert(sizeof(struct md_input_description)==1780,"gamepad description wire ABI");
static void feedback(void *context,const struct md_input_rumble *effect) {
    struct md_input_session *s=context;
    pthread_mutex_lock(&s->lock);
    if (s->count==FEEDBACK_QUEUE) atomic_store(&s->stopping,1);
    else {
        struct feedback *f=&s->feedback[(s->head+s->count++)%FEEDBACK_QUEUE];
        *f=(struct feedback){.header={MAGIC,VERSION,RUMBLE,effect->device,24},
            .effect=effect->effect,.strong=effect->strong,.weak=effect->weak,
            .duration=effect->milliseconds,.delay=effect->delay,.repeats=effect->repeats};
    }
    pthread_mutex_unlock(&s->lock); md_event_signal(s->wake);
}
static int directory(int root,const char *path) {
    char copy[PATH_MAX];
    if (strlen(path)>=sizeof(copy)) return -ENAMETOOLONG;
    strcpy(copy,path);
    for (char *p=copy;;++p) if (*p=='/' || !*p) {
        char end=*p; *p=0;
        if (mkdirat(root,copy,0755) && errno!=EEXIST) return -errno;
        *p=end; if (!end) return 0;
    }
}
static int text_file(int root,const char *path,const char *format,...) {
    char text[2048]; va_list args; va_start(args,format);
    int length=vsnprintf(text,sizeof(text),format,args); va_end(args);
    if (length<0 || (size_t)length>=sizeof(text)) return -EOVERFLOW;
    int fd=openat(root,path,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0644);
    if (fd<0) return -errno;
    int error=0; size_t offset=0;
    while (offset<(size_t)length) {
        ssize_t n=write(fd,text+offset,(size_t)length-offset);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { error=n<0 ? -errno : -EIO; break; }
        offset+=(size_t)n;
    }
    close(fd); return error;
}
static int link_file(int root,const char *target,const char *path) {
    return symlinkat(target,root,path) ? -errno : 0;
}
static void bitmap(const uint8_t *bits,size_t size,char *text,size_t capacity) {
    size_t words=(size+7)/8,used=0;
    while (words>1) {
        uint64_t value=0; size_t count=size-(words-1)*8; if (count>8) count=8;
        memcpy(&value,bits+(words-1)*8,count);
        if (value) break; --words;
    }
    while (words) {
        --words; uint64_t value=0; size_t count=size-words*8; if (count>8) count=8;
        memcpy(&value,bits+words*8,count);
        int n=snprintf(text+used,capacity-used,"%s%llx",used ? " " : "",(unsigned long long)value);
        if (n<0 || (size_t)n>=capacity-used) break;
        used+=(size_t)n;
    }
}
static int emit(struct md_input_session *s,unsigned slot,unsigned joy,const char *action) {
    char path[128],properties[256];
    snprintf(path,sizeof(path),"/devices/virtual/input/input%u/%s%u",slot,joy ? "js" : "event",slot);
    int n=snprintf(properties,sizeof(properties),"DEVNAME=/dev/input/%s%u%cMAJOR=13%cMINOR=%u%cID_INPUT=1%cID_INPUT_JOYSTICK=1%cID_BUS=virtual%cTAGS=:seat:uaccess:%cCURRENT_TAGS=:seat:uaccess:%c",
        joy ? "js" : "event",slot,0,0,md_input_minor(slot,(int)joy),0,0,0,0,0,0);
    if (n<0 || (size_t)n>=sizeof(properties)) return -EOVERFLOW;
    return md_device_events_publish(s->events,action,path,"input",properties,(size_t)n);
}
static int publish_nodes(struct md_input_session *s,unsigned slot,const struct md_input_description *d,const struct md_input_backend *backend) {
    int error=0;
    int sys=md_provider_tree_root(s->sys),udev=md_provider_tree_root(s->udev);
    char base[128],path[256],target[256];
    snprintf(base,sizeof(base),"devices/virtual/input/input%u",slot);
    if ((error=directory(sys,base))) return error;
    const char *dirs[]={"id","capabilities"};
    for (unsigned i=0;i<2;++i) {
        snprintf(path,sizeof(path),"%s/%s",base,dirs[i]);
        if ((error=directory(sys,path))) return error;
    }
    struct { const char *name; unsigned value; } ids[]={
        {"bustype",d->id.bustype},{"vendor",d->id.vendor},{"product",d->id.product},{"version",d->id.version}};
    for (unsigned i=0;i<4;++i) {
        snprintf(path,sizeof(path),"%s/id/%s",base,ids[i].name);
        if ((error=text_file(sys,path,"%04x\n",ids[i].value))) return error;
    }
    snprintf(path,sizeof(path),"%s/name",base); if ((error=text_file(sys,path,"%s\n",d->name))) return error;
    snprintf(path,sizeof(path),"%s/phys",base);
    if ((error=backend ? text_file(sys,path,"%s\n",backend->physical_path) : text_file(sys,path,"magicdesk/gamepad%u\n",slot))) return error;
    snprintf(path,sizeof(path),"%s/uniq",base); if ((error=text_file(sys,path,"\n"))) return error;
    snprintf(path,sizeof(path),"%s/subsystem",base); if ((error=link_file(sys,"../../../../class/input",path))) return error;
    snprintf(path,sizeof(path),"%s/uevent",base);
    if ((error=text_file(sys,path,"PRODUCT=%x/%x/%x/%x\nNAME=\"%s\"\n",d->id.bustype,d->id.vendor,d->id.product,d->id.version,d->name))) return error;
    uint8_t ev[8]={0},ff[16]={0},zero[8]={0};
    ev[0]=(1U<<EV_SYN)|(1U<<EV_KEY)|(1U<<EV_ABS);
    if (d->rumble) { ev[EV_FF/8]|=1U<<(EV_FF%8); ff[FF_RUMBLE/8]|=1U<<(FF_RUMBLE%8); ff[FF_GAIN/8]|=1U<<(FF_GAIN%8); }
    struct { const char *name; const uint8_t *bits; size_t size; } caps[]={
        {"ev",ev,sizeof(ev)},{"key",d->keys,sizeof(d->keys)},{"abs",d->axes,sizeof(d->axes)},
        {"ff",ff,sizeof(ff)},{"rel",zero,sizeof(zero)},{"msc",zero,sizeof(zero)},
        {"led",zero,sizeof(zero)},{"snd",zero,sizeof(zero)},{"sw",zero,sizeof(zero)}};
    for (unsigned i=0;i<sizeof(caps)/sizeof(*caps);++i) {
        char bits[256]={0}; bitmap(caps[i].bits,caps[i].size,bits,sizeof(bits));
        snprintf(path,sizeof(path),"%s/capabilities/%s",base,caps[i].name);
        if ((error=text_file(sys,path,"%s\n",bits))) return error;
    }
    snprintf(path,sizeof(path),"%s/properties",base); if ((error=text_file(sys,path,"0\n"))) return error;
    snprintf(path,sizeof(path),"class/input/input%u",slot); snprintf(target,sizeof(target),"../../%s",base);
    if ((error=link_file(sys,target,path))) return error;
    for (unsigned j=0;j<2;++j) {
        char node[32]; snprintf(node,sizeof(node),"%s%u",j ? "js" : "event",slot);
        unsigned minor=md_input_minor(slot,(int)j);
        snprintf(path,sizeof(path),"%s/%s",base,node); if ((error=directory(sys,path))) return error;
        snprintf(path,sizeof(path),"%s/%s/dev",base,node); if ((error=text_file(sys,path,"13:%u\n",minor))) return error;
        snprintf(path,sizeof(path),"%s/%s/uevent",base,node);
        if ((error=text_file(sys,path,"MAJOR=13\nMINOR=%u\nDEVNAME=input/%s\n",minor,node))) return error;
        snprintf(path,sizeof(path),"%s/%s/device",base,node); if ((error=link_file(sys,"..",path))) return error;
        snprintf(path,sizeof(path),"%s/%s/subsystem",base,node); if ((error=link_file(sys,"../../../../../class/input",path))) return error;
        snprintf(path,sizeof(path),"class/input/%s",node); snprintf(target,sizeof(target),"../../%s/%s",base,node);
        if ((error=link_file(sys,target,path))) return error;
        snprintf(path,sizeof(path),"dev/char/13:%u",minor); if ((error=link_file(sys,target,path))) return error;
        snprintf(path,sizeof(path),"data/c13:%u",minor);
        if ((error=text_file(udev,path,"I:1\nE:ID_INPUT=1\nE:ID_INPUT_JOYSTICK=1\nE:ID_BUS=virtual\nE:ID_VENDOR_ID=%04x\nE:ID_MODEL_ID=%04x\nG:seat\nG:uaccess\n",d->id.vendor,d->id.product))) return error;
        snprintf(path,sizeof(path),"input/%s",node);
        struct md_control_file file={0}; error=md_input_node(s->bus,slot,(int)j,&file);
        if (!error) error=md_device_tree_publish(s->dev,path,file);
        md_control_file_release(file);
        if (error) return error;
    }
    for (unsigned j=0;j<2;++j) if ((error=emit(s,slot,j,"add"))) return error;
    return 0;
}
static void unpublish(struct md_input_session *s,unsigned slot) {
    md_input_remove(s->bus,slot);
    int sys=md_provider_tree_root(s->sys),udev=md_provider_tree_root(s->udev);
    char base[128],path[256]; snprintf(base,sizeof(base),"devices/virtual/input/input%u",slot);
    for (unsigned j=0;j<2;++j) {
        char node[32]; snprintf(node,sizeof(node),"%s%u",j ? "js" : "event",slot);
        snprintf(path,sizeof(path),"input/%s",node); int removed=md_device_tree_remove(s->dev,path);
        snprintf(path,sizeof(path),"class/input/%s",node); unlinkat(sys,path,0);
        snprintf(path,sizeof(path),"dev/char/13:%u",md_input_minor(slot,(int)j)); unlinkat(sys,path,0);
        snprintf(path,sizeof(path),"data/c13:%u",md_input_minor(slot,(int)j)); unlinkat(udev,path,0);
        const char *files[]={"dev","uevent","device","subsystem"};
        for (unsigned i=0;i<4;++i) { snprintf(path,sizeof(path),"%s/%s/%s",base,node,files[i]); unlinkat(sys,path,0); }
        snprintf(path,sizeof(path),"%s/%s",base,node); unlinkat(sys,path,AT_REMOVEDIR);
        if (removed>0) emit(s,slot,j,"remove");
    }
    const char *files[]={"id/bustype","id/vendor","id/product","id/version","name","phys","uniq","uevent","properties","subsystem",
        "capabilities/ev","capabilities/key","capabilities/abs","capabilities/ff","capabilities/rel",
        "capabilities/msc","capabilities/led","capabilities/snd","capabilities/sw"};
    for (unsigned i=0;i<sizeof(files)/sizeof(*files);++i) { snprintf(path,sizeof(path),"%s/%s",base,files[i]); unlinkat(sys,path,0); }
    snprintf(path,sizeof(path),"%s/id",base); unlinkat(sys,path,AT_REMOVEDIR);
    snprintf(path,sizeof(path),"%s/capabilities",base); unlinkat(sys,path,AT_REMOVEDIR);
    unlinkat(sys,base,AT_REMOVEDIR);
    snprintf(path,sizeof(path),"class/input/input%u",slot); unlinkat(sys,path,0);
}
static int publish(void *context,unsigned slot,const struct md_input_description *d,const struct md_input_backend *backend) {
    struct md_input_session *s=context;
    int error=md_input_add_backend(s->bus,slot,d,backend);
    if (error) return error;
    error=publish_nodes(s,slot,d,backend);
    if (error) unpublish(s,slot);
    return error;
}
static void remove_virtual(void *context,unsigned slot) { unpublish(context,slot); }
static int packet(struct md_input_session *s,const struct header *h,const unsigned char *payload,int *ready) {
    if (h->magic!=MAGIC || h->version!=VERSION || h->slot>=MD_INPUT_PHYSICAL) return -EPROTO;
    switch (h->type) {
    case ADD: {
        if (h->size!=sizeof(struct md_input_description)) return -EPROTO;
        struct md_input_description d; memcpy(&d,payload,sizeof(d)); return publish(s,h->slot,&d,NULL);
    }
    case REMOVE: if (h->size) return -EPROTO; unpublish(s,h->slot); return 0;
    case NEUTRAL: if (h->size) return -EPROTO; md_input_neutralize(s->bus); return 0;
    case READY: if (h->size || *ready) return -EPROTO; *ready=1; md_event_signal(s->ready); return 0;
    case FRAME: {
        if (!*ready || h->size%8 || h->size/8>MD_INPUT_QUEUE-1) return -EPROTO;
        struct input_event events[MD_INPUT_QUEUE];
        for (unsigned i=0;i<h->size/8;++i) {
            uint16_t type,code; int32_t value;
            memcpy(&type,payload+i*8,2); memcpy(&code,payload+i*8+2,2); memcpy(&value,payload+i*8+4,4);
            events[i]=(struct input_event){.type=type,.code=code,.value=value};
        }
        return md_input_frame(s->bus,h->slot,events,h->size/8);
    }
    default: return -EPROTO;
    }
}
static void *transport(void *context) {
    struct md_input_session *s=context;
    unsigned char bytes[sizeof(struct header)+MAX_PAYLOAD]; size_t used=0,goal=sizeof(struct header),sent=0;
    int ready=0,error=0;
    while (!atomic_load(&s->stopping)) {
        pthread_mutex_lock(&s->lock); int queued=s->count>0; pthread_mutex_unlock(&s->lock);
        struct pollfd events[]={{s->socket,POLLIN|(queued ? POLLOUT : 0),0},{s->wake,POLLIN,0}};
        /* EVENT_WAIT: input/feedback readiness or stop event; no periodic polling. */
        long result=md_event_wait(events,2,INT64_MAX);
        if (result<0) { error=(int)result; break; }
        if (events[1].revents && (error=md_event_acknowledge(s->wake))) break;
        if (events[0].revents&POLLOUT) {
            pthread_mutex_lock(&s->lock);
            ssize_t n=send(s->socket,(char *)&s->feedback[s->head]+sent,sizeof(struct feedback)-sent,MSG_NOSIGNAL|MSG_DONTWAIT);
            if (n>0) { sent+=(size_t)n; if (sent==sizeof(struct feedback)) { sent=0; s->head=(s->head+1)%FEEDBACK_QUEUE; --s->count; } }
            else if (n<0 && errno!=EAGAIN && errno!=EINTR) error=-errno;
            pthread_mutex_unlock(&s->lock);
            if (error) break;
        }
        if (events[0].revents&(POLLIN|POLLHUP|POLLERR)) {
            ssize_t n=recv(s->socket,bytes+used,goal-used,MSG_DONTWAIT);
            if (n==0) break;
            if (n<0) { if (errno==EAGAIN || errno==EINTR) continue; error=-errno; break; }
            used+=(size_t)n;
            if (used<goal) continue;
            struct header h; memcpy(&h,bytes,sizeof(h));
            if (h.size>MAX_PAYLOAD) { error=-EMSGSIZE; break; }
            goal=sizeof(h)+h.size;
            if (used<goal) continue;
            error=packet(s,&h,bytes+sizeof(h),&ready);
            if (error) break;
            used=0; goal=sizeof(h);
        }
    }
    md_uinput_stop(s->uinput);
    md_input_disconnect(s->bus);
    if (!ready && !error) error=-ENOTCONN;
    atomic_store(&s->error,error); md_event_signal(s->ready); return NULL;
}
int md_input_session_start(struct md_filesystem *fs,const struct md_input_launch *launch,
        struct md_device_events *events,struct md_provider_tree *sysfs,struct md_input_session **out) {
    if (!launch || !launch->endpoint) return 0;
    if (!events || !sysfs) return -EINVAL;
    size_t length=strlen(launch->endpoint);
    struct sockaddr_un address={.sun_family=AF_UNIX};
    if (!length || length>=sizeof(address.sun_path)-1) return -EINVAL;
    struct md_input_session *s=calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    s->socket=s->wake=s->ready=-1;
    int error=pthread_mutex_init(&s->lock,NULL);
    if (error) { free(s); return -error; }
    atomic_init(&s->stopping,0); atomic_init(&s->error,0);
    s->wake=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC); s->ready=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if (s->wake<0 || s->ready<0) { error=-errno; goto failed; }
    error=md_input_bus_new(launch->wake_fd,feedback,s,&s->bus); if (error) goto failed;
    s->events=md_device_events_retain(events);
    int parent=md_fs_private_mounts_parent(fs->store);
    if (parent<0) { error=parent; goto failed; }
    if (fs->devices) s->dev=md_provider_tree_retain(fs->devices);
    else error=md_fs_devices_prepare(fs,1,&s->dev);
    s->sys=md_provider_tree_retain(sysfs);
    s->udev=md_provider_tree_new(parent,-1,NULL,0,NULL,NULL);
    close(parent);
    if (error) goto failed;
    if (!s->dev || !s->sys || !s->udev) { error=-errno; goto failed; }
    error=directory(md_provider_tree_root(s->dev),"input");
    if (!error) error=directory(md_provider_tree_root(s->udev),"data");
    if (!error) error=text_file(md_provider_tree_root(s->udev),"control","");
    const char *dirs[]={"class/input","devices/virtual/input"};
    for (unsigned i=0;i<sizeof(dirs)/sizeof(*dirs) && !error;++i)
        error=directory(md_provider_tree_root(s->sys),dirs[i]);
    if (error) goto failed;
    struct md_uinput_publisher publisher={.context=s,.add=publish,.remove=remove_virtual};
    error=md_uinput_new(s->bus,launch->wake_fd,&publisher,&s->uinput);
    struct md_control_file uinput={0};
    if (!error) error=md_uinput_node(s->uinput,&uinput);
    if (!error) error=md_device_tree_publish(s->dev,"uinput",uinput);
    md_control_file_release(uinput);
    if (!error) error=link_file(md_provider_tree_root(s->dev),"../uinput","input/uinput");
    if (error) goto failed;
    s->socket=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (s->socket<0) { error=-errno; goto failed; }
    memcpy(address.sun_path+1,launch->endpoint,length);
    if (connect(s->socket,(void *)&address,offsetof(struct sockaddr_un,sun_path)+length+1)) { error=-errno; goto failed; }
    error=pthread_create(&s->thread,NULL,transport,s);
    if (error) { error=-error; goto failed; } s->started=1;
    /* EVENT_WAIT: the app publishes its initial device snapshot and READY;
     * timeout fails this explicit input attachment, not unrelated services. */
    error=(int)md_event_wait_fd(s->ready,POLLIN,md_event_now()+10000000000LL);
    if (error>=0) error=atomic_load(&s->error);
    if (error) goto failed;
    const char *guest_dirs[]={"/run","/run/udev"};
    /* Launch preparation owns this view before guest task resources exist. */
    struct md_fs_context preparation={.filesystem=fs};
    for (unsigned i=0;i<2 && !error;++i) {
        struct md_fs_request q={.operation=MD_FS_MKDIR,.directory={AT_FDCWD,AT_FDCWD},.path={guest_dirs[i],NULL},.mode=0755};
        struct md_fs_result result; md_fs_context_execute(&preparation,&q,&result,NULL);
        if (result.error && result.error!=-EEXIST) error=result.error;
    }
    if (!error) error=md_fs_provider_mount(fs,s->udev,"/run/udev");
    if (error) goto failed;
    *out=s; return 0;
failed:
    md_input_session_stop(s); return error;
}
void md_input_session_stop(struct md_input_session *s) {
    if (!s) return;
    atomic_store(&s->stopping,1);
    if (s->wake>=0) md_event_signal(s->wake);
    if (s->started) pthread_join(s->thread,NULL);
    md_uinput_stop(s->uinput);
    md_input_disconnect(s->bus);
    md_provider_tree_release(s->dev); md_provider_tree_release(s->sys); md_provider_tree_release(s->udev);
    md_uinput_release(s->uinput);
    md_input_bus_release(s->bus);
    md_device_events_release(s->events);
    if (s->socket>=0) close(s->socket);
    if (s->wake>=0) close(s->wake);
    if (s->ready>=0) close(s->ready);
    pthread_mutex_destroy(&s->lock); free(s);
}
