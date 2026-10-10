#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <unistd.h>

struct upload { int fd,result,error; struct ff_effect effect; };
static void *upload(void *context) {
    struct upload *u=context;
    u->result=ioctl(u->fd,EVIOCSFF,&u->effect); u->error=errno; return NULL;
}
static struct input_event receive(int fd) {
    struct pollfd p={fd,POLLIN,0};
    /* EVENT_WAIT: kernel-compatible input readiness; timeout fails the test. */
    assert(poll(&p,1,10000)==1 && p.revents&POLLIN);
    struct input_event e; assert(read(fd,&e,sizeof(e))==sizeof(e)); return e;
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL);
    int ui=open("/dev/uinput",O_RDWR|O_NONBLOCK); assert(ui>=0);
    assert(!ioctl(ui,UI_SET_EVBIT,EV_KEY)); assert(!ioctl(ui,UI_SET_EVBIT,EV_ABS));
    assert(!ioctl(ui,UI_SET_EVBIT,EV_FF)); assert(!ioctl(ui,UI_SET_KEYBIT,BTN_SOUTH));
    assert(!ioctl(ui,UI_SET_FFBIT,FF_RUMBLE)); assert(!ioctl(ui,UI_SET_PHYS,"test/shroot-input"));
    struct uinput_setup setup={.name="Shroot virtual gamepad",.id={BUS_VIRTUAL,0x4d44,2,1},.ff_effects_max=2};
    assert(!ioctl(ui,UI_DEV_SETUP,&setup));
    for (unsigned i=0;i<2;++i) {
        struct uinput_abs_setup abs={.code=(unsigned short)i,.absinfo={.minimum=-32767,.maximum=32767}};
        assert(!ioctl(ui,UI_ABS_SETUP,&abs));
    }
    assert(!ioctl(ui,UI_DEV_CREATE));
    char sysname[32],path[128]; assert(ioctl(ui,UI_GET_SYSNAME(sizeof(sysname)),sysname)>0);
    snprintf(path,sizeof(path),"/sys/class/input/%s",sysname);
    DIR *dir=opendir(path); assert(dir); struct dirent *e; int ev=-1;
    while ((e=readdir(dir))) if (!strncmp(e->d_name,"event",5)) {
        snprintf(path,sizeof(path),"/dev/input/%s",e->d_name); ev=open(path,O_RDWR|O_NONBLOCK); break;
    }
    closedir(dir); assert(ev>=0); puts("CREATED virtual evdev through sysfs");
    if (argc==2 && !strcmp(argv[1],"--hotplug")) {
        char ack;
        /* EVENT_WAIT: the SDL observer opens the published device first. */
        assert(read(STDIN_FILENO,&ack,1)==1);
    }
    struct input_event frame[]={{.type=EV_KEY,.code=BTN_SOUTH,.value=1},{.type=EV_SYN,.code=SYN_REPORT}};
    assert(write(ui,frame,sizeof(frame))==sizeof(frame));
    struct pollfd check={ev,POLLIN,0};
    assert(poll(&check,1,0)==1 && check.revents==POLLIN);
    int ep=epoll_create1(EPOLL_CLOEXEC); assert(ep>=0);
    struct epoll_event interest={.events=EPOLLIN,.data.fd=ev},ready;
    assert(!epoll_ctl(ep,EPOLL_CTL_ADD,ev,&interest));
    assert(epoll_wait(ep,&ready,1,0)==1 && ready.events==EPOLLIN); close(ep);
    assert(read(ev,(void *)1,sizeof(frame))==-1 && errno==EFAULT);
    puts("READ copy rejected, waiting for preserved input");
    struct input_event pressed=receive(ev); assert(pressed.code==BTN_SOUTH && pressed.value==1);
    assert(receive(ev).type==EV_SYN);
    puts("INPUT delivered, requesting force feedback");
    struct upload u={.fd=ev,.effect={.type=FF_RUMBLE,.id=-1,.u.rumble={1000,2000},.replay={100,0}}};
    pthread_t thread; assert(!pthread_create(&thread,NULL,upload,&u));
    struct input_event request=receive(ui); assert(request.type==EV_UINPUT && request.code==UI_FF_UPLOAD);
    struct uinput_ff_upload reply={.request_id=(unsigned)request.value};
    assert(!ioctl(ui,UI_BEGIN_FF_UPLOAD,&reply)); assert(reply.effect.u.rumble.strong_magnitude==1000);
    assert(!ioctl(ui,UI_END_FF_UPLOAD,&reply));
    puts("FF acknowledged, waiting for caller");
    assert(!pthread_join(thread,NULL)); assert(!u.result && u.effect.id>=0);
    struct input_event play={.type=EV_FF,.code=(unsigned short)u.effect.id,.value=1};
    assert(write(ev,&play,sizeof(play))==sizeof(play)); assert(receive(ui).value==1);
    u.effect.id=-1; assert(!pthread_create(&thread,NULL,upload,&u));
    request=receive(ui); assert(request.type==EV_UINPUT);
    close(ui); assert(!pthread_join(thread,NULL)); assert(u.result==-1 && u.error==ENODEV);
    assert(read(ev,frame,sizeof(frame))==-1 && errno==ENODEV); close(ev);
    puts("PASS guest uinput: sysfs, input, EFAULT rollback, async FF, output, owner-close cancellation");
    return 0;
}
