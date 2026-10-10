#ifndef MD_INPUT_UINPUT_H
#define MD_INPUT_UINPUT_H
#include "input_devices.h"
struct md_uinput;
struct md_uinput_publisher {
    void *context;
    int (*add)(void *,unsigned,const struct md_input_description *,const struct md_input_backend *);
    void (*remove)(void *,unsigned);
};
int md_uinput_new(struct md_input_bus *,int wake_fd,const struct md_uinput_publisher *,struct md_uinput **);
void md_uinput_stop(struct md_uinput *);
void md_uinput_release(struct md_uinput *);
int md_uinput_node(struct md_uinput *,struct md_control_file *);
#endif
