#ifndef MD_INPUT_DEVICES_H
#define MD_INPUT_DEVICES_H
#include "control_file.h"
#include <linux/input.h>
#include <stdint.h>

enum { MD_INPUT_PHYSICAL=32, MD_INPUT_DEVICES=64, MD_INPUT_QUEUE=256, MD_INPUT_EFFECTS=16 };
struct md_input_description {
    char name[128];
    struct input_id id;
    uint8_t keys[(KEY_CNT+7)/8];
    uint8_t axes[(ABS_CNT+7)/8];
    struct input_absinfo abs[ABS_CNT];
    int rumble;
};
struct md_input_rumble {
    unsigned device, effect;
    uint16_t strong, weak, milliseconds, delay;
    unsigned repeats;
};
struct md_input_bus;
struct md_input_backend {
    void *context;
    void *(*retain)(void *);
    void (*release)(void *);
    void (*output)(void *,const struct input_event *);
    long (*effect)(void *,const struct ff_effect *,const struct ff_effect *,int erase,struct md_control_pending **);
    unsigned effects;
    const char *physical_path;
};
/* output() must enqueue without blocking. It runs under the short device lock;
 * it must not call back into the bus. wake_fd is duplicated, never borrowed. */
int md_input_bus_new(int wake_fd,void (*output)(void *,const struct md_input_rumble *),
    void *context,struct md_input_bus **);
struct md_input_bus *md_input_bus_retain(struct md_input_bus *);
void md_input_bus_release(struct md_input_bus *);
int md_input_add(struct md_input_bus *,unsigned slot,const struct md_input_description *);
int md_input_add_backend(struct md_input_bus *,unsigned,const struct md_input_description *,const struct md_input_backend *);
int md_input_remove(struct md_input_bus *,unsigned slot);
int md_input_frame(struct md_input_bus *,unsigned slot,const struct input_event *,size_t count);
void md_input_neutralize(struct md_input_bus *);
void md_input_disconnect(struct md_input_bus *);
int md_input_description(struct md_input_bus *,unsigned slot,struct md_input_description *);
/* Returns a retained node; its open() creates an independent event queue.
 * Evdev and joydev are two views of one device, not two input sources. */
int md_input_node(struct md_input_bus *,unsigned slot,int joystick,struct md_control_file *);
static inline unsigned md_input_minor(unsigned slot,int joystick) {
    return slot<32 ? slot+(joystick ? 0 : 64) : 256+(slot-32)*2+(joystick ? 1 : 0);
}
#endif
