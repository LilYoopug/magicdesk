#include "wayland_internal.h"
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <wlr/types/wlr_pointer_constraints_v1.h>
#include <wlr/types/wlr_relative_pointer_v1.h>
#include <wlr/types/wlr_seat.h>

struct MdwPointer {
    MdwServer *server;
    struct wlr_pointer_constraints_v1 *constraints;
    struct wlr_relative_pointer_manager_v1 *relative;
    struct wlr_pointer_constraint_v1 *constraint;
    MdwOutput *owner;
    struct wl_listener created, focus, destroyed, region;
    uint64_t next_serial, serial;
    bool active, declined;
};

static void listen(struct wl_signal *signal, struct wl_listener *listener,
        void (*notify)(struct wl_listener *, void *)) {
    listener->notify = notify;
    wl_signal_add(signal, listener);
}

static void publish(struct MdwPointer *pointer, uint64_t serial) {
    MdwEvents *events = &pointer->server->events;
    if (pointer->owner && events->pointer_capture)
        events->pointer_capture(events->context, pointer->owner, serial);
}

static void clear(struct MdwPointer *pointer, bool deactivate) {
    struct wlr_pointer_constraint_v1 *constraint = pointer->constraint;
    bool active = pointer->active;
    if (constraint) {
        wl_list_remove(&pointer->destroyed.link);
        wl_list_remove(&pointer->region.link);
    }
    if (pointer->serial) publish(pointer, 0);
    pointer->constraint = NULL;
    pointer->owner = NULL;
    pointer->serial = 0;
    pointer->active = pointer->declined = false;
    // Deactivation can synchronously destroy a one-shot constraint.
    if (active && deactivate) wlr_pointer_constraint_v1_send_deactivated(constraint);
}

static void destroyed(struct wl_listener *listener, void *data) {
    (void)data;
    struct MdwPointer *pointer = wl_container_of(listener, pointer, destroyed);
    clear(pointer, false);
}

static void region_changed(struct wl_listener *listener, void *data) {
    (void)data;
    struct MdwPointer *pointer = wl_container_of(listener, pointer, region);
    mdw_pointer_refresh(pointer->server);
}

void mdw_pointer_refresh(MdwServer *server) {
    struct MdwPointer *pointer = server->pointer;
    if (!pointer) return;
    struct wlr_seat_pointer_state *seat = &server->seat->pointer_state;
    MdwOutput *owner = server->pointer_owner;
    struct wlr_pointer_constraint_v1 *constraint = owner && owner == server->keyboard_owner && seat->focused_surface
        ? wlr_pointer_constraints_v1_constraint_for_surface(pointer->constraints, seat->focused_surface, server->seat) : NULL;
    // Android capture supplies relative motion and hides its cursor. Confinement
    // needs a separate visible-cursor policy; leave those requests unactivated.
    if (constraint && constraint->type != WLR_POINTER_CONSTRAINT_V1_LOCKED) constraint = NULL;
    if (pointer->constraint != constraint || (constraint && pointer->owner != owner)) {
        clear(pointer, true);
        // Re-query after a previous one-shot constraint may have been destroyed.
        constraint = constraint ? wlr_pointer_constraints_v1_constraint_for_surface(
            pointer->constraints, seat->focused_surface, server->seat) : NULL;
        if (constraint) {
            pointer->constraint = constraint;
            pointer->owner = owner;
            listen(&constraint->events.destroy, &pointer->destroyed, destroyed);
            listen(&constraint->events.set_region, &pointer->region, region_changed);
        }
    }
    if (!constraint || pointer->active || pointer->declined || pointer->serial || !server->events.pointer_capture) return;
    if (!pixman_region32_contains_point(&constraint->region, (int)floor(seat->sx), (int)floor(seat->sy), NULL)) return;
    pointer->serial = ++pointer->next_serial;
    publish(pointer, pointer->serial);
}

static void created(struct wl_listener *listener, void *data) {
    (void)data;
    struct MdwPointer *pointer = wl_container_of(listener, pointer, created);
    mdw_pointer_refresh(pointer->server);
}

static void focus_changed(struct wl_listener *listener, void *data) {
    (void)data;
    struct MdwPointer *pointer = wl_container_of(listener, pointer, focus);
    mdw_pointer_refresh(pointer->server);
}

bool mdw_pointer_locked(MdwServer *server, MdwOutput *output) {
    struct MdwPointer *pointer = server->pointer;
    return pointer && pointer->owner == output && pointer->active;
}

bool mdw_pointer_capture(MdwServer *server, MdwOutput *output, uint64_t serial, bool captured) {
    struct MdwPointer *pointer = server->pointer;
    if (!pointer || !serial || serial != pointer->serial || output != pointer->owner) return false;
    if (captured) {
        if (!pointer->active) {
            pointer->active = true;
            wlr_pointer_constraint_v1_send_activated(pointer->constraint);
        }
    } else {
        bool active = pointer->active;
        pointer->active = false;
        pointer->declined = true;
        pointer->serial = 0;
        publish(pointer, 0);
        if (active) wlr_pointer_constraint_v1_send_deactivated(pointer->constraint);
    }
    return true;
}

void mdw_pointer_motion(MdwServer *server, double dx, double dy) {
    if (!server->pointer || (!dx && !dy)) return;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    wlr_relative_pointer_manager_v1_send_relative_motion(server->pointer->relative, server->seat,
        (uint64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000, dx, dy, dx, dy);
}

bool mdw_pointer_relative(MdwServer *server, MdwOutput *output, uint64_t serial, double dx, double dy) {
    if (!mdw_pointer_locked(server, output) || serial != server->pointer->serial) return false;
    mdw_pointer_motion(server, dx, dy);
    wlr_seat_pointer_notify_frame(server->seat);
    return true;
}

bool mdw_pointer_init(MdwServer *server) {
    struct wlr_pointer_constraints_v1 *constraints = wlr_pointer_constraints_v1_create(server->display);
    struct wlr_relative_pointer_manager_v1 *relative = wlr_relative_pointer_manager_v1_create(server->display);
    if (!constraints || !relative) return false;
    struct MdwPointer *pointer = calloc(1, sizeof(*pointer));
    if (!pointer) return false;
    server->pointer = pointer;
    pointer->server = server;
    pointer->constraints = constraints;
    pointer->relative = relative;
    listen(&constraints->events.new_constraint, &pointer->created, created);
    listen(&server->seat->pointer_state.events.focus_change, &pointer->focus, focus_changed);
    return true;
}

void mdw_pointer_finish(MdwServer *server) {
    struct MdwPointer *pointer = server->pointer;
    if (!pointer) return;
    clear(pointer, true);
    wl_list_remove(&pointer->created.link);
    wl_list_remove(&pointer->focus.link);
    free(pointer);
    server->pointer = NULL;
}
