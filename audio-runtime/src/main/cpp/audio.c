#define _GNU_SOURCE
#include <aaudio/AAudio.h>
#include <android/log.h>
#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <signal.h>
#include <pipewire/impl.h>
#include <pipewire/thread-loop.h>
#include <spa/param/audio/format-utils.h>
#include <spa/param/port-config.h>
#include "audio_ring.h"
#include "audio_log.h"

#define JNI(name) Java_io_github_mekhontsev_magicdesk_audio_AudioEngine_##name
#define RATE 48000
#define QUANTUM 256
#define LOG(...) __android_log_print(ANDROID_LOG_ERROR, "MagicDeskAudio", __VA_ARGS__)

struct owner {
    struct spa_list link, clients;
    char id[64];
};
struct connection {
    struct spa_list link;
    struct spa_hook listener;
    struct pw_impl_client *client;
};
struct playback_node {
    struct spa_list link;
    struct spa_hook listener;
    struct pw_impl_node *node;
};
struct engine {
    struct pw_thread_loop *thread;
    struct pw_loop *loop;
    struct pw_context *context;
    struct pw_core *core;
    struct pw_stream *sink;
    struct spa_hook context_listener, stream_listener;
    struct spa_source *clock_source, *policy_event;
    struct md_audio_ring ring;
    void *native_module, *pulse_module, *pulse;
    struct pw_impl_client *(*native_accept)(struct pw_protocol *, int);
    int (*pulse_accept)(void *, int, void *);
    void (*pulse_disconnect)(void *, void *);
    void (*pulse_destroy)(void *);
    struct spa_list owners, playback_nodes;
    int event_fd, clock_fd;
    AAudioStream *output;
    bool allowed, running, destroying, admitting;
    _Atomic bool active, in_flight;
    _Atomic int output_error;
    _Atomic float gain;
    _Atomic uint64_t received, rendered, silence, overruns, nonzero, callbacks;
};

static void signal_fd(int fd) {
    uint64_t one = 1;
    if (write(fd, &one, sizeof(one)) < 0 && errno != EAGAIN) { /* Owner closes after callbacks stop. */ }
}
static void drain_fd(int fd) {
    uint64_t count;
    while (read(fd, &count, sizeof(count)) > 0) { }
}
static aaudio_data_callback_result_t output_data(AAudioStream *stream, void *data,
        void *audio, int32_t frames) {
    struct engine *e = data;
    uint32_t read = md_audio_read(&e->ring, audio, (uint32_t)frames,
            atomic_load_explicit(&e->gain, memory_order_relaxed));
    atomic_fetch_add_explicit(&e->rendered, read, memory_order_relaxed);
    atomic_fetch_add_explicit(&e->silence, (uint32_t)frames - read, memory_order_relaxed);
    atomic_fetch_add_explicit(&e->callbacks, 1, memory_order_relaxed);
    signal_fd(e->clock_fd);
    return AAUDIO_CALLBACK_RESULT_CONTINUE;
}
static void output_error(AAudioStream *stream, void *data, aaudio_result_t error) {
    struct engine *e = data;
    atomic_store(&e->output_error, error);
    signal_fd(e->event_fd);
}
static void close_output(struct engine *e) {
    if (!e->output) return;
    AAudioStream_requestStop(e->output);
    AAudioStream_close(e->output);
    e->output = NULL;
}
static int open_output(struct engine *e) {
    AAudioStreamBuilder *builder = NULL;
    aaudio_result_t res = AAudio_createStreamBuilder(&builder);
    if (res != AAUDIO_OK) return res;
    AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_OUTPUT);
    AAudioStreamBuilder_setSharingMode(builder, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setPerformanceMode(builder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    AAudioStreamBuilder_setUsage(builder, AAUDIO_USAGE_MEDIA);
    AAudioStreamBuilder_setContentType(builder, AAUDIO_CONTENT_TYPE_MUSIC);
    AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_FLOAT);
    AAudioStreamBuilder_setChannelCount(builder, MD_AUDIO_CHANNELS);
    AAudioStreamBuilder_setSampleRate(builder, RATE);
    AAudioStreamBuilder_setDataCallback(builder, output_data, e);
    AAudioStreamBuilder_setErrorCallback(builder, output_error, e);
    res = AAudioStreamBuilder_openStream(builder, &e->output);
    AAudioStreamBuilder_delete(builder);
    if (res != AAUDIO_OK) return res;
    if (AAudioStream_getChannelCount(e->output) != MD_AUDIO_CHANNELS
            || AAudioStream_getSampleRate(e->output) != RATE
            || AAudioStream_getFormat(e->output) != AAUDIO_FORMAT_PCM_FLOAT) {
        close_output(e);
        return AAUDIO_ERROR_INVALID_FORMAT;
    }
    int burst = AAudioStream_getFramesPerBurst(e->output);
    AAudioStream_setBufferSizeInFrames(e->output, burst * 2);
    res = AAudioStream_requestStart(e->output);
    if (res != AAUDIO_OK) close_output(e);
    return res;
}

static void process_audio(void *data) {
    struct engine *e = data;
    struct pw_buffer *buffer;
    if ((buffer = pw_stream_dequeue_buffer(e->sink)) == NULL) return;
    if (buffer->buffer->n_datas > 0) {
        struct spa_data *d = &buffer->buffer->datas[0];
        if (d->data && d->chunk && d->chunk->offset <= d->maxsize) {
            uint32_t size = SPA_MIN(d->chunk->size, d->maxsize - d->chunk->offset);
            const float *samples = SPA_PTROFF(d->data, d->chunk->offset, const float);
            uint32_t frames = size / (sizeof(float) * MD_AUDIO_CHANNELS);
            uint32_t written = md_audio_write(&e->ring, samples, frames);
            atomic_fetch_add_explicit(&e->received, frames, memory_order_relaxed);
            if (frames != written) atomic_fetch_add_explicit(&e->overruns, frames - written, memory_order_relaxed);
            for (uint32_t i = 0; i < frames * MD_AUDIO_CHANNELS; i++) {
                if (samples[i] != 0) { atomic_fetch_add_explicit(&e->nonzero, 1, memory_order_relaxed); break; }
            }
        }
    }
    pw_stream_queue_buffer(e->sink, buffer);
}
static void trigger_done(void *data) {
    struct engine *e = data;
    atomic_store_explicit(&e->in_flight, false, memory_order_release);
    if (md_audio_available(&e->ring) < QUANTUM * 2) signal_fd(e->clock_fd);
}
static void stream_state(void *data, enum pw_stream_state old,
        enum pw_stream_state state, const char *error) {
    struct engine *e = data;
    bool active = state == PW_STREAM_STATE_STREAMING;
    if (atomic_exchange(&e->active, active) != active) signal_fd(e->event_fd);
    if (state == PW_STREAM_STATE_ERROR) {
        LOG("PipeWire output: %s", error ? error : "unknown error");
        atomic_store(&e->output_error, -EIO);
        signal_fd(e->event_fd);
    }
}
static const struct pw_stream_events stream_events = {
    PW_VERSION_STREAM_EVENTS, .state_changed = stream_state,
    .process = process_audio, .trigger_done = trigger_done
};
static void clock_ready(void *data, int fd, uint32_t mask) {
    struct engine *e = data;
    drain_fd(fd);
    if (!e->allowed || !atomic_load(&e->active) || md_audio_available(&e->ring) >= QUANTUM * 2) return;
    if (!atomic_exchange(&e->in_flight, true)) {
        if (pw_stream_trigger_process(e->sink) < 0) atomic_store(&e->in_flight, false);
    }
}

struct ports { struct pw_impl_port *input[2]; struct engine *engine; };
struct link_match { struct pw_impl_port *input, *output; };
static int existing_link(void *data, struct pw_global *global) {
    struct link_match *match = data;
    if (!pw_global_is_type(global, PW_TYPE_INTERFACE_Link)) return 0;
    struct pw_impl_link *link = pw_global_get_object(global);
    return pw_impl_link_get_input(link) == match->input && pw_impl_link_get_output(link) == match->output;
}
static int collect_input(void *data, struct pw_impl_port *port) {
    struct ports *p = data;
    const char *channel = pw_properties_get(pw_impl_port_get_properties(port), PW_KEY_AUDIO_CHANNEL);
    if (channel && spa_streq(channel, "FL")) p->input[0] = port;
    else if (channel && spa_streq(channel, "FR")) p->input[1] = port;
    return 0;
}
static int connect_output(void *data, struct pw_impl_port *port) {
    struct ports *p = data;
    const char *channel = pw_properties_get(pw_impl_port_get_properties(port), PW_KEY_AUDIO_CHANNEL);
    int index = channel && spa_streq(channel, "FL") ? 0 : channel && spa_streq(channel, "FR") ? 1 : -1;
    if (index < 0 || !p->input[index]) return 0;
    struct link_match match = { p->input[index], port };
    if (pw_context_for_each_global(p->engine->context, existing_link, &match)) return 0;
    struct pw_impl_link *link = pw_context_create_link(p->engine->context, port, p->input[index],
            NULL, NULL, 0);
    if (!link) { LOG("Cannot link playback: %s", strerror(errno)); return 0; }
    if (pw_impl_link_register(link, NULL) < 0) pw_impl_link_destroy(link);
    return 0;
}
static void playback_node_destroyed(void *data) {
    struct playback_node *node = data;
    spa_hook_remove(&node->listener);
    spa_list_remove(&node->link);
    free(node);
}
static const struct pw_impl_node_events playback_node_events = {
    PW_VERSION_IMPL_NODE_EVENTS, .destroy = playback_node_destroyed
};
static int connect_node(void *data, struct pw_global *global) {
    struct ports *p = data;
    if (!pw_global_is_type(global, PW_TYPE_INTERFACE_Node)) return 0;
    struct pw_impl_node *node = pw_global_get_object(global);
    const char *type = pw_properties_get(pw_impl_node_get_properties(node), PW_KEY_MEDIA_CLASS);
    if (type && spa_streq(type, "Stream/Output/Audio")) {
        if (pw_impl_node_get_info(node)->n_output_ports == 0) {
            struct playback_node *known;
            bool configured = false;
            spa_list_for_each(known, &p->engine->playback_nodes, link)
                if (known->node == node) { configured = true; break; }
            if (!configured) {
                uint8_t bytes[1024], format_bytes[512];
                struct spa_pod_builder b = SPA_POD_BUILDER_INIT(bytes, sizeof(bytes));
                struct spa_pod_builder fb = SPA_POD_BUILDER_INIT(format_bytes, sizeof(format_bytes));
                struct spa_audio_info_raw format = { .format = SPA_AUDIO_FORMAT_F32P, .rate = RATE,
                    .channels = 2, .position = { SPA_AUDIO_CHANNEL_FL, SPA_AUDIO_CHANNEL_FR } };
                const struct spa_pod *pod = spa_pod_builder_add_object(&b, SPA_TYPE_OBJECT_ParamPortConfig,
                        SPA_PARAM_PortConfig, SPA_PARAM_PORT_CONFIG_direction, SPA_POD_Id(SPA_DIRECTION_OUTPUT),
                        SPA_PARAM_PORT_CONFIG_mode, SPA_POD_Id(SPA_PARAM_PORT_CONFIG_MODE_dsp),
                        SPA_PARAM_PORT_CONFIG_monitor, SPA_POD_Bool(false),
                        SPA_PARAM_PORT_CONFIG_control, SPA_POD_Bool(false),
                        SPA_PARAM_PORT_CONFIG_format, SPA_POD_Pod(spa_format_audio_raw_build(&fb, SPA_PARAM_EnumFormat, &format)));
                known = calloc(1, sizeof(*known));
                if (known) {
                    known->node = node;
                    spa_list_append(&p->engine->playback_nodes, &known->link);
                    pw_impl_node_add_listener(node, &known->listener, &playback_node_events, known);
                    int result = pw_impl_node_set_param(node, SPA_PARAM_PortConfig, 0, pod);
                    if (result < 0) LOG("Cannot configure playback ports: %s", strerror(-result));
                }
            }
        }
        pw_impl_node_for_each_port(node, PW_DIRECTION_OUTPUT, connect_output, p);
    }
    return 0;
}
static void reconcile(void *data, uint64_t count) {
    struct engine *e = data;
    if (e->destroying || !e->sink) return;
    struct pw_global *global = pw_context_find_global(e->context, pw_stream_get_node_id(e->sink));
    if (!global) return;
    struct ports ports = { .engine = e };
    pw_impl_node_for_each_port(pw_global_get_object(global), PW_DIRECTION_INPUT, collect_input, &ports);
    pw_context_for_each_global(e->context, connect_node, &ports);
}
static void global_changed(void *data, struct pw_global *global) {
    struct engine *e = data;
    if (!e->destroying && e->policy_event && (pw_global_is_type(global, PW_TYPE_INTERFACE_Port)
            || pw_global_is_type(global, PW_TYPE_INTERFACE_Node)))
        pw_loop_signal_event(e->loop, e->policy_event);
}
static int restrict_factory(void *data, struct pw_global *global) {
    if (!pw_global_is_type(global, PW_TYPE_INTERFACE_Factory)) return 0;
    struct pw_impl_factory *factory = pw_global_get_object(global);
    if (!spa_streq(pw_impl_factory_get_info(factory)->name, "client-node")) {
        const struct pw_permission permission = { pw_global_get_id(global), 0 };
        pw_impl_client_update_permissions(data, 1, &permission);
    }
    return 0;
}
static void check_access(void *data, struct pw_impl_client *client) {
    struct engine *e = data;
    bool external = e->admitting;
    struct owner *owner;
    struct connection *connection;
    spa_list_for_each(owner, &e->owners, link)
        spa_list_for_each(connection, &owner->clients, link)
            if (connection->client == client) external = true;
    const struct pw_permission permissions[] = {
        { PW_ID_ANY, external ? PW_PERM_R : PW_PERM_ALL },
        { PW_ID_CORE, PW_PERM_ALL }
    };
    pw_impl_client_update_permissions(client, 2, permissions);
    if (external) pw_context_for_each_global(e->context, restrict_factory, client);
}
static const struct pw_context_events context_events = {
    PW_VERSION_CONTEXT_EVENTS, .check_access = check_access,
    .global_added = global_changed, .global_removed = global_changed
};
static void connection_destroyed(void *data) {
    struct connection *c = data;
    spa_hook_remove(&c->listener);
    spa_list_remove(&c->link);
    free(c);
}
static const struct pw_impl_client_events client_events = {
    PW_VERSION_IMPL_CLIENT_EVENTS, .destroy = connection_destroyed
};
static void release_owner(struct engine *e, struct owner *owner) {
    struct connection *c, *next;
    spa_list_for_each_safe(c, next, &owner->clients, link) pw_impl_client_destroy(c->client);
    if (e->pulse) e->pulse_disconnect(e->pulse, owner);
    spa_list_remove(&owner->link);
    free(owner);
}
static struct owner *find_owner(struct engine *e, const char *id, bool create) {
    struct owner *owner;
    spa_list_for_each(owner, &e->owners, link) if (spa_streq(owner->id, id)) return owner;
    if (!create || strlen(id) >= sizeof(owner->id)) return NULL;
    owner = calloc(1, sizeof(*owner));
    if (!owner) return NULL;
    strcpy(owner->id, id);
    spa_list_init(&owner->clients);
    spa_list_append(&e->owners, &owner->link);
    return owner;
}
static void release_engine(struct engine *e) {
    if (!e) return;
    close_output(e);
    if (e->running) pw_thread_loop_stop(e->thread);
    e->destroying = true;
    struct owner *owner, *next;
    spa_list_for_each_safe(owner, next, &e->owners, link) release_owner(e, owner);
    if (e->pulse) e->pulse_destroy(e->pulse);
    if (e->sink) pw_stream_destroy(e->sink);
    if (e->core) pw_core_disconnect(e->core);
    if (e->context) pw_context_destroy(e->context);
    if (e->clock_source) pw_loop_destroy_source(e->loop, e->clock_source);
    if (e->policy_event) pw_loop_destroy_source(e->loop, e->policy_event);
    if (e->thread) pw_thread_loop_destroy(e->thread);
    if (e->clock_fd >= 0) close(e->clock_fd);
    if (e->event_fd >= 0) close(e->event_fd);
    if (e->pulse_module) dlclose(e->pulse_module);
    if (e->native_module) dlclose(e->native_module);
    pw_deinit();
    free(e);
}

static struct engine *create_engine(const char *directory, const char *libraries) {
    struct engine *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->event_fd = e->clock_fd = -1;
    spa_list_init(&e->owners);
    spa_list_init(&e->playback_nodes);
    atomic_init(&e->gain, 1);
    setenv("PIPEWIRE_MODULE_DIR", libraries, 1);
    setenv("SPA_PLUGIN_DIR", libraries, 1);
    setenv("SPA_SUPPORT_LIB", "libspa-support", 1);
    setenv("PIPEWIRE_CONFIG_DIR", directory, 1);
    setenv("PIPEWIRE_RUNTIME_DIR", directory, 1);
    setenv("PULSE_RUNTIME_PATH", directory, 1);
    setenv("XDG_RUNTIME_DIR", directory, 1);
    pw_init(NULL, NULL);
#ifndef MD_AUDIO_TEST_HOST
    pw_log_set(&audio_logger);
    pw_log_set_level(SPA_LOG_LEVEL_WARN);
#endif
    e->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    e->clock_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (e->event_fd < 0 || e->clock_fd < 0) goto error;
    e->thread = pw_thread_loop_new("MagicDeskAudio", NULL);
    if (!e->thread) goto error;
    e->loop = pw_thread_loop_get_loop(e->thread);
    e->context = pw_context_new(e->loop, pw_properties_new("config.name", "pipewire.conf", NULL), 0);
    if (!e->context) goto error;
    pw_context_add_listener(e->context, &e->context_listener, &context_events, e);
    char module[4096];
    snprintf(module, sizeof(module), "%s/libpipewire-module-protocol-native.so", libraries);
    e->native_module = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    snprintf(module, sizeof(module), "%s/libpipewire-module-protocol-pulse.so", libraries);
    e->pulse_module = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!e->native_module || !e->pulse_module) goto error;
    e->native_accept = dlsym(e->native_module, "magicdesk_native_accept");
    e->pulse_accept = dlsym(e->pulse_module, "magicdesk_pulse_accept");
    e->pulse_disconnect = dlsym(e->pulse_module, "magicdesk_pulse_disconnect");
    e->pulse_destroy = dlsym(e->pulse_module, "pw_protocol_pulse_destroy");
    void *(*pulse_new)(struct pw_context *, struct pw_properties *, size_t) =
            dlsym(e->pulse_module, "pw_protocol_pulse_new");
    if (!e->native_accept || !e->pulse_accept || !e->pulse_disconnect || !e->pulse_destroy || !pulse_new) goto error;
    e->pulse = pulse_new(e->context, pw_properties_new(
            "config.name", "pipewire.conf", "server.address", "[ \"unix:pulse-native\" ]",
            "pulse.allow-module-loading", "false", "pulse.min.req", "256/48000",
            "pulse.default.req", "512/48000", "pulse.default.tlength", "2048/48000",
            "pulse.min.quantum", "256/48000", "pulse.idle.timeout", "1", NULL), 0);
    if (!e->pulse) goto error;
    e->core = pw_context_connect_self(e->context, NULL, 0);
    if (!e->core) goto error;
    e->policy_event = pw_loop_add_event(e->loop, reconcile, e);
    e->clock_source = pw_loop_add_io(e->loop, e->clock_fd, SPA_IO_IN, false, clock_ready, e);
    if (!e->policy_event || !e->clock_source) goto error;
    e->sink = pw_stream_new(e->core, "Android audio", pw_properties_new(
            PW_KEY_NODE_NAME, "magicdesk.android", PW_KEY_NODE_DESCRIPTION, "Android audio",
            PW_KEY_MEDIA_CLASS, "Audio/Sink", PW_KEY_NODE_VIRTUAL, "false",
            PW_KEY_NODE_WANT_DRIVER, "false", PW_KEY_NODE_LATENCY, "256/48000",
            "node.force-quantum", "256", "node.force-rate", "48000",
            "adapter.auto-port-config", "{ mode = dsp monitor = false control = false position = preserve }", NULL));
    if (!e->sink) goto error;
    pw_stream_add_listener(e->sink, &e->stream_listener, &stream_events, e);
    uint8_t bytes[1024];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(bytes, sizeof(bytes));
    struct spa_audio_info_raw format = { .format = SPA_AUDIO_FORMAT_F32, .rate = RATE, .channels = 2,
        .position = { SPA_AUDIO_CHANNEL_FL, SPA_AUDIO_CHANNEL_FR } };
    const struct spa_pod *params[] = { spa_format_audio_raw_build(&builder, SPA_PARAM_EnumFormat, &format) };
    if (pw_stream_connect(e->sink, PW_DIRECTION_INPUT, PW_ID_ANY,
            PW_STREAM_FLAG_DRIVER | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_RT_PROCESS
            | PW_STREAM_FLAG_RT_TRIGGER_DONE, params, 1) < 0) goto error;
    if (pw_thread_loop_start(e->thread) < 0) goto error;
    e->running = true;
    return e;
error:
    LOG("Audio initialization failed: %s (%s)", strerror(errno), dlerror());
    release_engine(e);
    return NULL;
}

JNIEXPORT jlong JNICALL JNI(create)(JNIEnv *env, jclass type, jstring directory, jstring libraries) {
    const char *dir = (*env)->GetStringUTFChars(env, directory, NULL);
    if (!dir) return 0;
    const char *libs = (*env)->GetStringUTFChars(env, libraries, NULL);
    struct engine *e = libs ? create_engine(dir, libs) : NULL;
    if (libs) (*env)->ReleaseStringUTFChars(env, libraries, libs);
    (*env)->ReleaseStringUTFChars(env, directory, dir);
    return (jlong)(intptr_t)e;
}
JNIEXPORT jint JNICALL JNI(eventFd)(JNIEnv *env, jclass type, jlong handle) {
    return ((struct engine *)(intptr_t)handle)->event_fd;
}
JNIEXPORT jlongArray JNICALL JNI(snapshot)(JNIEnv *env, jclass type, jlong handle) {
    struct engine *e = (void *)(intptr_t)handle;
    jlong values[] = { atomic_load(&e->active), atomic_load(&e->output_error),
        atomic_load(&e->received), atomic_load(&e->rendered), atomic_load(&e->silence),
        atomic_load(&e->overruns), atomic_load(&e->nonzero), atomic_load(&e->callbacks),
        md_audio_available(&e->ring), e->output ? AAudioStream_getXRunCount(e->output) : 0 };
    jlongArray result = (*env)->NewLongArray(env, SPA_N_ELEMENTS(values));
    if (result) (*env)->SetLongArrayRegion(env, result, 0, SPA_N_ELEMENTS(values), values);
    return result;
}
JNIEXPORT void JNICALL JNI(acknowledge)(JNIEnv *env, jclass type, jlong handle) {
    drain_fd(((struct engine *)(intptr_t)handle)->event_fd);
}
JNIEXPORT void JNICALL JNI(revoke)(JNIEnv *env, jclass type, jlong handle, jstring id) {
    struct engine *e = (void *)(intptr_t)handle;
    const char *name = (*env)->GetStringUTFChars(env, id, NULL);
    if (!name) return;
    pw_thread_loop_lock(e->thread);
    struct owner *owner = find_owner(e, name, false);
    if (owner) release_owner(e, owner);
    pw_thread_loop_unlock(e->thread);
    (*env)->ReleaseStringUTFChars(env, id, name);
}
JNIEXPORT void JNICALL JNI(playback)(JNIEnv *env, jclass type, jlong handle, jboolean allowed, jboolean duck) {
    struct engine *e = (void *)(intptr_t)handle;
    atomic_store(&e->gain, duck ? .2f : 1.f);
    /* Control thread only; AAudio close must never run on its error/data callback. */
    if (!allowed || atomic_load(&e->output_error)) close_output(e);
    pw_thread_loop_lock(e->thread);
    e->allowed = allowed;
    if (!allowed) atomic_store(&e->ring.read, atomic_load(&e->ring.write));
    pw_thread_loop_unlock(e->thread);
    if (allowed && !e->output) {
        atomic_store(&e->output_error, 0);
        int result = open_output(e);
        if (result != AAUDIO_OK) { atomic_store(&e->output_error, result); signal_fd(e->event_fd); }
        else signal_fd(e->clock_fd);
    }
}
JNIEXPORT jint JNICALL JNI(accept)(JNIEnv *env, jclass type, jlong handle, jint protocol, jint fd, jstring owner) {
    struct engine *e = (void *)(intptr_t)handle;
    const char *id = (*env)->GetStringUTFChars(env, owner, NULL);
    if (!id) { close(fd); return -ENOMEM; }
    int res = fcntl(fd, F_GETFL);
    if (res < 0 || fcntl(fd, F_SETFL, res | O_NONBLOCK) < 0) { res = -errno; close(fd); }
    else {
        pw_thread_loop_lock(e->thread);
        struct owner *owner = find_owner(e, id, true);
        if (!owner) { close(fd); res = -ENOMEM; }
        else if (protocol == 0) {
            struct connection *c = calloc(1, sizeof(*c));
            if (!c) { close(fd); res = -ENOMEM; }
            else {
                e->admitting = true;
                c->client = e->native_accept(pw_context_find_protocol(e->context, PW_TYPE_INFO_Protocol ":Native"), fd);
                e->admitting = false;
                if (!c->client) { res = -errno; free(c); }
                else {
                    spa_list_append(&owner->clients, &c->link);
                    pw_impl_client_add_listener(c->client, &c->listener, &client_events, c);
                    res = 0;
                }
            }
        }
        else if (protocol == 1) res = e->pulse_accept(e->pulse, fd, owner);
        else { close(fd); res = -EINVAL; }
        pw_thread_loop_unlock(e->thread);
    }
    (*env)->ReleaseStringUTFChars(env, owner, id);
    return res;
}
JNIEXPORT void JNICALL JNI(destroy)(JNIEnv *env, jclass type, jlong handle) {
    release_engine((void *)(intptr_t)handle);
}

#ifdef MD_AUDIO_TEST_HOST
static volatile sig_atomic_t stopped;
static void stop_test(int signal) { stopped = 1; }
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    signal(SIGTERM, stop_test);
    signal(SIGINT, stop_test);
    struct engine *e = create_engine(argv[1], argv[2]);
    if (!e) return 1;
    fprintf(stderr, "audio-ready\n");
    while (!stopped) {
        struct pollfd fd = { e->event_fd, POLLIN, 0 };
        /* EVENT_WAIT: graph demand or SIGTERM; test runner owns the failure deadline. */
        if (poll(&fd, 1, -1) < 0) { if (errno == EINTR) continue; break; }
        drain_fd(e->event_fd);
        bool active = atomic_load(&e->active);
        fprintf(stderr, "active=%d received=%lu rendered=%lu nonzero=%lu error=%d\n", active,
                atomic_load(&e->received), atomic_load(&e->rendered), atomic_load(&e->nonzero),
                atomic_load(&e->output_error));
        JNI(playback)(NULL, NULL, (jlong)(intptr_t)e, active, false);
    }
    fprintf(stderr, "final received=%lu rendered=%lu nonzero=%lu callbacks=%lu overruns=%lu\n",
            atomic_load(&e->received), atomic_load(&e->rendered), atomic_load(&e->nonzero),
            atomic_load(&e->callbacks), atomic_load(&e->overruns));
    release_engine(e);
    return 0;
}
#endif
