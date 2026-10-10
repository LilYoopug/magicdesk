#include <pipewire/pipewire.h>
#include <spa/param/audio/format-utils.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

struct fixture {
    struct pw_main_loop *loop;
    struct pw_stream *stream;
    unsigned frames;
    int failed;
    bool draining;
};
static void drained(void *data) { pw_main_loop_quit(((struct fixture *)data)->loop); }
static void state(void *data, enum pw_stream_state old, enum pw_stream_state now, const char *error) {
    struct fixture *f = data;
    if (now == PW_STREAM_STATE_ERROR || (now == PW_STREAM_STATE_UNCONNECTED && old != now)) {
        fprintf(stderr, "stream error: %s\n", error);
        f->failed = 1;
        pw_main_loop_quit(f->loop);
    }
}
static void process(void *data) {
    struct fixture *f = data;
    struct pw_buffer *b = pw_stream_dequeue_buffer(f->stream);
    if (!b) return;
    struct spa_data *d = &b->buffer->datas[0];
    unsigned frames = SPA_MIN(d->maxsize / 8, b->requested ? b->requested : 256);
    if (f->frames + frames > 48000) frames = 48000 - f->frames;
    if (!d->data) { f->failed = 1; frames = 0; }
    else memset(d->data, 0, frames * 8);
    d->chunk->offset = 0;
    d->chunk->stride = 8;
    d->chunk->size = frames * 8;
    f->frames += frames;
    pw_stream_queue_buffer(f->stream, b);
    if (f->frames == 48000 && !f->draining) {
        f->draining = true;
        pw_stream_flush(f->stream, true);
    }
}
static const struct pw_stream_events events = {
    PW_VERSION_STREAM_EVENTS, .state_changed = state, .process = process, .drained = drained
};
struct denied_fixture { struct pw_main_loop *loop; int denied, sync; };
static void denied_error(void *data, uint32_t id, int seq, int res, const char *message) {
    struct denied_fixture *f = data;
    if (id != PW_ID_CORE && (res == -EACCES || res == -ENOENT || res == -EPERM)) f->denied = 1;
    fprintf(stderr, "factory denial id=%u result=%d: %s\n", id, res, message);
}
static void denied_done(void *data, uint32_t id, int seq) {
    struct denied_fixture *f = data;
    if (id == PW_ID_CORE && seq == f->sync) pw_main_loop_quit(f->loop);
}
static int check_denied_factory(void) {
    struct denied_fixture f = { .loop = pw_main_loop_new(NULL) };
    struct pw_context *context = pw_context_new(pw_main_loop_get_loop(f.loop), NULL, 0);
    struct pw_core *core = pw_context_connect(context,
            pw_properties_new("magicdesk.audio.external", "false", NULL), 0);
    if (!core) return 2;
    struct spa_hook listener;
    const struct pw_core_events events = { PW_VERSION_CORE_EVENTS, .done = denied_done, .error = denied_error };
    pw_core_add_listener(core, &listener, &events, &f);
    struct pw_proxy *proxy = pw_core_create_object(core, "adapter", PW_TYPE_INTERFACE_Node,
            PW_VERSION_NODE, NULL, 0);
    f.sync = pw_core_sync(core, PW_ID_CORE, 0);
    /* EVENT_WAIT: protocol rejection and following sync; caller supplies failure deadline. */
    pw_main_loop_run(f.loop);
    if (proxy) pw_proxy_destroy(proxy);
    spa_hook_remove(&listener);
    pw_core_disconnect(core);
    pw_context_destroy(context);
    pw_main_loop_destroy(f.loop);
    return !f.denied;
}
int main(int argc, char **argv) {
    pw_init(NULL, NULL);
    if (argc == 2 && strcmp(argv[1], "--deny-adapter") == 0) {
        int result = check_denied_factory();
        pw_deinit();
        return result;
    }
    struct fixture f = {0};
    f.loop = pw_main_loop_new(NULL);
    f.stream = pw_stream_new_simple(pw_main_loop_get_loop(f.loop), "MagicDesk audio fixture",
            pw_properties_new(PW_KEY_MEDIA_TYPE, "Audio", PW_KEY_MEDIA_CATEGORY, "Playback",
                PW_KEY_MEDIA_ROLE, "Music", NULL), &events, &f);
    if (!f.stream) return 2;
    uint8_t bytes[1024];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(bytes, sizeof(bytes));
    struct spa_audio_info_raw format = { .format = SPA_AUDIO_FORMAT_F32, .rate = 48000, .channels = 2,
        .position = {SPA_AUDIO_CHANNEL_FL, SPA_AUDIO_CHANNEL_FR} };
    const struct spa_pod *params[] = { spa_format_audio_raw_build(&builder, SPA_PARAM_EnumFormat, &format) };
    if (pw_stream_connect(f.stream, PW_DIRECTION_OUTPUT, PW_ID_ANY,
                PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS, params, 1) < 0) return 3;
    /* EVENT_WAIT: actual stream drain; the external test runner owns the failure deadline. */
    pw_main_loop_run(f.loop);
    fprintf(stderr, "native client frames=%u failed=%d\n", f.frames, f.failed);
    int failed = f.failed || f.frames != 48000;
    pw_stream_destroy(f.stream);
    pw_main_loop_destroy(f.loop);
    pw_deinit();
    return failed;
}
