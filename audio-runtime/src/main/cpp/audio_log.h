#ifndef MD_AUDIO_LOG_H
#define MD_AUDIO_LOG_H

#include <android/log.h>
#include <pipewire/log.h>

static void audio_logv(void *data, enum spa_log_level level, const char *file,
        int line, const char *function, const char *format, va_list args) {
    int priority = level == SPA_LOG_LEVEL_ERROR ? ANDROID_LOG_ERROR
            : level == SPA_LOG_LEVEL_WARN ? ANDROID_LOG_WARN : ANDROID_LOG_INFO;
    __android_log_vprint(priority, "MagicDeskPipeWire", format, args);
}
static void audio_log(void *data, enum spa_log_level level, const char *file,
        int line, const char *function, const char *format, ...) {
    va_list args;
    va_start(args, format);
    audio_logv(data, level, file, line, function, format, args);
    va_end(args);
}
static const struct spa_log_methods audio_log_methods = {
    .version = 0, .log = audio_log, .logv = audio_logv
};
static struct spa_log audio_logger = {
    .iface = SPA_INTERFACE_INIT(SPA_TYPE_INTERFACE_Log, SPA_VERSION_LOG, &audio_log_methods, NULL),
    .level = SPA_LOG_LEVEL_WARN
};

#endif
