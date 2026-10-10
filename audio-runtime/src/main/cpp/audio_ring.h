#pragma once
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#define MD_AUDIO_CHANNELS 2u
#define MD_AUDIO_CAPACITY 8192u

/* Single producer (PipeWire), single consumer (AAudio), stereo frames. */
struct md_audio_ring {
    _Atomic uint32_t read, write;
    float samples[MD_AUDIO_CAPACITY * MD_AUDIO_CHANNELS];
};
static inline uint32_t md_audio_available(struct md_audio_ring *r) {
    uint32_t read = atomic_load_explicit(&r->read, memory_order_acquire);
    uint32_t available = atomic_load_explicit(&r->write, memory_order_acquire) - read;
    return available < MD_AUDIO_CAPACITY ? available : MD_AUDIO_CAPACITY;
}
static inline uint32_t md_audio_write(struct md_audio_ring *r, const float *data, uint32_t frames) {
    uint32_t w = atomic_load_explicit(&r->write, memory_order_relaxed);
    uint32_t used = w - atomic_load_explicit(&r->read, memory_order_acquire);
    if (frames > MD_AUDIO_CAPACITY - used) frames = MD_AUDIO_CAPACITY - used;
    uint32_t offset = w % MD_AUDIO_CAPACITY;
    uint32_t first = frames < MD_AUDIO_CAPACITY - offset ? frames : MD_AUDIO_CAPACITY - offset;
    memcpy(r->samples + offset * 2, data, first * 2 * sizeof(float));
    memcpy(r->samples, data + first * 2, (frames - first) * 2 * sizeof(float));
    atomic_store_explicit(&r->write, w + frames, memory_order_release);
    return frames;
}
static inline uint32_t md_audio_read(struct md_audio_ring *r, float *data, uint32_t frames, float gain) {
    uint32_t start = atomic_load_explicit(&r->read, memory_order_relaxed);
    uint32_t available = atomic_load_explicit(&r->write, memory_order_acquire) - start;
    uint32_t count = frames < available ? frames : available;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t offset = ((start + i) % MD_AUDIO_CAPACITY) * 2;
        data[i * 2] = r->samples[offset] * gain;
        data[i * 2 + 1] = r->samples[offset + 1] * gain;
    }
    memset(data + count * 2, 0, (frames - count) * 2 * sizeof(float));
    atomic_store_explicit(&r->read, start + count, memory_order_release);
    return count;
}
