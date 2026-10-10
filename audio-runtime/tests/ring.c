#include "audio_ring.h"
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>

static struct md_audio_ring ring;
static void *produce(void *unused) {
    (void)unused;
    for (uint32_t i = 1; i <= 100000; i++) {
        float frame[2] = { (float)i, -(float)i };
        while (!md_audio_write(&ring, frame, 1)) sched_yield();
    }
    return NULL;
}
int main(void) {
    float *input = calloc(MD_AUDIO_CAPACITY * 2, sizeof(float));
    float *output = calloc(MD_AUDIO_CAPACITY * 2, sizeof(float));
    assert(input && output);
    for (unsigned i = 0; i < MD_AUDIO_CAPACITY * 2; i++) input[i] = (float)i;
    assert(md_audio_write(&ring, input, MD_AUDIO_CAPACITY) == MD_AUDIO_CAPACITY);
    assert(md_audio_write(&ring, input, 1) == 0);
    assert(md_audio_read(&ring, output, MD_AUDIO_CAPACITY, .5f) == MD_AUDIO_CAPACITY);
    for (unsigned i = 0; i < MD_AUDIO_CAPACITY * 2; i++) assert(output[i] == input[i] * .5f);
    assert(md_audio_read(&ring, output, 17, 1) == 0);
    for (unsigned i = 0; i < 34; i++) assert(output[i] == 0);
    atomic_store(&ring.read, UINT32_MAX - 10);
    atomic_store(&ring.write, UINT32_MAX - 10);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, produce, NULL) == 0);
    for (uint32_t i = 1; i <= 100000; ) {
        float frame[2];
        if (md_audio_read(&ring, frame, 1, 1)) {
            assert(frame[0] == i && frame[1] == -(float)i);
            i++;
        } else sched_yield();
    }
    assert(pthread_join(thread, NULL) == 0);
    assert(md_audio_available(&ring) == 0);
    free(input); free(output);
}
