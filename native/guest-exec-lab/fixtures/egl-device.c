#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "line %d: %s (EGL error %#x)\n", \
                __LINE__, #condition, eglGetError()); \
        return 1; \
    } \
} while (0)

static bool extension(const char *extensions, const char *name) {
    if (!extensions) return false;
    size_t length = strlen(name);
    for (const char *at = extensions; (at = strstr(at, name)); at += length) {
        if ((at == extensions || at[-1] == ' ') &&
            (at[length] == '\0' || at[length] == ' ')) return true;
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "hardware") && strcmp(argv[1], "software")) ||
            (strcmp(argv[2], "wayland") && strcmp(argv[2], "x11") && strcmp(argv[2], "surfaceless"))) {
        fprintf(stderr, "usage: egl-device hardware|software wayland|x11|surfaceless\n");
        return 2;
    }
    bool software = !strcmp(argv[1], "software");
    PFNEGLGETPLATFORMDISPLAYEXTPROC get_display =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    PFNEGLQUERYDISPLAYATTRIBEXTPROC query_display =
        (PFNEGLQUERYDISPLAYATTRIBEXTPROC)eglGetProcAddress("eglQueryDisplayAttribEXT");
    PFNEGLQUERYDEVICESTRINGEXTPROC query_device =
        (PFNEGLQUERYDEVICESTRINGEXTPROC)eglGetProcAddress("eglQueryDeviceStringEXT");
    PFNEGLQUERYDEVICESEXTPROC query_devices =
        (PFNEGLQUERYDEVICESEXTPROC)eglGetProcAddress("eglQueryDevicesEXT");
    CHECK(get_display && query_display && query_device && query_devices);
    EGLenum platform = EGL_PLATFORM_SURFACELESS_MESA;
    if (!strcmp(argv[2], "wayland")) platform = EGL_PLATFORM_WAYLAND_EXT;
    if (!strcmp(argv[2], "x11")) platform = EGL_PLATFORM_X11_EXT;
    EGLDeviceEXT previous = EGL_NO_DEVICE_EXT;
    EGLint previous_count = 0;
    for (int iteration = 0; iteration < 3; ++iteration) {
        EGLDisplay display = get_display(platform, EGL_DEFAULT_DISPLAY, NULL);
        CHECK(display != EGL_NO_DISPLAY);
        CHECK(eglInitialize(display, NULL, NULL));
        EGLAttrib value = 0;
        CHECK(query_display(display, EGL_DEVICE_EXT, &value));
        EGLDeviceEXT device = (EGLDeviceEXT)value;
        CHECK(device != EGL_NO_DEVICE_EXT);
        CHECK(previous == EGL_NO_DEVICE_EXT || previous == device);
        previous = device;
        const char *extensions = query_device(device, EGL_EXTENSIONS);
        CHECK(extensions);
        CHECK(extension(extensions, "EGL_MESA_device_software") == software);
        CHECK(!extension(extensions, "EGL_EXT_device_drm"));
        if (!software) {
            CHECK(!extension(extensions, "EGL_EXT_device_drm_render_node"));
            CHECK(!query_device(device, EGL_DRM_RENDER_NODE_FILE_EXT));
            CHECK(eglGetError() == EGL_BAD_PARAMETER);
        }
        CHECK(!query_device(device, EGL_DRM_DEVICE_FILE_EXT));
        CHECK(eglGetError() == EGL_BAD_PARAMETER);
        EGLint count = 0;
        CHECK(query_devices(0, NULL, &count));
        CHECK(count > 0 && count < 64);
        CHECK(iteration == 0 || count == previous_count);
        previous_count = count;
        EGLDeviceEXT devices[64];
        EGLint listed = 0;
        CHECK(query_devices(64, devices, &listed));
        CHECK(listed == count);
        int matches = 0;
        for (int i = 0; i < listed; ++i) matches += devices[i] == device;
        CHECK(matches == 1);
        CHECK(eglBindAPI(EGL_OPENGL_ES_API));
        EGLConfig config;
        EGLint configs;
        const EGLint attributes[] = {
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_SURFACE_TYPE, platform == EGL_PLATFORM_SURFACELESS_MESA ? EGL_PBUFFER_BIT : EGL_WINDOW_BIT,
            EGL_NONE
        };
        const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
        CHECK(eglChooseConfig(display, attributes, &config, 1, &configs) && configs);
        EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
        CHECK(context != EGL_NO_CONTEXT);
        CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, context));
        GLuint texture, framebuffer;
        glGenTextures(1, &texture);
        glBindTexture(GL_TEXTURE_2D, texture);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
        glGenFramebuffers(1, &framebuffer);
        glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
        CHECK(glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE);
        glClearColor(0, 1, 0, 1);
        glClear(GL_COLOR_BUFFER_BIT);
        unsigned char pixel[4] = {0};
        glReadPixels(0, 0, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
        CHECK(glGetError() == GL_NO_ERROR);
        CHECK(pixel[0] == 0 && pixel[1] == 255 && pixel[2] == 0 && pixel[3] == 255);
        printf("iteration=%d software=%d devices=%d renderer=%s pixel=0,255,0,255\n",
               iteration, software, count, glGetString(GL_RENDERER));
        glDeleteFramebuffers(1, &framebuffer);
        glDeleteTextures(1, &texture);
        CHECK(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT));
        CHECK(eglDestroyContext(display, context));
        CHECK(eglTerminate(display));
        CHECK(query_device(device, EGL_EXTENSIONS));
    }
    CHECK(eglReleaseThread());
    return 0;
}
