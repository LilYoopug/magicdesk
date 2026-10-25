#define _POSIX_C_SOURCE 200809L
/* Exercise advertised GLX callbacks and their actual X11 presentation. */
#include <GL/gl.h>
#include <GL/glx.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>

static int has_extension(const char *extensions, const char *name)
{
    size_t length = strlen(name);
    const char *match = extensions;
    while (match && (match = strstr(match, name))) {
        if ((match == extensions || match[-1] == ' ') &&
            (match[length] == '\0' || match[length] == ' '))
            return 1;
        match += length;
    }
    return 0;
}

static int expected_pixel(unsigned long pixel)
{
    return (pixel & 0xffffff) == 0x33994c ||
           (pixel & 0xffffff) == 0x33994d;
}

static int await_pixel(Display *display, Window window)
{
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    unsigned long pixel = 0;
    /* Bounded state probe: Vulkan presentation may follow GL completion.
     * Expiry fails the frame; a polling interval is not a readiness claim. */
    do {
        XImage *image = XGetImage(display, window, 80, 60, 1, 1, AllPlanes, ZPixmap);
        if (!image)
            return 5;
        pixel = XGetPixel(image, 0, 0);
        XDestroyImage(image);
        if (expected_pixel(pixel)) {
            printf("presented_pixel=%#lx\n", pixel);
            return 0;
        }
        struct timespec interval = {.tv_nsec = 10000000};
        nanosleep(&interval, NULL);
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((now.tv_sec - start.tv_sec) * 1000000000LL +
             now.tv_nsec - start.tv_nsec < 2000000000LL);
    fprintf(stderr, "unexpected presented_pixel=%#lx\n", pixel);
    return 6;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "0") && strcmp(argv[1], "1")))
        return 64;
    Display *display = XOpenDisplay(NULL);
    if (!display)
        return 1;
    int attributes[] = {GLX_RGBA, GLX_DOUBLEBUFFER, None};
    XVisualInfo *visual = glXChooseVisual(display, DefaultScreen(display), attributes);
    if (!visual)
        return 2;
    XSetWindowAttributes options = {0};
    options.event_mask = StructureNotifyMask;
    options.override_redirect = True;
    options.colormap = XCreateColormap(display, RootWindow(display, visual->screen),
                                      visual->visual, AllocNone);
    Window window = XCreateWindow(display, RootWindow(display, visual->screen),
        0, 0, 160, 120, 0, visual->depth, InputOutput, visual->visual,
        CWColormap | CWEventMask | CWOverrideRedirect, &options);
    GLXContext context = glXCreateContext(display, visual, NULL, True);
    if (!context || !glXMakeCurrent(display, window, context))
        return 3;
    const char *extensions = glXQueryExtensionsString(display, visual->screen);
    int swap = has_extension(extensions, "GLX_EXT_swap_control");
    printf("renderer=%s swap_control=%d\n", glGetString(GL_RENDERER), swap);
    fflush(stdout);
    if (swap) {
        unsigned interval = 0, maximum = 0;
        glXQueryDrawable(display, window, GLX_SWAP_INTERVAL_EXT, &interval);
        glXQueryDrawable(display, window, GLX_MAX_SWAP_INTERVAL_EXT, &maximum);
        printf("swap_interval=%u maximum=%u\n", interval, maximum);
    }
    int result = swap != atoi(argv[1]) ? 4 : 0;
    int32_t numerator = 0, denominator = 0;
    PFNGLXGETMSCRATEOMLPROC rate = (PFNGLXGETMSCRATEOMLPROC)
        glXGetProcAddressARB((const GLubyte *)"glXGetMscRateOML");
    if (!rate || !rate(display, window, &numerator, &denominator)
            || numerator <= 0 || denominator <= 0) {
        fprintf(stderr, "GLX MSC rate unavailable\n");
        result = 9;
    } else {
        printf("msc_rate=%d/%d\n", numerator, denominator);
    }
    XMapWindow(display, window);
    XFlush(display);
    for (;;) {
        struct pollfd socket = {.fd = ConnectionNumber(display), .events = POLLIN};
        /* EVENT_WAIT: X11 MapNotify; expiry fails before drawable readback.
         * The outer fixture deadline also bounds a stream of unrelated events. */
        if (!XPending(display) && poll(&socket, 1, 5000) != 1)
            return 8;
        XEvent event;
        XNextEvent(display, &event);
        if (event.type == MapNotify && event.xmap.window == window)
            break;
    }
    XWindowAttributes mapped;
    XGetWindowAttributes(display, window, &mapped);
    printf("mapped=%d geometry=%d,%d %dx%d depth=%d\n", mapped.map_state,
           mapped.x, mapped.y, mapped.width, mapped.height, mapped.depth);
    fflush(stdout);
    glViewport(0, 0, 160, 120);
    glClearColor(0.2f, 0.6f, 0.3f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    unsigned char rgba[4] = {0};
    glReadPixels(80, 60, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
    GLenum error = glGetError();
    printf("rendered_pixel=%u,%u,%u,%u error=%#x\n",
           rgba[0], rgba[1], rgba[2], rgba[3], error);
    if (error || rgba[0] != 51 || rgba[1] != 153 ||
        (rgba[2] != 76 && rgba[2] != 77) || rgba[3] != 255)
        result = 7;
    glXSwapBuffers(display, window);
    glFinish();
    XSync(display, False);
    int presented = await_pixel(display, window);
    if (!result)
        result = presented;
    glXMakeCurrent(display, None, NULL);
    glXDestroyContext(display, context);
    XDestroyWindow(display, window);
    XFreeColormap(display, options.colormap);
    XFree(visual);
    XCloseDisplay(display);
    printf("GLX_LOADER_%s\n", result ? "FAIL" : "PASS");
    return result;
}
