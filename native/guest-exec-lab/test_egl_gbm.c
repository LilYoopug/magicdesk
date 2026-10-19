#define _GNU_SOURCE
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <gbm.h>
#include <libdrm/drm_fourcc.h>
#include <linux/dma-buf.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REQUIRE(c) do { if (!(c)) { \
    fprintf(stderr,"FAIL %s errno=%d EGL=%x GL=%x\n",#c,errno,eglGetError(),glGetError()); \
    exit(1); } } while (0)

int main(int argc, char **argv) {
    setbuf(stdout,NULL);
    int node=open(argc>1 ? argv[1] : "/dev/dri/renderD128",O_RDONLY|O_CLOEXEC);
    REQUIRE(node>=0);
    struct gbm_device *device=gbm_create_device(node);
    REQUIRE(device);
    printf("GBM backend=%s\n",gbm_device_get_backend_name(device));
    EGLDisplay display=eglGetPlatformDisplay(EGL_PLATFORM_GBM_KHR,device,NULL);
    REQUIRE(display!=EGL_NO_DISPLAY);
    EGLint major,minor;
    REQUIRE(eglInitialize(display,&major,&minor));
    printf("EGL %d.%d %s\n",major,minor,eglQueryString(display,EGL_EXTENSIONS));
    REQUIRE(eglBindAPI(EGL_OPENGL_ES_API));
    EGLint context_attrs[]={EGL_CONTEXT_CLIENT_VERSION,2,EGL_NONE};
    EGLContext context=eglCreateContext(display,EGL_NO_CONFIG_KHR,EGL_NO_CONTEXT,context_attrs);
    REQUIRE(context!=EGL_NO_CONTEXT);
    REQUIRE(eglMakeCurrent(display,EGL_NO_SURFACE,EGL_NO_SURFACE,context));
    printf("renderer=%s\n",glGetString(GL_RENDERER));
    REQUIRE(strstr((const char *)glGetString(GL_RENDERER),"MESA_TURNIP"));
    const uint64_t linear=DRM_FORMAT_MOD_LINEAR;
    struct gbm_bo *bo=gbm_bo_create_with_modifiers2(device,64,64,GBM_FORMAT_ARGB8888,
        &linear,1,GBM_BO_USE_RENDERING|GBM_BO_USE_SCANOUT);
    REQUIRE(bo);
    REQUIRE(gbm_bo_get_modifier(bo)==linear && gbm_bo_get_plane_count(bo)==1);
    int fd=gbm_bo_get_fd(bo);
    REQUIRE(fd>=0);
    uint32_t stride=gbm_bo_get_stride(bo), offset=gbm_bo_get_offset(bo,0);
    printf("GBM allocation stride=%u offset=%u modifier=%llu\n",stride,offset,
        (unsigned long long)gbm_bo_get_modifier(bo));
    EGLint attrs[]={EGL_WIDTH,64,EGL_HEIGHT,64,EGL_LINUX_DRM_FOURCC_EXT,DRM_FORMAT_ARGB8888,
        EGL_DMA_BUF_PLANE0_FD_EXT,fd,EGL_DMA_BUF_PLANE0_OFFSET_EXT,(EGLint)offset,
        EGL_DMA_BUF_PLANE0_PITCH_EXT,(EGLint)stride,EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT,0,
        EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT,0,EGL_NONE};
    PFNEGLCREATEIMAGEKHRPROC create=(void *)eglGetProcAddress("eglCreateImageKHR");
    PFNEGLDESTROYIMAGEKHRPROC destroy=(void *)eglGetProcAddress("eglDestroyImageKHR");
    PFNGLEGLIMAGETARGETTEXTURE2DOESPROC target=(void *)eglGetProcAddress("glEGLImageTargetTexture2DOES");
    PFNEGLCREATESYNCKHRPROC create_sync=(void *)eglGetProcAddress("eglCreateSyncKHR");
    PFNEGLDESTROYSYNCKHRPROC destroy_sync=(void *)eglGetProcAddress("eglDestroySyncKHR");
    PFNEGLDUPNATIVEFENCEFDANDROIDPROC dup_fence=(void *)eglGetProcAddress("eglDupNativeFenceFDANDROID");
    REQUIRE(create && destroy && target && create_sync && destroy_sync && dup_fence);
    EGLImageKHR image=create(display,EGL_NO_CONTEXT,EGL_LINUX_DMA_BUF_EXT,NULL,attrs);
    REQUIRE(image!=EGL_NO_IMAGE_KHR);
    GLuint texture,fbo;
    glGenTextures(1,&texture); glBindTexture(GL_TEXTURE_2D,texture); target(GL_TEXTURE_2D,image);
    REQUIRE(glGetError()==GL_NO_ERROR);
    glGenFramebuffers(1,&fbo); glBindFramebuffer(GL_FRAMEBUFFER,fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,texture,0);
    REQUIRE(glCheckFramebufferStatus(GL_FRAMEBUFFER)==GL_FRAMEBUFFER_COMPLETE);
    size_t size=offset+stride*64;
    unsigned char *pixels=mmap(NULL,size,PROT_READ,MAP_SHARED,fd,0);
    REQUIRE(pixels!=MAP_FAILED);
    for (unsigned frame=0; frame<64; ++frame) {
        glClearColor(!(frame&1),frame&1,0,1); glClear(GL_COLOR_BUFFER_BIT);
        EGLSyncKHR completion=create_sync(display,EGL_SYNC_NATIVE_FENCE_ANDROID,NULL);
        REQUIRE(completion!=EGL_NO_SYNC_KHR); glFlush();
        int fence=dup_fence(display,completion); REQUIRE(fence>=0);
        struct dma_buf_import_sync_file publish={.flags=DMA_BUF_SYNC_WRITE,.fd=fence};
        REQUIRE(!ioctl(fd,DMA_BUF_IOCTL_IMPORT_SYNC_FILE,&publish)); close(fence);
        REQUIRE(destroy_sync(display,completion));
        struct dma_buf_export_sync_file read={.flags=DMA_BUF_SYNC_READ,.fd=-1};
        REQUIRE(!ioctl(fd,DMA_BUF_IOCTL_EXPORT_SYNC_FILE,&read));
        struct pollfd wait={.fd=read.fd,.events=POLLIN};
        /* EVENT_WAIT: completed GPU write fence, timeout fails the assertion. */
        REQUIRE(poll(&wait,1,5000)==1 && (wait.revents&POLLIN)); close(read.fd);
        struct dma_buf_sync sync={.flags=DMA_BUF_SYNC_START|DMA_BUF_SYNC_READ};
        REQUIRE(!ioctl(fd,DMA_BUF_IOCTL_SYNC,&sync));
        uint32_t pixel; memcpy(&pixel,pixels+offset,sizeof(pixel));
        sync.flags=DMA_BUF_SYNC_END|DMA_BUF_SYNC_READ;
        REQUIRE(!ioctl(fd,DMA_BUF_IOCTL_SYNC,&sync));
        REQUIRE(pixel==((frame&1) ? 0xff00ff00u : 0xffff0000u));
    }
    munmap(pixels,size); glDeleteFramebuffers(1,&fbo); glDeleteTextures(1,&texture);
    REQUIRE(destroy(display,image)); close(fd); gbm_bo_destroy(bo);
    REQUIRE(eglMakeCurrent(display,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT));
    REQUIRE(eglDestroyContext(display,context)); REQUIRE(eglTerminate(display));
    gbm_device_destroy(device); close(node);
    puts("PASS GBM/EGL hardware rendering: 64 exact frames with real DMA-BUF fences");
    return 0;
}
