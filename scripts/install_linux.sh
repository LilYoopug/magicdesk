#!/bin/sh
# Run from a saved file in MagicDesk's Shell console; stdin is used for questions.
set -eu

# Raise this floor only when recipes require newer APK behavior.
MIN_MAGICDESK_VERSION_CODE=224
MIN_MAGICDESK_VERSION_NAME=2.1.2
readonly MIN_MAGICDESK_VERSION_CODE MIN_MAGICDESK_VERSION_NAME

usage() {
    cat <<'HELP'
Usage: sh install_linux.sh [--distro ID] [OPTIONS]

Install an ARM64 Linux userspace in Shroot. Choose applications or a desktop
independently of the distribution. Installation output stays in this console.
New environments use software rendering unless Turnip is selected; SteamOS
defaults to automatic Turnip detection and a Wayland Plasma desktop.

  --distro ID   Debian 13 (default), Ubuntu 24.04, Alpine 3.23, Fedora 44,
                Arch Linux ARM, openSUSE Tumbleweed, openKylin 3.0, Deepin 25,
                Manjaro ARM, Void (glibc), Armtix (runit), or SteamOS ARM64
  --name NAME   Independent environment name (default: distribution name)
  --image REF   Alternative OCI reference for the SAME distribution/version
  --downloads DIR  Verified archive/wheel cache (default: $HOME/downloads)
  --gui MODE    none, apps (default), xfce, weston, plasma (Debian 13/SteamOS),
                gnome (Fedora devkit), keep
                apps: Mousepad, Thunar, Xfce Terminal; xfce: X11 desktop;
                weston: Wayland desktop; plasma: X11 and nested Wayland desktops;
                gnome: experimental nested shell
  --protocol P  x11, wayland, both (default); installer application entries
  --gpu keep    Retain the graphics profile (default)
  --gpu auto    Try Turnip when KGSL is accessible, otherwise use software
  --gpu software  Use the distribution's software renderer
  --gpu turnip  Build private Mesa/Zink/Turnip for a supported Adreno KGSL GPU
  --jobs N      Mesa/KWin compiler jobs, 1-8 (default: 2)
  --locale L    UTF-8 locale, e.g. ru_RU.UTF-8, or keep (default)
  --timezone Z  IANA zone, system (Android zone), or keep (default)
  --create-user USER  Create an optional guest account, with a locked password
                Select it later with login --user or the shortcut User field;
                this does not change the image account or grant Android root
  --fonts F    basic (default), cjk (also Chinese/Japanese/Korean), keep
  --package P   Additional repository package (repeatable)
  --cache C     keep (default), clean (package downloads only, not Mesa work)
  --dns POLICY  New image DNS: system (default), preserve, or IP[,IP...]
                VPN/Private DNS needs an explicit choice during configuration
  --yes         Accept the selected configuration without questions
  --resume      Continue in --name NAME; detect distribution, preserve GUI by default
  --list        Show available distribution/profile combinations
  --print-system-setup  Print the guest setup script without running it
  --print-graphics-setup  Print the guest graphics setup script without running it
  --print-mesa-patch  Print the embedded patch without running the installer
  --print-kwin-patch [6.3.6|6.2.5]  Print the matching embedded KWin patch
  --print-recovery-reader  Print the embedded SteamOS image converter

Turnip builds inside Linux, needs several GB of free space and can take a while.
The source version and SHA-256 are pinned; no Android or distribution drivers are replaced.
Failed builds retain the previous profile and can be resumed. New launches use
the selected profile; already running programs are not restarted.
Void: set FORCE_IPV4=1 before this command if the network has no working IPv6.

No Termux or Android root is required. Use trusted images: Shroot is not a
security sandbox. The current shell/root identity is never changed.
GUI profiles include PipeWire audio, SDL gamepad discovery and Wayland decorations.
Graphical Shroot launches receive Android gamepads automatically; no host device binds.
GNOME devkit needs a working Linux system bus; this installer does not boot system services.
SteamOS retains its supplied applications, fonts and system drivers. The default
--gui plasma --gpu auto adds a nested desktop and a private graphics profile.
It needs about 35 GB free during conversion, not a booted recovery/VR session.
Its packages are updated from the image's configured repositories before first use.
HELP
    printf '\nRequires MagicDesk %s or newer (versionCode %s).\n' \
        "$MIN_MAGICDESK_VERSION_NAME" "$MIN_MAGICDESK_VERSION_CODE"
}

configurations() {
    printf '%s\n' 'Distribution  Version     Source                                   GUI' \
        'debian        13          Debian official slim rootfs               none/apps/xfce/weston/plasma' \
        'ubuntu        24.04       Ubuntu Base official rootfs               none/apps/xfce/weston' \
        'alpine        3.23        Alpine official minirootfs                none/apps/xfce/weston' \
        'fedora        44          registry.fedoraproject.org/fedora:44       none/apps/xfce/weston/gnome' \
        'arch          rolling     Arch Linux ARM official rootfs            none/apps/xfce/weston' \
        'opensuse      Tumbleweed  openSUSE official LXC rootfs               none/apps/xfce/weston' \
        'openkylin     3.0         openkylin/openkylin:latest                 none/apps/xfce/weston' \
        'deepin        25          linuxdeepin/deepin:crimson-arm64            none/apps/xfce/weston' \
        'manjaro       rolling     Manjaro ARM official rootfs               none/apps/xfce/weston' \
        'void          rolling     Void official glibc rootfs                none/apps/xfce/weston' \
        'armtix        rolling     Armtix official runit rootfs              none/apps/xfce/weston' \
        'steamos       0.3.0       Valve Steam Frame recovery                plasma/keep (supplied applications)'
    printf '%s\n' 'GUI profiles include Android audio and gamepad client libraries.' \
        'GNOME devkit requires a Linux system bus.'
}

# Package-manager differences stay here; setup and the Mesa recipe share them.
distribution_support() {
    cat <<'DISTRO'
set -eu
umask 022
. /etc/os-release
case "$ID" in
    debian|ubuntu|openkylin|deepin) family=apt ;;
    alpine) family=apk ;;
    fedora) family=dnf ;;
    arch|archarm|manjaro-arm|manjaro|artix) family=pacman ;;
    opensuse-tumbleweed) family=zypper ;;
    void) family=xbps ;;
    steamos) family=recovery ;;
    *) echo "Unsupported distribution: $ID" >&2; exit 1 ;;
esac
packages() {
    case "$family" in
        apt) apt-get install -y --no-install-recommends "$@" </dev/null ;;
        apk) apk add "$@" </dev/null ;;
        dnf) dnf -y --setopt=install_weak_deps=False install "$@" </dev/null ;;
        zypper) zypper --non-interactive install --no-recommends "$@" </dev/null ;;
        xbps) xbps-install -y "$@" </dev/null ;;
        pacman|recovery) pacman -S --needed --noconfirm "$@" </dev/null ;;
        *) echo 'Package setup is unavailable for this image.' >&2; exit 1 ;;
    esac
}
refresh_packages() {
    case "$family" in
        apt) apt-get update </dev/null ;;
        apk) apk update </dev/null ;;
        zypper) zypper --non-interactive refresh </dev/null ;;
        xbps)
            # XBPS must upgrade itself before the rest of a rolling rootfs.
            xbps-install -Suy xbps </dev/null
            xbps-install -uy </dev/null ;;
        pacman)
            case "$ID" in
                manjaro|manjaro-arm) keyrings='archlinuxarm manjaro manjaro-arm' ;;
                artix) keyrings=artix ;;
                arch|archarm) keyrings=archlinuxarm ;;
                *) keyrings= ;;
            esac
            if [ -n "$keyrings" ]; then
                pacman-key --init </dev/null
                pacman-key --populate $keyrings </dev/null
            fi
            # Rolling repositories require a complete userspace upgrade.
            pacman -Syu --noconfirm </dev/null ;;
        recovery)
            # Retain the image repository branch, keyring and signature policy.
            printf 'Updating SteamOS packages from the image repositories...\n'
            printf 'Kernel/service hooks may warn about the non-booted environment. Android is not updated.\n'
            pacman -Syu --noconfirm </dev/null ;;
    esac
}
package_cleanup() {
    # pacman-key's service is scoped to the package keyring, not a user's GPG home.
    if { [ "$family" = pacman ] || [ "$family" = recovery ]; } && command -v gpgconf >/dev/null 2>&1; then
        gpgconf --homedir /etc/pacman.d/gnupg --kill all || {
            echo 'Could not stop the package-keyring GPG services.' >&2
        }
    fi
}
DISTRO
}

mesa_patch() {
    cat <<'PATCH'
Mesa 26.2.3: explicitly selected Zink uses Kopper without a DRM render node.
The EGLDevice convention matches platform_x11_finalize(force_zink).
KGSL calibrated timestamps use the kernel timestamp ioctl when available;
unsupported kernels do not advertise that extension. Queue queries are unchanged.
GLX loader capabilities follow the effective backend when Kopper is disabled.
Zink retains GPU rendering with sw_winsys readback presentation when the client
disables Kopper or the X server lacks DRI3. Direct Vulkan presentation is unchanged.

--- a/src/glx/drisw_glx.c
+++ b/src/glx/drisw_glx.c
@@ -634,6 +634,12 @@

    /* this is only relevant if zink bits are set */
    glx_driver &= (GLX_DRIVER_ZINK_INFER | GLX_DRIVER_ZINK_YES);
+   /* Without DRI3, use the frontend's readback presentation, not Vulkan WSI. */
+   if (glx_driver && !kopper_disable) {
+      int opcode, event, error;
+      kopper_disable = !XQueryExtension(priv->dpy, "DRI3", &opcode, &event, &error);
+   }
+
    const char *driver = glx_driver && !kopper_disable ? "zink" : "swrast";

    psc = calloc(1, sizeof *psc);
@@ -642,7 +648,7 @@
    psc->kopper = !strcmp(driver, "zink");
    psc->base.driverName = strdup(driver);

-   if (glx_driver)
+   if (psc->kopper)
       loader_extensions_local = kopper_extensions_noshm;
 #ifdef HAVE_SYS_SHM_H
    else if (!x11_xcb_display_supports_xshm(XGetXCBConnection(priv->dpy), &xshm_opcode))
@@ -650,7 +656,7 @@
 #endif
    else
       loader_extensions_local = loader_extensions_shm;
-   priv->driver = glx_driver ? GLX_DRIVER_ZINK_YES : GLX_DRIVER_SW;
+   priv->driver = psc->kopper ? GLX_DRIVER_ZINK_YES : GLX_DRIVER_SW;

    if (!dri_screen_init(&psc->base, priv, screen, -1, loader_extensions_local, driver_name_is_inferred)) {
       if (!glx_driver || !driver_name_is_inferred)
@@ -664,7 +670,7 @@
    psp->createDrawable = driswCreateDrawable;
    psp->swapBuffers = driswSwapBuffers;

-   if (!glx_driver)
+   if (!psc->kopper)
       psp->copySubBuffer = drisw_copy_sub_buffer;

    if (psc->kopper) {
--- a/src/egl/drivers/dri2/platform_wayland.c
+++ b/src/egl/drivers/dri2/platform_wayland.c
@@ -3262,7 +3262,7 @@ dri2_initialize_wayland_swrast(_EGLDisplay *disp)
    if (!dri2_create_screen(disp))
       goto cleanup;

-   if (!dri2_setup_device(disp, disp->Options.ForceSoftware)) {
+   if (!dri2_setup_device(disp, disp->Options.ForceSoftware || disp->Options.Zink)) {
       _eglError(EGL_NOT_INITIALIZED, "DRI2: failed to setup EGLDevice");
       goto cleanup;
    }
@@ -3297,7 +3297,7 @@ dri2_initialize_wayland_swrast(_EGLDisplay *disp)
 EGLBoolean
 dri2_initialize_wayland(_EGLDisplay *disp)
 {
-   if (disp->Options.ForceSoftware)
+   if (disp->Options.ForceSoftware || disp->Options.Zink)
       return dri2_initialize_wayland_swrast(disp);
    else
       return dri2_initialize_wayland_drm(disp);
--- a/src/freedreno/vulkan/tu_knl.h
+++ b/src/freedreno/vulkan/tu_knl.h
@@ -128,6 +128,7 @@
    VkResult (*device_init)(struct tu_device *dev);
    void (*device_finish)(struct tu_device *dev);
    int (*device_get_gpu_timestamp)(struct tu_device *dev, uint64_t *ts);
+   bool (*can_query_gpu_timestamp)(const struct tu_physical_device *dev);
    int (*device_get_suspend_count)(struct tu_device *dev, uint64_t *suspend_count);
    VkResult (*device_check_status)(struct tu_device *dev);
    int (*submitqueue_new)(struct tu_device *dev, struct tu_queue *queue);
--- a/src/freedreno/vulkan/tu_device.cc
+++ b/src/freedreno/vulkan/tu_device.cc
@@ -39,6 +39,7 @@
 #include "tu_descriptor_set.h"
 #include "tu_dynamic_rendering.h"
 #include "tu_image.h"
+#include "tu_knl.h"
 #include "tu_pass.h"
 #include "tu_query_pool.h"
 #include "tu_queue.h"
@@ -192,6 +193,9 @@
                       struct vk_device_extension_table *ext)
 {
    bool has_gralloc = vk_android_get_ugralloc() != NULL;
+   bool has_calibrated_timestamps = device->info->props.has_persistent_counter &&
+      (!device->instance->knl->can_query_gpu_timestamp ||
+       device->instance->knl->can_query_gpu_timestamp(device));
    /* device->has_raytracing contains the value of the SW fuse. If the
     * device doesn't have a fuse (i.e. a740), we have to ignore it because
     * kgsl returns false. If it does have a fuse, enable raytracing if the
@@ -207,7 +211,7 @@
       .KHR_acceleration_structure = has_raytracing,
       .KHR_bind_memory2 = true,
       .KHR_buffer_device_address = true,
-      .KHR_calibrated_timestamps = device->info->props.has_persistent_counter,
+      .KHR_calibrated_timestamps = has_calibrated_timestamps,
       .KHR_compute_shader_derivatives = true,
       .KHR_copy_commands2 = true,
       // TODO workaround for https://github.com/KhronosGroup/VK-GL-CTS/issues/525
@@ -304,7 +308,7 @@
       .EXT_attachment_feedback_loop_dynamic_state = true,
       .EXT_attachment_feedback_loop_layout = true,
       .EXT_border_color_swizzle = true,
-      .EXT_calibrated_timestamps = device->info->props.has_persistent_counter,
+      .EXT_calibrated_timestamps = has_calibrated_timestamps,
       .EXT_color_write_enable = true,
       .EXT_conditional_rendering = true,
       .EXT_conservative_rasterization = device->info->chip >= 7,
--- a/src/freedreno/vulkan/tu_knl_kgsl.cc
+++ b/src/freedreno/vulkan/tu_knl_kgsl.cc
@@ -1703,10 +1703,28 @@
 }

 static int
+kgsl_read_gpu_timestamp(int fd, uint64_t *ts)
+{
+   uint32_t domain = KGSL_CALIBRATED_TIME_DOMAIN_DEVICE;
+   struct kgsl_read_calibrated_timestamps request = {
+      .sources = (uintptr_t)&domain,
+      .ts = (uintptr_t)ts,
+      .count = 1,
+   };
+   return safe_ioctl(fd, IOCTL_KGSL_READ_CALIBRATED_TIMESTAMPS, &request);
+}
+
+static bool
+kgsl_can_query_gpu_timestamp(const struct tu_physical_device *dev)
+{
+   uint64_t timestamp;
+   return kgsl_read_gpu_timestamp(dev->local_fd, &timestamp) == 0;
+}
+
+static int
 kgsl_device_get_gpu_timestamp(struct tu_device *dev, uint64_t *ts)
 {
-   UNREACHABLE("");
-   return 0;
+   return kgsl_read_gpu_timestamp(dev->fd, ts);
 }

 static int
@@ -1754,6 +1772,7 @@
       .device_init = kgsl_device_init,
       .device_finish = kgsl_device_finish,
       .device_get_gpu_timestamp = kgsl_device_get_gpu_timestamp,
+      .can_query_gpu_timestamp = kgsl_can_query_gpu_timestamp,
       .device_get_suspend_count = kgsl_device_get_suspend_count,
       .device_check_status = kgsl_device_check_status,
       .submitqueue_new = kgsl_submitqueue_new,
--- a/src/gallium/drivers/zink/zink_screen.c
+++ b/src/gallium/drivers/zink/zink_screen.c
@@ -34,6 +34,9 @@
 #include "zink_public.h"
 #include "zink_query.h"
 #include "zink_resource.h"
+#include "frontend/sw_winsys.h"
+#include "util/u_inlines.h"
+#include "util/u_surface.h"
 #include "zink_state.h"
 #include "nir_to_spirv/nir_to_spirv.h" // for SPIRV_VERSION

@@ -1892,6 +1895,45 @@
 }

 static void
+zink_present_readback(struct zink_screen *screen, struct pipe_context *pipe,
+                      struct pipe_resource *pres, unsigned level, unsigned layer,
+                      void *drawable, unsigned nboxes, struct pipe_box *boxes)
+{
+   struct sw_winsys *ws = screen->winsys;
+   struct zink_resource *res = zink_resource(pres);
+   if (!ws || !(pres->bind & PIPE_BIND_DISPLAY_TARGET))
+      return;
+
+   if (res->sw_dt && res->sw_level != level) {
+      ws->displaytarget_destroy(ws, res->sw_dt);
+      res->sw_dt = NULL;
+   }
+   unsigned width = u_minify(pres->width0, level);
+   unsigned height = u_minify(pres->height0, level);
+   if (!res->sw_dt) {
+      res->sw_dt = ws->displaytarget_create(ws, pres->bind, pres->format,
+                                           width, height, 64, NULL, &res->sw_stride);
+      res->sw_level = level;
+      if (!res->sw_dt)
+         return;
+   }
+   struct pipe_transfer *transfer = NULL;
+   void *pixels = pipe_texture_map(pipe, pres, level, layer, PIPE_MAP_READ,
+                                  0, 0, width, height, &transfer);
+   if (!pixels)
+      return;
+   void *output = ws->displaytarget_map(ws, res->sw_dt, PIPE_MAP_WRITE);
+   if (output) {
+      util_copy_rect(output, pres->format, res->sw_stride, 0, 0, width, height,
+                     pixels, transfer->stride, 0, 0);
+      ws->displaytarget_unmap(ws, res->sw_dt);
+   }
+   pipe_texture_unmap(pipe, transfer);
+   if (output)
+      ws->displaytarget_display(ws, res->sw_dt, drawable, nboxes, boxes);
+}
+
+static void
 zink_flush_frontbuffer(struct pipe_screen *pscreen,
                        struct pipe_context *pctx,
                        struct pipe_resource *pres,
@@ -1904,9 +1946,12 @@
    struct zink_resource *res = zink_resource(pres);
    struct zink_context *ctx = zink_context(pctx);

-   /* if the surface is no longer a swapchain, this is a no-op */
-   if (!zink_is_swapchain(res))
+   /* A non-Kopper frontend owns presentation; Vulkan still renders the image. */
+   if (!zink_is_swapchain(res)) {
+      zink_present_readback(screen, pctx, pres, level, layer,
+                            winsys_drawable_handle, nboxes, sub_box);
       return;
+   }

    ctx = zink_tc_context_unwrap(pctx);

@@ -3862,9 +3907,10 @@
    struct zink_screen *ret = zink_internal_create_screen(config, -1, -1, 0);
    if (ret) {
       ret->drm_fd = -1;
-   }
-
-   return &ret->base;
+      ret->winsys = winsys;
+   }
+
+   return ret ? &ret->base : NULL;
 }

 static inline int
--- a/src/gallium/drivers/zink/zink_types.h
+++ b/src/gallium/drivers/zink/zink_types.h
@@ -1268,6 +1268,9 @@
 struct zink_resource {
    struct threaded_resource base;

+   struct sw_displaytarget *sw_dt;
+   unsigned sw_stride, sw_level;
+
    enum pipe_format internal_format:16;

    struct zink_resource_object *obj;
@@ -1367,6 +1370,8 @@

 struct zink_screen {
    struct pipe_screen base;
+
+   struct sw_winsys *winsys;

    const char *vendor_name;
    const char *device_name;
--- a/src/gallium/drivers/zink/zink_resource.c
+++ b/src/gallium/drivers/zink/zink_resource.c
@@ -47,6 +47,7 @@
 #include "util/u_upload_mgr.h"
 #include "util/os_file.h"
 #include "frontend/winsys_handle.h"
+#include "frontend/sw_winsys.h"

 #if !defined(__APPLE__)
 #define ZINK_USE_DMABUF
@@ -254,6 +255,9 @@
    struct zink_resource *res = zink_resource(pres);
    /* prevent double-free when unrefing internal surfaces */
    res->base.b.reference.count = 999;
+
+   if (res->sw_dt)
+      screen->winsys->displaytarget_destroy(screen->winsys, res->sw_dt);

 #ifdef HAVE_LIBDRM
    if (res->ro_scanout)
PATCH
}

kwin_patch() {
    case "${1:-6.3.6}" in 6.2.5|6.3.6) ;; *) return 1 ;; esac
    cat <<'PATCH'
KWin: nested DMA-BUF v3/EGL rendering without a DRM device.

--- a/src/backends/wayland/CMakeLists.txt
+++ b/src/backends/wayland/CMakeLists.txt
@@ -1,4 +1,5 @@
 target_sources(kwin PRIVATE
+    dmaheapgraphicsbufferallocator.cpp
     wayland_backend.cpp
     wayland_display.cpp
     wayland_egl_backend.cpp
--- a/src/backends/wayland/dmaheapgraphicsbufferallocator.cpp
+++ b/src/backends/wayland/dmaheapgraphicsbufferallocator.cpp
@@ -0,0 +1,78 @@
+/* SPDX-License-Identifier: GPL-2.0-or-later */
+#include "dmaheapgraphicsbufferallocator.h"
+#include "core/graphicsbuffer.h"
+#include "utils/drm_format_helper.h"
+
+#include <drm_fourcc.h>
+#include <fcntl.h>
+#include <limits>
+#include <linux/dma-heap.h>
+#include <sys/ioctl.h>
+
+namespace KWin::Wayland
+{
+
+class DmaHeapGraphicsBuffer : public GraphicsBuffer
+{
+public:
+    explicit DmaHeapGraphicsBuffer(DmaBufAttributes &&attributes)
+        : m_attributes(std::move(attributes))
+    {
+    }
+
+    QSize size() const override { return {m_attributes.width, m_attributes.height}; }
+    bool hasAlphaChannel() const override { return alphaChannelFromDrmFormat(m_attributes.format); }
+    const DmaBufAttributes *dmabufAttributes() const override { return &m_attributes; }
+
+private:
+    DmaBufAttributes m_attributes;
+};
+
+DmaHeapGraphicsBufferAllocator::DmaHeapGraphicsBufferAllocator()
+    : m_heap(open("/dev/dma_heap/system", O_RDONLY | O_CLOEXEC))
+{
+}
+
+bool DmaHeapGraphicsBufferAllocator::isValid() const
+{
+    return m_heap.isValid();
+}
+
+GraphicsBuffer *DmaHeapGraphicsBufferAllocator::allocate(const GraphicsBufferOptions &options)
+{
+    if (!isValid() || options.software || options.size.isEmpty()
+        || !options.modifiers.contains(DRM_FORMAT_MOD_LINEAR)) {
+        return nullptr;
+    }
+    switch (options.format) {
+    case DRM_FORMAT_XRGB8888:
+    case DRM_FORMAT_ARGB8888:
+    case DRM_FORMAT_XBGR8888:
+    case DRM_FORMAT_ABGR8888:
+        break;
+    default:
+        return nullptr;
+    }
+    const uint64_t stride = (uint64_t(options.size.width()) * 4 + 255) & ~uint64_t(255);
+    const uint64_t length = stride * options.size.height();
+    if (stride > std::numeric_limits<uint32_t>::max() || length > std::numeric_limits<int32_t>::max()) {
+        return nullptr;
+    }
+    dma_heap_allocation_data allocation{};
+    allocation.len = length;
+    allocation.fd_flags = O_RDWR | O_CLOEXEC;
+    if (ioctl(m_heap.get(), DMA_HEAP_IOCTL_ALLOC, &allocation) < 0) {
+        return nullptr;
+    }
+    DmaBufAttributes attributes;
+    attributes.width = options.size.width();
+    attributes.height = options.size.height();
+    attributes.format = options.format;
+    attributes.modifier = DRM_FORMAT_MOD_LINEAR;
+    attributes.planeCount = 1;
+    attributes.fd[0] = FileDescriptor(allocation.fd);
+    attributes.pitch[0] = stride;
+    return new DmaHeapGraphicsBuffer(std::move(attributes));
+}
+
+}
--- a/src/backends/wayland/dmaheapgraphicsbufferallocator.h
+++ b/src/backends/wayland/dmaheapgraphicsbufferallocator.h
@@ -0,0 +1,21 @@
+/* SPDX-License-Identifier: GPL-2.0-or-later */
+#pragma once
+
+#include "core/graphicsbufferallocator.h"
+#include "utils/filedescriptor.h"
+
+namespace KWin::Wayland
+{
+
+class DmaHeapGraphicsBufferAllocator : public GraphicsBufferAllocator
+{
+public:
+    DmaHeapGraphicsBufferAllocator();
+    bool isValid() const;
+    GraphicsBuffer *allocate(const GraphicsBufferOptions &options) override;
+
+private:
+    FileDescriptor m_heap;
+};
+
+}
--- a/src/backends/wayland/wayland_backend.cpp
+++ b/src/backends/wayland/wayland_backend.cpp
@@ -431,7 +431,7 @@
         return false;
     }

-    if (WaylandLinuxDmabufV1 *dmabuf = m_display->linuxDmabuf()) {
+    if (WaylandLinuxDmabufV1 *dmabuf = m_display->linuxDmabuf(); dmabuf && !dmabuf->mainDevice().isEmpty()) {
         m_drmDevice = DrmDevice::open(dmabuf->mainDevice());
         if (!m_drmDevice) {
             qCWarning(KWIN_WAYLAND_BACKEND) << "Failed to open drm render node" << dmabuf->mainDevice();
@@ -550,7 +550,7 @@
 QList<CompositingType> WaylandBackend::supportedCompositors() const
 {
     QList<CompositingType> ret;
-    if (m_display->linuxDmabuf() && m_drmDevice) {
+    if (m_display->linuxDmabuf() && !m_display->linuxDmabuf()->formats().isEmpty()) {
         ret.append(OpenGLCompositing);
     }
     ret.append(QPainterCompositing);
--- a/src/backends/wayland/wayland_display.cpp
+++ b/src/backends/wayland/wayland_display.cpp
@@ -281,7 +281,9 @@
     };
     zwp_linux_dmabuf_v1_add_listener(m_dmabuf, &dmabufListener, this);

-    m_defaultFeedback = std::make_unique<WaylandLinuxDmabufFeedbackV1>(zwp_linux_dmabuf_v1_get_default_feedback(m_dmabuf));
+    if (version >= 4) {
+        m_defaultFeedback = std::make_unique<WaylandLinuxDmabufFeedbackV1>(zwp_linux_dmabuf_v1_get_default_feedback(m_dmabuf));
+    }
 }

 WaylandLinuxDmabufV1::~WaylandLinuxDmabufV1()
@@ -296,12 +298,12 @@

 QByteArray WaylandLinuxDmabufV1::mainDevice() const
 {
-    return m_defaultFeedback->mainDevice;
+    return m_defaultFeedback ? m_defaultFeedback->mainDevice : QByteArray();
 }

 QHash<uint32_t, QList<uint64_t>> WaylandLinuxDmabufV1::formats() const
 {
-    return m_defaultFeedback->formats;
+    return m_defaultFeedback ? m_defaultFeedback->formats : m_formats;
 }

 void WaylandLinuxDmabufV1::format(void *data, struct zwp_linux_dmabuf_v1 *zwp_linux_dmabuf_v1, uint32_t format)
@@ -311,7 +313,12 @@

 void WaylandLinuxDmabufV1::modifier(void *data, struct zwp_linux_dmabuf_v1 *zwp_linux_dmabuf_v1, uint32_t format, uint32_t modifier_hi, uint32_t modifier_lo)
 {
-    // Not sent in v4 and onward.
+    auto *self = static_cast<WaylandLinuxDmabufV1 *>(data);
+    const uint64_t modifier = (uint64_t(modifier_hi) << 32) | modifier_lo;
+    auto &modifiers = self->m_formats[format];
+    if (!modifiers.contains(modifier)) {
+        modifiers.append(modifier);
+    }
 }

 WaylandDisplay::WaylandDisplay()
@@ -460,8 +467,8 @@
         display->m_xdgDecorationManager = std::make_unique<KWayland::Client::XdgDecorationManager>();
         display->m_xdgDecorationManager->setup(static_cast<zxdg_decoration_manager_v1 *>(wl_registry_bind(registry, name, &zxdg_decoration_manager_v1_interface, std::min(version, 1u))));
     } else if (strcmp(interface, zwp_linux_dmabuf_v1_interface.name) == 0) {
-        if (version < 4) {
-            qWarning("zwp_linux_dmabuf_v1 v4 or newer is needed");
+        if (version < 3) {
+            qWarning("zwp_linux_dmabuf_v1 v3 or newer is needed");
             return;
         }
         display->m_linuxDmabuf = std::make_unique<WaylandLinuxDmabufV1>(registry, name, std::min(version, 4u));
--- a/src/backends/wayland/wayland_display.h
+++ b/src/backends/wayland/wayland_display.h
@@ -55,6 +55,7 @@

     zwp_linux_dmabuf_v1 *m_dmabuf;
     std::unique_ptr<WaylandLinuxDmabufFeedbackV1> m_defaultFeedback;
+    QHash<uint32_t, QList<uint64_t>> m_formats;
 };

 class WaylandDisplay : public QObject
--- a/src/backends/wayland/wayland_egl_backend.h
+++ b/src/backends/wayland/wayland_egl_backend.h
@@ -98,6 +98,9 @@

     WaylandBackend *backend() const;
     DrmDevice *drmDevice() const override;
+    GraphicsBufferAllocator *graphicsBufferAllocator() const override;
+    bool acquireBuffer(GraphicsBuffer *buffer);
+    bool releaseBuffer(GraphicsBuffer *buffer, const FileDescriptor &fence);

     std::unique_ptr<SurfaceTexture> createSurfaceTextureWayland(SurfacePixmap *pixmap) override;

@@ -121,6 +124,7 @@
     };

     WaylandBackend *m_backend;
+    std::unique_ptr<GraphicsBufferAllocator> m_allocator;
     std::map<Output *, Layers> m_outputs;
 };

--- a/src/opengl/egldisplay.cpp
+++ b/src/opengl/egldisplay.cpp
@@ -7,6 +7,9 @@
     SPDX-License-Identifier: GPL-2.0-or-later
 */
 #include "egldisplay.h"
+#include "eglnativefence.h"
+#include <linux/dma-buf.h>
+#include <sys/ioctl.h>
 #include "core/drmdevice.h"
 #include "core/graphicsbuffer.h"
 #include "opengl/eglutils_p.h"
@@ -24,6 +27,54 @@
 namespace KWin
 {

+void EglDisplay::setDmaBufSyncRequired(bool required)
+{
+    m_dmaBufSyncRequired = required;
+}
+
+bool EglDisplay::dmaBufSyncRequired() const
+{
+    return m_dmaBufSyncRequired;
+}
+
+bool EglDisplay::acquireDmaBuf(GraphicsBuffer *buffer, bool write)
+{
+    const auto attributes = buffer->dmabufAttributes();
+    if (!m_dmaBufSyncRequired || !attributes) {
+        return true;
+    }
+    for (int plane = 0; plane < attributes->planeCount; ++plane) {
+        dma_buf_export_sync_file sync{.flags = uint32_t(write ? DMA_BUF_SYNC_RW : DMA_BUF_SYNC_READ), .fd = -1};
+        if (ioctl(attributes->fd[plane].get(), DMA_BUF_IOCTL_EXPORT_SYNC_FILE, &sync) < 0) {
+            return false;
+        }
+        // This is a GPU dependency; it does not block the compositor thread.
+        auto fence = EGLNativeFence::importFence(this, FileDescriptor(sync.fd));
+        if (!fence.waitSync()) {
+            return false;
+        }
+    }
+    return true;
+}
+
+bool EglDisplay::releaseDmaBuf(GraphicsBuffer *buffer, const FileDescriptor &fence, bool write)
+{
+    const auto attributes = buffer->dmabufAttributes();
+    if (!m_dmaBufSyncRequired || !attributes) {
+        return true;
+    }
+    if (!fence.isValid()) {
+        return false;
+    }
+    for (int plane = 0; plane < attributes->planeCount; ++plane) {
+        dma_buf_import_sync_file sync{.flags = uint32_t(write ? DMA_BUF_SYNC_WRITE : DMA_BUF_SYNC_READ), .fd = fence.get()};
+        if (ioctl(attributes->fd[plane].get(), DMA_BUF_IOCTL_IMPORT_SYNC_FILE, &sync) < 0) {
+            return false;
+        }
+    }
+    return true;
+}
+
 bool EglDisplay::shouldUseOpenGLES()
 {
     if (qstrcmp(qgetenv("KWIN_COMPOSE"), "O2ES") == 0) {
--- a/src/opengl/egldisplay.h
+++ b/src/opengl/egldisplay.h
@@ -22,6 +22,8 @@

 struct DmaBufAttributes;
 class GLTexture;
+class GraphicsBuffer;
+class FileDescriptor;

 class KWIN_EXPORT EglDisplay
 {
@@ -45,6 +47,10 @@

     bool supportsBufferAge() const;
     bool supportsNativeFence() const;
+    void setDmaBufSyncRequired(bool required);
+    bool dmaBufSyncRequired() const;
+    bool acquireDmaBuf(GraphicsBuffer *buffer, bool write);
+    bool releaseDmaBuf(GraphicsBuffer *buffer, const FileDescriptor &fence, bool write);

     QHash<uint32_t, QList<uint64_t>> nonExternalOnlySupportedDrmFormats() const;
     QHash<uint32_t, DrmFormatInfo> allSupportedDrmFormats() const;
@@ -72,6 +78,7 @@
     const bool m_supportsBufferAge;
     const bool m_supportsNativeFence;
     QHash<uint32_t, DrmFormatInfo> m_importFormats;
+    bool m_dmaBufSyncRequired = false;

     struct
     {
--- a/src/platformsupport/scenes/opengl/abstract_egl_backend.cpp
+++ b/src/platformsupport/scenes/opengl/abstract_egl_backend.cpp
@@ -94,6 +94,12 @@
     setSupportsBufferAge(m_display->supportsBufferAge());
 }

+GraphicsBufferAllocator *AbstractEglBackend::graphicsBufferAllocator() const
+{
+    const auto device = drmDevice();
+    return device ? device->allocator() : nullptr;
+}
+
 void AbstractEglBackend::initWayland()
 {
     if (!WaylandServer::self()) {
@@ -192,6 +198,19 @@
         LinuxDmaBufV1ClientBufferIntegration *dmabuf = waylandServer()->linuxDmabuf();
         dmabuf->setRenderBackend(this);
         dmabuf->setSupportedFormatsWithModifiers(m_tranches);
+    } else if (m_display->dmaBufSyncRequired()) {
+        QHash<uint32_t, QList<uint64_t>> formats;
+        const auto supported = m_display->allSupportedDrmFormats();
+        for (auto it = supported.constBegin(); it != supported.constEnd(); ++it) {
+            if (!it->nonExternalOnlyModifiers.isEmpty()) {
+                formats.insert(it.key(), it->nonExternalOnlyModifiers);
+            }
+        }
+        if (!formats.isEmpty()) {
+            auto *dmabuf = waylandServer()->linuxDmabuf(false);
+            dmabuf->setRenderBackend(this);
+            dmabuf->setSupportedFormatsWithModifiers(formats);
+        }
     }
     waylandServer()->setRenderBackend(this);
 }
--- a/src/platformsupport/scenes/opengl/abstract_egl_backend.h
+++ b/src/platformsupport/scenes/opengl/abstract_egl_backend.h
@@ -23,6 +23,7 @@

 struct DmaBufAttributes;
 class Output;
+class GraphicsBufferAllocator;

 class KWIN_EXPORT AbstractEglBackend : public OpenGLBackend
 {
@@ -36,6 +37,7 @@
     EglDisplay *eglDisplayObject() const override;
     EglContext *openglContext() const override;
     std::shared_ptr<EglContext> openglContextRef() const;
+    virtual GraphicsBufferAllocator *graphicsBufferAllocator() const;

     bool testImportBuffer(GraphicsBuffer *buffer) override;
     QHash<uint32_t, QList<uint64_t>> supportedFormats() const override;
--- a/src/plugins/qpa/eglplatformcontext.cpp
+++ b/src/plugins/qpa/eglplatformcontext.cpp
@@ -15,6 +15,7 @@
 #include "offscreensurface.h"
 #include "opengl/eglcontext.h"
 #include "opengl/egldisplay.h"
+#include "opengl/eglnativefence.h"
 #include "opengl/glutils.h"
 #include "swapchain.h"
 #include "window.h"
@@ -84,7 +85,7 @@
         }

         GraphicsBuffer *buffer = swapchain->acquire();
-        if (!buffer) {
+        if (!buffer || !m_eglDisplay->acquireDmaBuf(buffer, true)) {
             return false;
         }

@@ -158,6 +159,13 @@

         glFlush(); // We need to flush pending rendering commands manually

+        if (m_eglDisplay->dmaBufSyncRequired()) {
+            EGLNativeFence fence{m_eglDisplay};
+            if (!m_eglDisplay->releaseDmaBuf(m_current->buffer, fence.fileDescriptor(), true)) {
+                qFatal("Could not publish internal window DMA-BUF completion");
+            }
+        }
+
         internalWindow->present(InternalWindowFrame{
             .buffer = m_current->buffer,
             .bufferDamage = QRect(QPoint(0, 0), m_current->buffer->size()),
--- a/src/plugins/qpa/window.cpp
+++ b/src/plugins/qpa/window.cpp
@@ -12,10 +12,10 @@
 #include "utils/drm_format_helper.h"

 #include "compositor.h"
-#include "core/drmdevice.h"
 #include "core/renderbackend.h"
 #include "core/shmgraphicsbufferallocator.h"
 #include "internalwindow.h"
+#include "platformsupport/scenes/opengl/abstract_egl_backend.h"
 #include "swapchain.h"
 #include "window.h"

@@ -57,7 +57,11 @@
             static ShmGraphicsBufferAllocator shmAllocator;
             allocator = &shmAllocator;
         } else {
-            allocator = Compositor::self()->backend()->drmDevice()->allocator();
+            const auto backend = qobject_cast<AbstractEglBackend *>(Compositor::self()->backend());
+            allocator = backend ? backend->graphicsBufferAllocator() : nullptr;
+        }
+        if (!allocator) {
+            return nullptr;
         }

         for (auto it = formats.begin(); it != formats.end(); it++) {
--- a/src/plugins/screencast/screencaststream.cpp
+++ b/src/plugins/screencast/screencaststream.cpp
@@ -920,7 +920,7 @@
 std::optional<ScreenCastDmaBufTextureParams> ScreenCastStream::testCreateDmaBuf(const QSize &size, quint32 format, const QList<uint64_t> &modifiers)
 {
     AbstractEglBackend *backend = qobject_cast<AbstractEglBackend *>(Compositor::self()->backend());
-    if (!backend) {
+    if (!backend || !backend->drmDevice()) {
         return std::nullopt;
     }

--- a/src/scene/itemrenderer_opengl.cpp
+++ b/src/scene/itemrenderer_opengl.cpp
@@ -11,6 +11,7 @@
 #include "core/renderviewport.h"
 #include "core/syncobjtimeline.h"
 #include "effect/effect.h"
+#include "opengl/egldisplay.h"
 #include "opengl/eglnativefence.h"
 #include "platformsupport/scenes/opengl/openglsurfacetexture.h"
 #include "scene/decorationitem.h"
@@ -53,6 +54,13 @@

     if (m_eglDisplay) {
         EGLNativeFence fence(m_eglDisplay);
+        for (auto *buffer : m_dmaBufReads) {
+            if (!m_eglDisplay->releaseDmaBuf(buffer, fence.fileDescriptor(), false)) {
+                qFatal("Could not publish DMA-BUF read completion");
+            }
+            buffer->unref();
+        }
+        m_dmaBufReads.clear();
         if (fence.isValid()) {
             for (const auto &releasePoint : m_releasePoints) {
                 releasePoint->addReleaseFence(fence.fileDescriptor());
@@ -197,6 +205,7 @@
                     .colorDescription = item->colorDescription(),
                     .renderingIntent = item->renderingIntent(),
                     .bufferReleasePoint = surfaceItem->bufferReleasePoint(),
+                    .buffer = pixmap->buffer(),
                 });
             }
         }
@@ -339,6 +348,16 @@
             continue;
         }

+        if (m_eglDisplay && m_eglDisplay->dmaBufSyncRequired() && renderNode.buffer
+            && renderNode.buffer->dmabufAttributes() && !m_dmaBufReads.contains(renderNode.buffer)) {
+            if (!m_eglDisplay->acquireDmaBuf(renderNode.buffer, false)) {
+                qCWarning(KWIN_OPENGL) << "Could not acquire client DMA-BUF for reading";
+                continue;
+            }
+            renderNode.buffer->ref();
+            m_dmaBufReads.insert(renderNode.buffer);
+        }
+
         setBlendEnabled(renderNode.hasAlpha || renderNode.opacity < 1.0);

         ShaderTraits traits = baseShaderTraits;
--- a/src/scene/itemrenderer_opengl.h
+++ b/src/scene/itemrenderer_opengl.h
@@ -32,6 +32,7 @@
         ColorDescription colorDescription;
         RenderingIntent renderingIntent;
         std::shared_ptr<SyncReleasePoint> bufferReleasePoint;
+        GraphicsBuffer *buffer = nullptr;
     };

     struct RenderContext
@@ -65,6 +66,7 @@
     bool m_blendingEnabled = false;
     EglDisplay *const m_eglDisplay;
     std::unordered_set<std::shared_ptr<SyncReleasePoint>> m_releasePoints;
+    std::unordered_set<GraphicsBuffer *> m_dmaBufReads;

     struct
     {
--- a/src/wayland/linuxdmabufv1clientbuffer.cpp
+++ b/src/wayland/linuxdmabufv1clientbuffer.cpp
@@ -23,11 +23,10 @@

 namespace KWin
 {
-static const int s_version = 4;
-
-LinuxDmaBufV1ClientBufferIntegrationPrivate::LinuxDmaBufV1ClientBufferIntegrationPrivate(LinuxDmaBufV1ClientBufferIntegration *q, Display *display)
-    : QtWaylandServer::zwp_linux_dmabuf_v1(*display, s_version)
+LinuxDmaBufV1ClientBufferIntegrationPrivate::LinuxDmaBufV1ClientBufferIntegrationPrivate(LinuxDmaBufV1ClientBufferIntegration *q, Display *display, bool deviceFeedback)
+    : QtWaylandServer::zwp_linux_dmabuf_v1(*display, deviceFeedback ? 4 : 3)
     , q(q)
+    , deviceFeedback(deviceFeedback)
     , defaultFeedback(new LinuxDmaBufV1Feedback(this))
 {
 }
@@ -289,9 +288,9 @@
     return true;
 }

-LinuxDmaBufV1ClientBufferIntegration::LinuxDmaBufV1ClientBufferIntegration(Display *display)
+LinuxDmaBufV1ClientBufferIntegration::LinuxDmaBufV1ClientBufferIntegration(Display *display, bool deviceFeedback)
     : QObject(display)
-    , d(new LinuxDmaBufV1ClientBufferIntegrationPrivate(this, display))
+    , d(new LinuxDmaBufV1ClientBufferIntegrationPrivate(this, display, deviceFeedback))
 {
 }

@@ -328,6 +327,12 @@
     }
 }

+void LinuxDmaBufV1ClientBufferIntegration::setSupportedFormatsWithModifiers(const QHash<uint32_t, QList<uint64_t>> &formats)
+{
+    Q_ASSERT(!d->deviceFeedback);
+    d->supportedModifiers = formats;
+}
+
 void LinuxDmaBufV1ClientBuffer::buffer_destroy_resource(wl_resource *resource)
 {
     if (LinuxDmaBufV1ClientBuffer *buffer = LinuxDmaBufV1ClientBuffer::get(resource)) {
--- a/src/wayland/linuxdmabufv1clientbuffer.h
+++ b/src/wayland/linuxdmabufv1clientbuffer.h
@@ -66,13 +66,14 @@
     Q_OBJECT

 public:
-    explicit LinuxDmaBufV1ClientBufferIntegration(Display *display);
+    explicit LinuxDmaBufV1ClientBufferIntegration(Display *display, bool deviceFeedback = true);
     ~LinuxDmaBufV1ClientBufferIntegration() override;

     RenderBackend *renderBackend() const;
     void setRenderBackend(RenderBackend *renderBackend);

     void setSupportedFormatsWithModifiers(const QList<LinuxDmaBufV1Feedback::Tranche> &tranches);
+    void setSupportedFormatsWithModifiers(const QHash<uint32_t, QList<uint64_t>> &formats);

 private:
     friend class LinuxDmaBufV1ClientBufferIntegrationPrivate;
--- a/src/wayland/linuxdmabufv1clientbuffer_p.h
+++ b/src/wayland/linuxdmabufv1clientbuffer_p.h
@@ -31,9 +31,10 @@
 class LinuxDmaBufV1ClientBufferIntegrationPrivate : public QtWaylandServer::zwp_linux_dmabuf_v1
 {
 public:
-    LinuxDmaBufV1ClientBufferIntegrationPrivate(LinuxDmaBufV1ClientBufferIntegration *q, Display *display);
+    LinuxDmaBufV1ClientBufferIntegrationPrivate(LinuxDmaBufV1ClientBufferIntegration *q, Display *display, bool deviceFeedback);

     LinuxDmaBufV1ClientBufferIntegration *q;
+    const bool deviceFeedback;
     std::unique_ptr<LinuxDmaBufV1Feedback> defaultFeedback;
     std::unique_ptr<LinuxDmaBufV1FormatTable> table;
     dev_t mainDevice;
--- a/src/wayland_server.cpp
+++ b/src/wayland_server.cpp
@@ -521,10 +521,10 @@
     return m_drm;
 }

-LinuxDmaBufV1ClientBufferIntegration *WaylandServer::linuxDmabuf()
+LinuxDmaBufV1ClientBufferIntegration *WaylandServer::linuxDmabuf(bool deviceFeedback)
 {
     if (!m_linuxDmabuf) {
-        m_linuxDmabuf = new LinuxDmaBufV1ClientBufferIntegration(m_display);
+        m_linuxDmabuf = new LinuxDmaBufV1ClientBufferIntegration(m_display, deviceFeedback);
     }
     return m_linuxDmabuf;
 }
@@ -823,7 +823,7 @@

 void WaylandServer::setRenderBackend(RenderBackend *backend)
 {
-    if (backend->drmDevice()->supportsSyncObjTimelines()) {
+    if (const auto device = backend->drmDevice(); device && device->supportsSyncObjTimelines()) {
         // ensure the DRM_IOCTL_SYNCOBJ_EVENTFD ioctl is supported
         const auto linuxVersion = linuxKernelVersion();
         if (linuxVersion.majorVersion() < 6 && linuxVersion.minorVersion() < 6) {
--- a/src/wayland_server.h
+++ b/src/wayland_server.h
@@ -131,7 +131,7 @@
     bool isKeyboardShortcutsInhibited() const;

     DrmClientBufferIntegration *drm();
-    LinuxDmaBufV1ClientBufferIntegration *linuxDmabuf();
+    LinuxDmaBufV1ClientBufferIntegration *linuxDmabuf(bool deviceFeedback = true);

     InputMethodV1Interface *inputMethod() const
     {
PATCH
    case "${1:-6.3.6}" in
        6.2.5) cat <<'PATCH'
--- a/src/backends/wayland/wayland_egl_backend.cpp
+++ b/src/backends/wayland/wayland_egl_backend.cpp
@@ -9,6 +9,7 @@
 */

 #include "wayland_egl_backend.h"
+#include "dmaheapgraphicsbufferallocator.h"
 #include "core/drmdevice.h"
 #include "core/gbmgraphicsbufferallocator.h"
 #include "opengl/eglswapchain.h"
@@ -71,7 +72,7 @@
             if (it == formatTable.constEnd()) {
                 continue;
             }
-            m_swapchain = EglSwapchain::create(m_backend->drmDevice()->allocator(), m_backend->openglContext(), nativeSize, it.key(), it.value());
+            m_swapchain = EglSwapchain::create(m_backend->graphicsBufferAllocator(), m_backend->openglContext(), nativeSize, it.key(), it.value());
             if (m_swapchain) {
                 break;
             }
@@ -83,7 +84,7 @@
     }

     m_buffer = m_swapchain->acquire();
-    if (!m_buffer) {
+    if (!m_buffer || !m_backend->acquireBuffer(m_buffer->buffer())) {
         return std::nullopt;
     }

@@ -103,6 +104,9 @@
     // Flush rendering commands to the dmabuf.
     glFlush();
     EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
+    if (!m_backend->releaseBuffer(m_buffer->buffer(), releaseFence.fileDescriptor())) {
+        return false;
+    }

     m_presentationBuffer = m_backend->backend()->importBuffer(m_buffer->buffer());
     m_swapchain->release(m_buffer, releaseFence.takeFileDescriptor());
@@ -170,28 +174,24 @@
     const QSize bufferSize(std::ceil(tmp.width()), std::ceil(tmp.height()));
     if (!m_swapchain || m_swapchain->size() != bufferSize) {
         const QHash<uint32_t, QList<uint64_t>> formatTable = m_backend->backend()->display()->linuxDmabuf()->formats();
-        uint32_t format = DRM_FORMAT_INVALID;
-        QList<uint64_t> modifiers;
         for (const uint32_t &candidateFormat : {DRM_FORMAT_ARGB2101010, DRM_FORMAT_ARGB8888}) {
             auto it = formatTable.constFind(candidateFormat);
-            if (it != formatTable.constEnd()) {
-                format = it.key();
-                modifiers = it.value();
+            if (it == formatTable.constEnd()) {
+                continue;
+            }
+            m_swapchain = EglSwapchain::create(m_backend->graphicsBufferAllocator(), m_backend->openglContext(), bufferSize, it.key(), it.value());
+            if (m_swapchain) {
                 break;
             }
         }
-        if (format == DRM_FORMAT_INVALID) {
-            qCWarning(KWIN_WAYLAND_BACKEND) << "Could not find a suitable render format";
-            return std::nullopt;
-        }
-        m_swapchain = EglSwapchain::create(m_backend->drmDevice()->allocator(), m_backend->openglContext(), bufferSize, format, modifiers);
         if (!m_swapchain) {
+            qCWarning(KWIN_WAYLAND_BACKEND) << "Could not find a suitable cursor format";
             return std::nullopt;
         }
     }

     m_buffer = m_swapchain->acquire();
-    if (!m_buffer) {
+    if (!m_buffer || !m_backend->acquireBuffer(m_buffer->buffer())) {
         return std::nullopt;
     }

@@ -212,12 +212,16 @@
     // Flush rendering commands to the dmabuf.
     glFlush();

+    EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
+    if (!m_backend->releaseBuffer(m_buffer->buffer(), releaseFence.fileDescriptor())) {
+        return false;
+    }
+
     wl_buffer *buffer = m_backend->backend()->importBuffer(m_buffer->buffer());
     Q_ASSERT(buffer);

     static_cast<WaylandOutput *>(m_output)->cursor()->update(buffer, scale(), hotspot().toPoint());

-    EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
     m_swapchain->release(m_buffer, releaseFence.takeFileDescriptor());
     return true;
 }
@@ -259,6 +263,21 @@
     return m_backend->drmDevice();
 }

+GraphicsBufferAllocator *WaylandEglBackend::graphicsBufferAllocator() const
+{
+    return m_allocator ? m_allocator.get() : AbstractEglBackend::graphicsBufferAllocator();
+}
+
+bool WaylandEglBackend::acquireBuffer(GraphicsBuffer *buffer)
+{
+    return eglDisplayObject()->acquireDmaBuf(buffer, true);
+}
+
+bool WaylandEglBackend::releaseBuffer(GraphicsBuffer *buffer, const FileDescriptor &fence)
+{
+    return eglDisplayObject()->releaseDmaBuf(buffer, fence, true);
+}
+
 void WaylandEglBackend::cleanupSurfaces()
 {
     m_outputs.clear();
@@ -278,14 +297,19 @@
     initClientExtensions();

     if (!m_backend->sceneEglDisplayObject()) {
-        for (const QByteArray &extension : {QByteArrayLiteral("EGL_EXT_platform_base"), QByteArrayLiteral("EGL_KHR_platform_gbm")}) {
+        const auto platform = drmDevice() ? QByteArrayLiteral("EGL_KHR_platform_gbm") : QByteArrayLiteral("EGL_KHR_platform_wayland");
+        for (const QByteArray &extension : {QByteArrayLiteral("EGL_EXT_platform_base"), platform}) {
             if (!hasClientExtension(extension)) {
                 qCWarning(KWIN_WAYLAND_BACKEND) << extension << "client extension is not supported by the platform";
                 return false;
             }
         }

-        m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, m_backend->drmDevice()->gbmDevice(), nullptr)));
+        if (drmDevice()) {
+            m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, drmDevice()->gbmDevice(), nullptr)));
+        } else {
+            m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_WAYLAND_KHR, m_backend->display()->nativeDisplay(), nullptr)));
+        }
     }

     const auto display = m_backend->sceneEglDisplayObject();
@@ -293,6 +317,22 @@
         return false;
     }
     setEglDisplay(display);
+    if (!drmDevice()) {
+        for (const auto &extension : {QByteArrayLiteral("EGL_EXT_image_dma_buf_import_modifiers"),
+                                     QByteArrayLiteral("EGL_ANDROID_native_fence_sync"),
+                                     QByteArrayLiteral("EGL_KHR_wait_sync")}) {
+            if (!display->hasExtension(extension)) {
+                qCWarning(KWIN_WAYLAND_BACKEND) << "DMA heap rendering requires" << extension;
+                return false;
+            }
+        }
+        auto allocator = std::make_unique<DmaHeapGraphicsBufferAllocator>();
+        if (!allocator->isValid()) {
+            return false;
+        }
+        m_allocator = std::move(allocator);
+        display->setDmaBufSyncRequired(true);
+    }
     return true;
 }

@@ -307,6 +347,20 @@
         return;
     }

+    if (m_allocator) {
+        // Validate allocation, EGL import and both synchronization directions before
+        // advertising GPU composition or DMA-BUF to nested clients.
+        const auto formats = m_backend->display()->linuxDmabuf()->formats();
+        auto probe = EglSwapchain::create(m_allocator.get(), openglContext(), QSize(64, 64),
+                                          DRM_FORMAT_XRGB8888, formats.value(DRM_FORMAT_XRGB8888));
+        auto slot = probe ? probe->acquire() : nullptr;
+        EGLNativeFence fence{eglDisplayObject()};
+        if (!slot || !acquireBuffer(slot->buffer()) || !releaseBuffer(slot->buffer(), fence.fileDescriptor())) {
+            setFailed("DMA heap buffer import or synchronization is unavailable");
+            return;
+        }
+    }
+
     initWayland();
 }

--- a/src/compositor_wayland.cpp
+++ b/src/compositor_wayland.cpp
@@ -167,7 +167,7 @@
             break;
         } else if (qEnvironmentVariableIsSet("KWIN_COMPOSE")) {
             qCCritical(KWIN_CORE) << "Could not fulfill the requested compositing mode in KWIN_COMPOSE:" << type << ". Exiting.";
-            qApp->quit();
+            break;
         }
     }

@@ -176,7 +176,8 @@

         qCCritical(KWIN_CORE) << "The used windowing system requires compositing";
         qCCritical(KWIN_CORE) << "We are going to quit KWin now as it is broken";
-        qApp->quit();
+        // Startup may run before exec(); queue the failure for the event loop.
+        QMetaObject::invokeMethod(qApp, [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
         return;
     }

PATCH
            ;;
        6.3.6) cat <<'PATCH'
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -7,7 +7,7 @@
 set(CMAKE_CXX_STANDARD 23)
 set(CMAKE_CXX_STANDARD_REQUIRED ON)

-set(PROJECT_DEP_VERSION "6.3.6")
+set(PROJECT_DEP_VERSION "6.3.4")
 set(QT_MIN_VERSION "6.7.0")
 set(KF6_MIN_VERSION "6.10.0")
 set(KDE_COMPILERSETTINGS_LEVEL "5.82")
--- a/src/backends/wayland/wayland_egl_backend.cpp
+++ b/src/backends/wayland/wayland_egl_backend.cpp
@@ -9,6 +9,7 @@
 */

 #include "wayland_egl_backend.h"
+#include "dmaheapgraphicsbufferallocator.h"
 #include "core/drmdevice.h"
 #include "core/gbmgraphicsbufferallocator.h"
 #include "opengl/eglswapchain.h"
@@ -71,7 +72,7 @@
             if (it == formatTable.constEnd()) {
                 continue;
             }
-            m_swapchain = EglSwapchain::create(m_backend->drmDevice()->allocator(), m_backend->openglContext(), nativeSize, it.key(), it.value());
+            m_swapchain = EglSwapchain::create(m_backend->graphicsBufferAllocator(), m_backend->openglContext(), nativeSize, it.key(), it.value());
             if (m_swapchain) {
                 break;
             }
@@ -83,7 +84,7 @@
     }

     m_buffer = m_swapchain->acquire();
-    if (!m_buffer) {
+    if (!m_buffer || !m_backend->acquireBuffer(m_buffer->buffer())) {
         return std::nullopt;
     }

@@ -103,6 +104,9 @@
     // Flush rendering commands to the dmabuf.
     glFlush();
     EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
+    if (!m_backend->releaseBuffer(m_buffer->buffer(), releaseFence.fileDescriptor())) {
+        return false;
+    }

     static_cast<WaylandOutput *>(m_output)->setPrimaryBuffer(m_backend->backend()->importBuffer(m_buffer->buffer()));
     m_swapchain->release(m_buffer, releaseFence.takeFileDescriptor());
@@ -159,28 +163,24 @@
     const QSize bufferSize(std::ceil(tmp.width()), std::ceil(tmp.height()));
     if (!m_swapchain || m_swapchain->size() != bufferSize) {
         const QHash<uint32_t, QList<uint64_t>> formatTable = m_backend->backend()->display()->linuxDmabuf()->formats();
-        uint32_t format = DRM_FORMAT_INVALID;
-        QList<uint64_t> modifiers;
         for (const uint32_t &candidateFormat : {DRM_FORMAT_ARGB2101010, DRM_FORMAT_ARGB8888}) {
             auto it = formatTable.constFind(candidateFormat);
-            if (it != formatTable.constEnd()) {
-                format = it.key();
-                modifiers = it.value();
+            if (it == formatTable.constEnd()) {
+                continue;
+            }
+            m_swapchain = EglSwapchain::create(m_backend->graphicsBufferAllocator(), m_backend->openglContext(), bufferSize, it.key(), it.value());
+            if (m_swapchain) {
                 break;
             }
         }
-        if (format == DRM_FORMAT_INVALID) {
-            qCWarning(KWIN_WAYLAND_BACKEND) << "Could not find a suitable render format";
-            return std::nullopt;
-        }
-        m_swapchain = EglSwapchain::create(m_backend->drmDevice()->allocator(), m_backend->openglContext(), bufferSize, format, modifiers);
         if (!m_swapchain) {
+            qCWarning(KWIN_WAYLAND_BACKEND) << "Could not find a suitable cursor format";
             return std::nullopt;
         }
     }

     m_buffer = m_swapchain->acquire();
-    if (!m_buffer) {
+    if (!m_buffer || !m_backend->acquireBuffer(m_buffer->buffer())) {
         return std::nullopt;
     }

@@ -201,12 +201,16 @@
     // Flush rendering commands to the dmabuf.
     glFlush();

+    EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
+    if (!m_backend->releaseBuffer(m_buffer->buffer(), releaseFence.fileDescriptor())) {
+        return false;
+    }
+
     wl_buffer *buffer = m_backend->backend()->importBuffer(m_buffer->buffer());
     Q_ASSERT(buffer);

     static_cast<WaylandOutput *>(m_output)->cursor()->update(buffer, scale(), hotspot().toPoint());

-    EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
     m_swapchain->release(m_buffer, releaseFence.takeFileDescriptor());
     return true;
 }
@@ -248,6 +252,21 @@
     return m_backend->drmDevice();
 }

+GraphicsBufferAllocator *WaylandEglBackend::graphicsBufferAllocator() const
+{
+    return m_allocator ? m_allocator.get() : AbstractEglBackend::graphicsBufferAllocator();
+}
+
+bool WaylandEglBackend::acquireBuffer(GraphicsBuffer *buffer)
+{
+    return eglDisplayObject()->acquireDmaBuf(buffer, true);
+}
+
+bool WaylandEglBackend::releaseBuffer(GraphicsBuffer *buffer, const FileDescriptor &fence)
+{
+    return eglDisplayObject()->releaseDmaBuf(buffer, fence, true);
+}
+
 void WaylandEglBackend::cleanupSurfaces()
 {
     m_outputs.clear();
@@ -267,14 +286,19 @@
     initClientExtensions();

     if (!m_backend->sceneEglDisplayObject()) {
-        for (const QByteArray &extension : {QByteArrayLiteral("EGL_EXT_platform_base"), QByteArrayLiteral("EGL_KHR_platform_gbm")}) {
+        const auto platform = drmDevice() ? QByteArrayLiteral("EGL_KHR_platform_gbm") : QByteArrayLiteral("EGL_KHR_platform_wayland");
+        for (const QByteArray &extension : {QByteArrayLiteral("EGL_EXT_platform_base"), platform}) {
             if (!hasClientExtension(extension)) {
                 qCWarning(KWIN_WAYLAND_BACKEND) << extension << "client extension is not supported by the platform";
                 return false;
             }
         }

-        m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, m_backend->drmDevice()->gbmDevice(), nullptr)));
+        if (drmDevice()) {
+            m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, drmDevice()->gbmDevice(), nullptr)));
+        } else {
+            m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_WAYLAND_KHR, m_backend->display()->nativeDisplay(), nullptr)));
+        }
     }

     const auto display = m_backend->sceneEglDisplayObject();
@@ -282,6 +306,22 @@
         return false;
     }
     setEglDisplay(display);
+    if (!drmDevice()) {
+        for (const auto &extension : {QByteArrayLiteral("EGL_EXT_image_dma_buf_import_modifiers"),
+                                     QByteArrayLiteral("EGL_ANDROID_native_fence_sync"),
+                                     QByteArrayLiteral("EGL_KHR_wait_sync")}) {
+            if (!display->hasExtension(extension)) {
+                qCWarning(KWIN_WAYLAND_BACKEND) << "DMA heap rendering requires" << extension;
+                return false;
+            }
+        }
+        auto allocator = std::make_unique<DmaHeapGraphicsBufferAllocator>();
+        if (!allocator->isValid()) {
+            return false;
+        }
+        m_allocator = std::move(allocator);
+        display->setDmaBufSyncRequired(true);
+    }
     return true;
 }

@@ -296,6 +336,20 @@
         return;
     }

+    if (m_allocator) {
+        // Validate allocation, EGL import and both synchronization directions before
+        // advertising GPU composition or DMA-BUF to nested clients.
+        const auto formats = m_backend->display()->linuxDmabuf()->formats();
+        auto probe = EglSwapchain::create(m_allocator.get(), openglContext(), QSize(64, 64),
+                                          DRM_FORMAT_XRGB8888, formats.value(DRM_FORMAT_XRGB8888));
+        auto slot = probe ? probe->acquire() : nullptr;
+        EGLNativeFence fence{eglDisplayObject()};
+        if (!slot || !acquireBuffer(slot->buffer()) || !releaseBuffer(slot->buffer(), fence.fileDescriptor())) {
+            setFailed("DMA heap buffer import or synchronization is unavailable");
+            return;
+        }
+    }
+
     initWayland();
 }

--- a/src/compositor_wayland.cpp
+++ b/src/compositor_wayland.cpp
@@ -120,7 +120,7 @@
     return true;
 }

-void WaylandCompositor::createRenderer()
+bool WaylandCompositor::createRenderer()
 {
     // If compositing has been restarted, try to use the last used compositing type.
     const QList<CompositingType> availableCompositors = kwinApp()->outputBackend()->supportedCompositors();
@@ -161,9 +161,16 @@
             break;
         } else if (qEnvironmentVariableIsSet("KWIN_COMPOSE")) {
             qCCritical(KWIN_CORE) << "Could not fulfill the requested compositing mode in KWIN_COMPOSE:" << type << ". Exiting.";
-            qApp->quit();
+            break;
         }
     }
+    if (m_backend) {
+        return true;
+    }
+    qCCritical(KWIN_CORE) << "The used windowing system requires compositing";
+    // Startup may run before exec(); queue the failure for the event loop.
+    QMetaObject::invokeMethod(qApp, [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
+    return false;
 }

 void WaylandCompositor::createScene()
@@ -191,16 +198,8 @@
     Q_EMIT aboutToToggleCompositing();
     m_state = State::Starting;

-    if (!m_backend) {
-        createRenderer();
-    }
-
-    if (!m_backend) {
+    if (!m_backend && !createRenderer()) {
         m_state = State::Off;
-
-        qCCritical(KWIN_CORE) << "The used windowing system requires compositing";
-        qCCritical(KWIN_CORE) << "We are going to quit KWin now as it is broken";
-        qApp->quit();
         return;
     }

--- a/src/compositor_wayland.h
+++ b/src/compositor_wayland.h
@@ -23,7 +23,7 @@
     static WaylandCompositor *create(QObject *parent = nullptr);
     ~WaylandCompositor() override;

-    void createRenderer();
+    bool createRenderer();

     void start() override;
     void stop() override;
--- a/src/main_wayland.cpp
+++ b/src/main_wayland.cpp
@@ -142,7 +142,9 @@
     createTabletModeManager();

     auto compositor = WaylandCompositor::create();
-    compositor->createRenderer();
+    if (!compositor->createRenderer()) {
+        return;
+    }
     createWorkspace();
     createColorManager();
     createPlugins();
PATCH
            ;;
    esac
}

plasma_setup() {
    case "$distro" in steamos) kwin_version=6.2.5 ;; *) kwin_version=6.3.6 ;; esac
    distribution_support
    cat <<'KWIN_HEAD'
jobs=$1
recipe=$2
[ -f /usr/local/share/applications/magicdesk-plasma-wayland.desktop ] || exit 0
[ ! -r /etc/profile.d/magicdesk-graphics.sh ] || . /etc/profile.d/magicdesk-graphics.sh
[ -n "${MAGICDESK_MESA_PREFIX:-}" ] || exit 0
case "$ID:$VERSION_ID" in
    debian:13)
        version=6.3.6
        archive_sha=27f2205f06d58f1d1f480d2a94ae24022c2f95b9c1fdc5a549f8e143713fce12 ;;
    steamos:0.3.0)
        version=6.2.5
        archive_sha=5cc450a6e41105c8c49929b72550b331237f96aafb294690f4707bdc5f776848 ;;
    *) echo 'The pinned KWin recipe requires Debian 13 or SteamOS 0.3.0.' >&2; exit 1 ;;
esac
prefix=/opt/magicdesk/kwin/$version-$recipe
work=/var/cache/magicdesk/kwin/$version-$recipe
mkdir -p /var/lib/magicdesk /etc/magicdesk "$work"
exec 9>/var/lib/magicdesk/installer.lock
flock -n 9 || { echo 'Another graphics setup is running in this environment.' >&2; exit 1; }
candidate=/etc/magicdesk/plasma-kwin.sh.new
trap 'status=$?; rm -f "$candidate"; package_cleanup; exit "$status"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
cat > "$work/dmaheap.patch" <<'KWIN_PATCH'
KWIN_HEAD
    kwin_patch "$kwin_version"
    cat <<'KWIN_BODY'
KWIN_PATCH
if [ ! -f "$prefix/.complete" ]; then
    case "$family" in
    apt)
    packages build-essential cmake ninja-build extra-cmake-modules pkgconf patch curl xz-utils \
        gettext hwdata breeze-dev kscreenlocker-dev kwayland-dev \
        libcanberra-dev libcap-dev libdisplay-info-dev libdrm-dev libegl-dev libeis-dev \
        libepoxy-dev libfontconfig-dev libfreetype-dev libgbm-dev libice-dev libinput-dev \
        libkdecorations3-dev libkf6auth-dev libkf6colorscheme-dev libkf6config-dev \
        libkf6configwidgets-dev libkf6coreaddons-dev libkf6crash-dev libkf6dbusaddons-dev \
        libkf6declarative-dev libkf6doctools-dev libkf6globalaccel-dev libkf6guiaddons-dev \
        libkf6i18n-dev libkf6idletime-dev libkf6itemviews-dev libkf6kcmutils-dev \
        libkf6newstuff-dev libkf6notifications-dev libkf6package-dev libkf6runner-dev \
        libkf6service-dev libkf6svg-dev libkf6widgetsaddons-dev libkf6windowsystem-dev \
        libkf6xmlgui-dev libkglobalacceld-dev libkirigami-dev liblcms2-dev libpipewire-0.3-dev \
        libplasma-dev libplasmaactivities-dev libqaccessibilityclient-qt6-dev libsm-dev \
        libsystemd-dev libudev-dev libwayland-dev libx11-xcb-dev libxcb-composite0-dev \
        libxcb-cursor-dev libxcb-damage0-dev libxcb-dri3-dev libxcb-glx0-dev \
        libxcb-icccm4-dev libxcb-image0-dev libxcb-keysyms1-dev libxcb-present-dev \
        libxcb-randr0-dev libxcb-render0-dev libxcb-shape0-dev libxcb-shm0-dev \
        libxcb-sync-dev libxcb-util-dev libxcb-xfixes0-dev libxcb-xinerama0-dev \
        libxcb-xinput-dev libxcb-xkb-dev libxcb-xtest0-dev libxcb1-dev libxcursor-dev \
        libxcvt-dev libxkbcommon-dev libxkbcommon-x11-dev plasma-wayland-protocols \
        qt6-5compat-dev qt6-base-dev qt6-base-private-dev qt6-declarative-dev \
        qt6-declarative-private-dev qt6-sensors-dev qt6-svg-dev qt6-tools-dev \
        qt6-wayland-dev qt6-wayland-dev-tools wayland-protocols xwayland ;;
    recovery)
        # Arch-style packages already include headers; retain the image's Plasma ABI.
        packages base-devel cmake ninja extra-cmake-modules pkgconf patch curl xz \
            gettext wayland-protocols plasma-wayland-protocols ;;
    esac
    mkdir -p /var/cache/magicdesk/kwin/downloads
    archive=/var/cache/magicdesk/kwin/downloads/kwin-$version.tar.xz
    if ! printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c - >/dev/null 2>&1; then
        # EVENT_WAIT: download progress; a stalled connection fails and curl retries it.
        curl --fail --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 30 --speed-limit 1 --speed-time 60 --retry 3 --output "$archive.part" \
            "https://download.kde.org/stable/plasma/$version/kwin-$version.tar.xz"
        printf '%s  %s\n' "$archive_sha" "$archive.part" | sha256sum -c -
        mv "$archive.part" "$archive"
    fi
    source=$work/source
    if [ ! -f "$source/.patched" ]; then
        rm -rf "$source" "$work/build" "$work/unpack"
        mkdir "$work/unpack"
        tar -xJf "$archive" -C "$work/unpack"
        patch --batch --forward --fuzz=0 -p1 -d "$work/unpack/kwin-$version" < "$work/dmaheap.patch"
        touch "$work/unpack/kwin-$version/.patched"
        mv "$work/unpack/kwin-$version" "$source"
        rmdir "$work/unpack"
    fi
    cmake -S "$source" -B "$work/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_AUTOGEN_PARALLEL="$jobs" \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DKDE_INSTALL_USE_QT_SYS_PATHS=OFF \
        -DKDE_INSTALL_LIBDIR=lib -DKDE_INSTALL_QTPLUGINDIR=lib/qt6/plugins \
        -DKDE_INSTALL_QMLDIR=lib/qt6/qml -DCMAKE_INSTALL_RPATH="$prefix/lib" \
        -DBUILD_TESTING=OFF -DKWIN_BUILD_KCMS=OFF -DKWIN_BUILD_X11_BACKEND=OFF </dev/null
    cmake --build "$work/build" --parallel "$jobs" </dev/null
    rm -rf "$work/stage"
    DESTDIR="$work/stage" cmake --install "$work/build" </dev/null
    [ -x "$work/stage$prefix/bin/kwin_wayland" ] || exit 1
    mkdir -p /opt/magicdesk/kwin
    [ ! -e "$prefix" ] || { echo "Incomplete prefix exists: $prefix" >&2; exit 1; }
    printf '%s\n' "$recipe" > "$work/stage$prefix/.complete"
    mv "$work/stage$prefix" "$prefix"
fi
[ "$(cat "$prefix/.complete")" = "$recipe" ] || { echo 'KWin build identity mismatch.' >&2; exit 1; }
printf "kwin_prefix='%s'\n" "$prefix" > "$candidate"
mv "$candidate" /etc/magicdesk/plasma-kwin.sh
KWIN_BODY
}

# One payload is both fingerprinted and executed; the lab exports the same patch.
graphics_setup() {
    distribution_support
    cat <<'GPU_HEAD'
set -eu
umask 022
gpu=$1
jobs=$2
recipe=$3
version=26.2.3
archive_sha=1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f
mkdir -p /var/lib/magicdesk /etc/profile.d
exec 9>/var/lib/magicdesk/installer.lock
flock -n 9 || { echo 'Another graphics setup is running in this environment.' >&2; exit 1; }
profile=/etc/profile.d/magicdesk-graphics.sh
candidate=$profile.new
trap 'status=$?; rm -f "$candidate"; package_cleanup; exit "$status"' 0
trap 'exit 130' INT
trap 'exit 143' TERM

automatic=no
if [ "$gpu" = auto ]; then
    automatic=yes
    gpu=software
    if [ -c /dev/kgsl-3d0 ] && [ -r /dev/kgsl-3d0 ] && [ -w /dev/kgsl-3d0 ]; then
        gpu=turnip
    else
        printf 'KGSL is unavailable; selecting software rendering.\n'
    fi
fi
if [ "$gpu" = turnip ]; then
    [ -c /dev/kgsl-3d0 ] && [ -r /dev/kgsl-3d0 ] && [ -w /dev/kgsl-3d0 ] || {
        echo 'Turnip requires access to /dev/kgsl-3d0; the graphics profile is unchanged.' >&2
        exit 1
    }
    prefix=/opt/magicdesk/mesa/$version-$recipe
    work=/var/cache/magicdesk/mesa/$version-$recipe
    mkdir -p "$work"
    cat > "$work/wayland-zink.patch" <<'MESA_PATCH'
GPU_HEAD
    mesa_patch
    cat <<'GPU_BODY'
MESA_PATCH
    case "$family" in
    apt) packages build-essential meson ninja-build pkg-config \
        python3-mako python3-yaml python3-ply bison flex patch curl xz-utils glslang-tools \
        libdrm-dev libexpat1-dev libzstd-dev zlib1g-dev libelf-dev \
        libwayland-dev libwayland-egl-backend-dev wayland-protocols libglvnd-dev libvulkan-dev vulkan-tools mesa-utils \
        libx11-dev libx11-xcb-dev libxext-dev libxfixes-dev libxxf86vm-dev \
        libxrandr-dev libxshmfence-dev libxcb-glx0-dev libxcb-randr0-dev \
        libxcb-shm0-dev libxcb-dri3-dev libxcb-present-dev libxcb-sync-dev \
        libxcb-xfixes0-dev ;;
    apk) packages build-base meson ninja pkgconf python3 py3-mako py3-yaml py3-ply bison flex \
        patch curl xz glslang-dev linux-headers libdrm-dev expat-dev zstd-dev zlib-dev elfutils-dev \
        wayland-dev wayland-protocols libglvnd-dev vulkan-headers vulkan-tools \
        libx11-dev libxext-dev libxfixes-dev libxxf86vm-dev libxrandr-dev libxshmfence-dev libxcb-dev ;;
    dnf) packages gcc gcc-c++ meson ninja-build pkgconf-pkg-config python3-mako python3-pyyaml \
        python3-ply bison flex patch curl xz glslang libdrm-devel expat-devel libzstd-devel zlib-ng-compat-devel \
        elfutils-libelf-devel wayland-devel wayland-protocols-devel libglvnd-devel vulkan-headers vulkan-tools \
        libX11-devel libXext-devel libXfixes-devel libXxf86vm-devel libXrandr-devel libxshmfence-devel libxcb-devel ;;
    pacman|recovery) packages base-devel meson ninja pkgconf python-mako python-yaml python-ply bison flex \
        patch curl xz glslang libdrm expat zstd zlib libelf wayland wayland-protocols libglvnd vulkan-headers \
        vulkan-tools libx11 libxext libxfixes libxxf86vm libxrandr libxshmfence libxcb ;;
    zypper) packages gcc gcc-c++ make meson ninja pkgconf-pkg-config python3-Mako python3-PyYAML \
        python3-ply bison flex patch curl xz glslang-devel libdrm-devel libexpat-devel libzstd-devel zlib-devel \
        libelf-devel wayland-devel wayland-protocols-devel libglvnd-devel vulkan-headers vulkan-tools \
        libX11-devel libXext-devel libXfixes-devel libXxf86vm-devel libXrandr-devel libxshmfence-devel libxcb-devel ;;
    xbps) packages base-devel meson ninja pkg-config python3-Mako python3-yaml python3-ply bison flex \
        patch curl xz glslang libdrm-devel expat-devel libzstd-devel zlib-devel elfutils-devel \
        wayland-devel wayland-protocols libglvnd-devel Vulkan-Headers Vulkan-Tools \
        libX11-devel libXext-devel libXfixes-devel libXxf86vm-devel libXrandr-devel libxshmfence-devel libxcb-devel ;;
    esac
    if [ ! -f "$prefix/.complete" ]; then
        mkdir -p /var/cache/magicdesk/mesa/downloads
        archive=/var/cache/magicdesk/mesa/downloads/mesa-$version.tar.xz
        if ! printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c - >/dev/null 2>&1; then
            # EVENT_WAIT: download progress; a stalled connection fails and curl retries it.
            curl --fail --location --proto '=https' --proto-redir '=https' \
                --connect-timeout 30 --speed-limit 1 --speed-time 60 --retry 3 --output "$archive.part" \
                "https://archive.mesa3d.org/mesa-$version.tar.xz"
            printf '%s  %s\n' "$archive_sha" "$archive.part" | sha256sum -c -
            mv "$archive.part" "$archive"
        fi
        source=$work/source
        if [ ! -f "$source/.patched" ]; then
            rm -rf "$source" "$work/build" "$work/unpack"
            mkdir "$work/unpack"
            tar -xJf "$archive" -C "$work/unpack"
            source_tmp=$work/unpack/mesa-$version
            patch --batch --forward --fuzz=0 -p1 -d "$source_tmp" < "$work/wayland-zink.patch"
            touch "$source_tmp/.patched"
            mv "$source_tmp" "$source"
            rmdir "$work/unpack"
        fi
        # Both KMDs are needed: Vulkan WSI also uses the DRM image allocator.
        set -- --prefix="$prefix" --libdir=lib --buildtype=release --wrap-mode=nodownload \
            -Dauto_features=disabled -Dplatforms=x11,wayland -Dllvm=disabled \
            -Dxmlconfig=disabled -Dbuild-tests=false -Dgallium-rusticl=false \
            -Dvulkan-drivers=freedreno -Dfreedreno-kmds=msm,kgsl \
            -Dgallium-drivers=zink,softpipe -Dopengl=true -Dgles1=enabled -Dgles2=enabled -Dglx=dri \
            -Degl=enabled -Dgbm=enabled -Dglvnd=enabled -Dgallium-va=disabled
        if [ -f "$work/build/build.ninja" ]; then
            meson setup --reconfigure "$work/build" "$source" "$@" </dev/null
        else
            meson setup "$work/build" "$source" "$@" </dev/null
        fi
        ninja -C "$work/build" -j "$jobs" </dev/null
        # Install off to the side; a resumed/failed installation cannot alter active libraries.
        rm -rf "$work/stage"
        meson install -C "$work/build" --no-rebuild --destdir "$work/stage" </dev/null
        mkdir -p /opt/magicdesk/mesa
        [ ! -e "$prefix" ] || { echo "Incomplete prefix exists: $prefix" >&2; exit 1; }
        printf '%s\n' "$recipe" > "$work/stage$prefix/.complete"
        mv "$work/stage$prefix" "$prefix"
    fi
    [ "$(cat "$prefix/.complete")" = "$recipe" ] || { echo 'Mesa build identity mismatch.' >&2; exit 1; }
fi

# Remove only our previously exported library directory when re-sourcing a login profile.
reset_profile() {
cat <<'PROFILE'
if [ -n "${MAGICDESK_FEX_THUNKCONFIG:-}" ] && [ "${FEX_THUNKCONFIG:-}" = "$MAGICDESK_FEX_THUNKCONFIG" ]; then
    unset FEX_THUNKCONFIG
fi
unset MAGICDESK_FEX_THUNKCONFIG
if [ -n "${MAGICDESK_MESA_PREFIX:-}" ]; then
    _md_paths=${LD_LIBRARY_PATH:-}
    _md_kept=
    while [ -n "$_md_paths" ]; do
        _md_item=${_md_paths%%:*}
        case $_md_paths in *:*) _md_paths=${_md_paths#*:} ;; *) _md_paths= ;; esac
        if [ -n "$_md_item" ] && [ "$_md_item" != "$MAGICDESK_MESA_PREFIX/lib" ]; then
            _md_kept=${_md_kept:+$_md_kept:}$_md_item
        fi
    done
    if [ -n "$_md_kept" ]; then export LD_LIBRARY_PATH=$_md_kept; else unset LD_LIBRARY_PATH; fi
    _md_paths=${PRESSURE_VESSEL_FILESYSTEMS_RO:-}
    _md_kept=
    while [ -n "$_md_paths" ]; do
        _md_item=${_md_paths%%:*}
        case $_md_paths in *:*) _md_paths=${_md_paths#*:} ;; *) _md_paths= ;; esac
        if [ -n "$_md_item" ] && [ "$_md_item" != "$MAGICDESK_MESA_PREFIX" ] && [ "$_md_item" != /opt/magicdesk/fex-thunks.json ]; then
            _md_kept=${_md_kept:+$_md_kept:}$_md_item
        fi
    done
    if [ -n "$_md_kept" ]; then export PRESSURE_VESSEL_FILESYSTEMS_RO=$_md_kept; else unset PRESSURE_VESSEL_FILESYSTEMS_RO; fi
    unset _md_paths _md_kept _md_item
fi
unset MAGICDESK_MESA_PREFIX LIBGL_ALWAYS_SOFTWARE GALLIUM_DRIVER MESA_LOADER_DRIVER_OVERRIDE
unset LIBGL_DRIVERS_PATH LIBGL_KOPPER_DRI2 __EGL_VENDOR_LIBRARY_FILENAMES VK_DRIVER_FILES VK_ICD_FILENAMES
unset MESA_VK_WSI_DEBUG
PROFILE
}
reset_profile > "$candidate"
if [ "$gpu" = turnip ]; then
    printf 'export MAGICDESK_MESA_PREFIX=%s\n' "$prefix" >> "$candidate"
    cat >> "$candidate" <<'PROFILE'
export LD_LIBRARY_PATH="$MAGICDESK_MESA_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LIBGL_DRIVERS_PATH="$MAGICDESK_MESA_PREFIX/lib/dri"
export __EGL_VENDOR_LIBRARY_FILENAMES="$MAGICDESK_MESA_PREFIX/share/glvnd/egl_vendor.d/50_mesa.json"
export VK_DRIVER_FILES="$MAGICDESK_MESA_PREFIX/share/vulkan/icd.d/freedreno_icd.aarch64.json"
# Zink can also present through the frontend when Kopper/DRI3 is unavailable.
export MESA_LOADER_DRIVER_OVERRIDE=zink GALLIUM_DRIVER=zink LIBGL_KOPPER_DRI2=true
# Thunk defaults are loaded before FEX's per-game overrides; never replace those.
if [ -r /opt/magicdesk/fex-thunks.json ]; then
    if [ "${FEX_THUNKCONFIG+x}" != x ]; then
        export FEX_THUNKCONFIG=/opt/magicdesk/fex-thunks.json
        export MAGICDESK_FEX_THUNKCONFIG=$FEX_THUNKCONFIG
    fi
    export PRESSURE_VESSEL_FILESYSTEMS_RO="$MAGICDESK_MESA_PREFIX:/opt/magicdesk/fex-thunks.json${PRESSURE_VESSEL_FILESYSTEMS_RO:+:$PRESSURE_VESSEL_FILESYSTEMS_RO}"
fi
PROFILE
    # EVENT_WAIT: Vulkan enumeration exits; timeout rejects a hung driver, never activates it.
    probe_status=0
    /bin/sh -c '. "$1"; unset DISPLAY WAYLAND_DISPLAY; exec timeout 30 vulkaninfo --summary' sh "$candidate" \
        > "$work/vulkan-probe.log" 2>&1 || probe_status=$?
    cat "$work/vulkan-probe.log"
    if [ "$probe_status" -ne 0 ] || ! grep -Eq 'driverID[[:space:]]*=[[:space:]]*DRIVER_ID_MESA_TURNIP' "$work/vulkan-probe.log"; then
        [ "$automatic" = yes ] || {
            echo 'No working Turnip GPU found; the graphics profile is unchanged.' >&2; exit 1;
        }
        printf 'Turnip could not initialize this GPU (status %s); selecting software rendering.\n' "$probe_status"
        gpu=software
        reset_profile > "$candidate"
    fi
fi
if [ "$gpu" = software ]; then
    if [ "$ID" = steamos ]; then
        # Valve's Mesa supplies Zink, not a swrast Gallium driver. Its older
        # Lavapipe package needs LLVM 17 alongside the image's newer LLVM.
        packages vulkan-swrast llvm17-libs vulkan-tools mesa-utils
        cat >> "$candidate" <<'PROFILE'
export LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=zink MESA_LOADER_DRIVER_OVERRIDE=zink
export LIBGL_KOPPER_DRI2=true
export VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.aarch64.json
PROFILE
        work=/var/cache/magicdesk/software
        mkdir -p "$work"
        # EVENT_WAIT: Vulkan/EGL probes exit; expiry rejects the candidate profile.
        probe_status=0
        /bin/sh -c '. "$1"; unset DISPLAY WAYLAND_DISPLAY; exec timeout 30 /bin/sh -ec \
            "vulkaninfo --summary; eglinfo -B -p surfaceless"' sh "$candidate" \
            > "$work/probe.log" 2>&1 || probe_status=$?
        cat "$work/probe.log"
        if [ "$probe_status" -ne 0 ] \
                || ! grep -q 'DRIVER_ID_MESA_LLVMPIPE' "$work/probe.log" \
                || ! grep -Eq 'OpenGL core profile renderer:.*zink.*llvmpipe' "$work/probe.log"; then
            echo 'Lavapipe/Zink could not initialize; the graphics profile is unchanged.' >&2
            exit 1
        fi
    else
        printf 'export LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe\n' >> "$candidate"
    fi
fi
chmod 644 "$candidate"
mv -f "$candidate" "$profile"
printf 'Graphics profile activated for new launches: %s\n' "$gpu"
GPU_BODY
}

desktop_session() {
    cat <<'DESKTOP'
#!/bin/sh
set -eu
desktop=${1:?Expected xfce, weston, gnome, plasma-x11 or plasma-wayland}
shift
[ ! -r /etc/profile.d/magicdesk-graphics.sh ] || . /etc/profile.d/magicdesk-graphics.sh
[ ! -r /etc/profile.d/magicdesk-applications.sh ] || . /etc/profile.d/magicdesk-applications.sh
# Root needs no authentication agent. Keep packaged and user autostart files
# intact; this profile applies only to explicitly launched root desktops.
if [ "$(id -u)" = 0 ]; then
    export XDG_CONFIG_DIRS="/etc/magicdesk/root-session:${XDG_CONFIG_DIRS:-/etc/xdg}"
fi
case "$desktop" in
    xfce)
        unset WAYLAND_DISPLAY WAYLAND_SOCKET
        export XDG_SESSION_TYPE=x11 XDG_CURRENT_DESKTOP=XFCE XDG_SESSION_DESKTOP=xfce
        set -- xfce4-session "$@" ;;
    weston)
        export XDG_SESSION_TYPE=wayland
        renderer=pixman
        [ -z "${MAGICDESK_MESA_PREFIX:-}" ] || renderer=gl
        mkdir -p -m 1777 /tmp/.X11-unix
        set -- weston --backend=wayland --renderer="$renderer" --shell=desktop-shell.so --xwayland "$@" ;;
    gnome)
        export XDG_SESSION_TYPE=wayland XDG_CURRENT_DESKTOP=GNOME
        set -- gnome-shell --devkit "$@" ;;
    plasma-x11|plasma-wayland)
        export XDG_CURRENT_DESKTOP=KDE XDG_SESSION_DESKTOP=KDE KDE_FULL_SESSION=true KDE_SESSION_VERSION=6
        unset WAYLAND_SOCKET
        mkdir -p -m 1777 /tmp/.X11-unix
        mkdir -p "$HOME/.config"
        kwriteconfig6 --file startkderc --group General --key systemdBoot false
        if [ "$desktop" = plasma-x11 ]; then
            unset WAYLAND_DISPLAY
            export XDG_SESSION_TYPE=x11 QT_QPA_PLATFORM=xcb
            if [ "${LIBGL_ALWAYS_SOFTWARE:-}" = 1 ]; then
                export QT_QUICK_BACKEND=software
            fi
            set -- startplasma-x11 "$@"
        else
            unset DISPLAY
            export XDG_SESSION_TYPE=wayland QT_QPA_PLATFORM=wayland
            if [ -n "${MAGICDESK_MESA_PREFIX:-}" ]; then
                [ -r /etc/magicdesk/plasma-kwin.sh ] || {
                    echo 'Complete Plasma Turnip setup before launching the Wayland desktop.' >&2; exit 1;
                }
                . /etc/magicdesk/plasma-kwin.sh
                [ -x "$kwin_prefix/bin/kwin_wayland" ] || exit 1
                export PATH="$kwin_prefix/bin:$PATH"
                export LD_LIBRARY_PATH="$kwin_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
                export QT_PLUGIN_PATH="$kwin_prefix/lib/qt6/plugins${QT_PLUGIN_PATH:+:$QT_PLUGIN_PATH}"
                export QML_IMPORT_PATH="$kwin_prefix/lib/qt6/qml${QML_IMPORT_PATH:+:$QML_IMPORT_PATH}"
                export XDG_DATA_DIRS="$kwin_prefix/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
            else
                # The stock nested compositor has no DRM output in this session.
                export KWIN_COMPOSE=Q QT_QUICK_BACKEND=software
            fi
            set -- startplasma-wayland "$@"
        fi ;;
    *) echo "Unknown desktop: $desktop" >&2; exit 2 ;;
esac
# Reuse the launcher's bus. Direct guest-console launches get the same contract.
if [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    exec magicdesk-audio-session "$@"
fi
exec dbus-run-session -- magicdesk-audio-session "$@"
DESKTOP
}

audio_session() {
    cat <<'AUDIO'
#!/bin/bash
set -euo pipefail
if [[ ${1:-} == --ready ]]; then
    printf '%s\n' "$2" >&3
    exit
fi
[[ $# != 0 ]] || { echo 'Expected desktop command.' >&2; exit 2; }
[[ -n ${MAGICDESK_AUDIO_PULSE:-} ]] || exec "$@"
[[ ${MAGICDESK_AUDIO_SESSION:-} != active ]] || exec "$@"
# Native scheduling remains available; this session does not provide RTKit.
export DISABLE_RTKIT=1
host=$MAGICDESK_AUDIO_PULSE
[[ $host == /* && $host != *$'\n'* && $host != *$'\r'* ]] || {
    echo 'Invalid Android audio endpoint.' >&2; exit 2;
}
work=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/magicdesk-audio.XXXXXXXX")
children=()
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    # EVENT_WAIT: release clients before their server; wait owns only our child processes.
    for (( i=${#children[@]}-1; i>=0; i-- )); do
        kill "${children[i]}" 2>/dev/null || :
        wait "${children[i]}" 2>/dev/null || :
    done
    rm -rf -- "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/config/pipewire.conf.d" "$work/config/pipewire-pulse.conf.d" "$work/wp/wireplumber.conf.d"
cp /usr/share/pipewire/pipewire.conf /usr/share/pipewire/pipewire-pulse.conf "$work/config/"
cp /usr/share/wireplumber/wireplumber.conf "$work/wp/"
if [[ -d /usr/share/wireplumber/main.lua.d ]]; then
    # WirePlumber 0.4 (Ubuntu 24.04) uses Lua configuration, not feature profiles.
    for part in main.lua.d policy.lua.d bluetooth.lua.d common; do
        cp -a "/usr/share/wireplumber/$part" "$work/wp/"
    done
    cat > "$work/wp/main.lua.d/80-magicdesk.lua" <<'LUA'
alsa_monitor.enabled = false
v4l2_monitor.enabled = false
libcamera_monitor.enabled = false
LUA
    cat > "$work/wp/bluetooth.lua.d/80-magicdesk.lua" <<'LUA'
bluez_monitor.enabled = false
bluez_midi_monitor.enabled = false
LUA
fi
host=unix:${host//\\/\\\\}
host=${host//\"/\\\"}
cat > "$work/config/pipewire.conf.d/90-magicdesk.conf" <<CONFIG
# The guest graph has no hardware clock or guaranteed real-time scheduling.
# Keep a bounded scheduling budget even when a client requests a tiny quantum.
context.properties = { default.clock.rate = 48000 default.clock.min-quantum = 1024 mem.allow-mlock = false }
context.exec = [ { path = /usr/local/bin/magicdesk-audio-session args = "--ready core" } ]
CONFIG
# Keep the remote tunnel in a client context, not a core-to-itself connection.
cat > "$work/config/pipewire-pulse.conf.d/90-magicdesk.conf" <<CONFIG
pulse.properties = { pulse.min.req = 1024/48000 pulse.min.quantum = 1024/48000 }
context.modules = [
  { name = libpipewire-module-pulse-tunnel args = {
      tunnel.mode = sink
      pulse.server.address = "$host"
      pulse.latency = 60
      audio.rate = 48000
      audio.channels = 2
      audio.position = [ FL FR ]
      stream.props = {
        node.name = magicdesk.android
        node.description = "Android audio"
        # This is the guest's output device, not an internal routing node.
        node.virtual = false
      }
  } }
]
context.exec = [ { path = /usr/local/bin/magicdesk-audio-session args = "--ready pulse" } ]
CONFIG
cat > "$work/wp/wireplumber.conf.d/90-magicdesk.conf" <<'CONFIG'
wireplumber.profiles = {
  main = {
    monitor.alsa = disabled monitor.alsa-midi = disabled
    monitor.bluez = disabled monitor.bluez-midi = disabled
    monitor.v4l2 = disabled monitor.libcamera = disabled
  }
}
CONFIG
export PIPEWIRE_RUNTIME_DIR=$work PULSE_RUNTIME_PATH=$work/pulse
export PIPEWIRE_REMOTE=pipewire-0 PULSE_SERVER=unix:$work/pulse/native
export MAGICDESK_AUDIO_SESSION=active
mkfifo "$work/ready"
exec 3<>"$work/ready"
PIPEWIRE_CONFIG_DIR=$work/config pipewire &
children+=("$!")
# EVENT_WAIT: PipeWire context.exec startup receipt; expiry tears down this session.
read -r -t 15 receipt <&3 && [[ $receipt == core ]] || {
    echo 'Guest PipeWire startup failed.' >&2; exit 1;
}
WIREPLUMBER_CONFIG_DIR=$work/wp wireplumber 3>&- &
children+=("$!")
PIPEWIRE_CONFIG_DIR=$work/config pipewire-pulse &
children+=("$!")
# EVENT_WAIT: Pulse protocol server initialization, not a fixed startup delay.
read -r -t 15 receipt <&3 && [[ $receipt == pulse ]] || {
    echo 'Guest Pulse compatibility startup failed.' >&2; exit 1;
}
# EVENT_WAIT: the policy manager publishes both output ports; expiry rejects startup.
# A listening server alone does not mean that its sink has been configured.
exec 4< <(pw-link --input --monitor 3>&-)
monitor=$!
children+=("$monitor")
left=0 right=0 deadline=$((SECONDS + 15))
while (( !left || !right )); do
    remaining=$((deadline - SECONDS))
    (( remaining > 0 )) && IFS= read -r -t "$remaining" port <&4 || {
        echo 'Guest Android audio sink was not configured.' >&2; exit 1;
    }
    case $port in
        *magicdesk.android:*_FL) left=1 ;;
        *magicdesk.android:*_FR) right=1 ;;
    esac
done
exec 4<&-
kill "$monitor" 2>/dev/null || :
wait "$monitor" 2>/dev/null || :
unset 'children[-1]'
"$@" <&0 3>&- &
children+=("$!")
# EVENT_WAIT: desktop command lifetime; signal traps stop all owned audio services.
status=0
wait "${children[-1]}" || status=$?
unset 'children[-1]'
exit "$status"
AUDIO
}

steam_game() {
    cat <<'STEAM_GAME'
#!/usr/bin/env python3
"""Steam Launch Options: magicdesk-steam-game %command%."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


CONTAINER = r'''
set -eu
# FEX's empty-root lookup is relative to cwd; the container root is explicit.
if [ "${FEX_ROOTFS-unset}" = "" ]; then export FEX_ROOTFS=/; fi
if [ -n "${MAGICDESK_MESA_PREFIX:-}" ]; then
    export LD_LIBRARY_PATH="$MAGICDESK_MESA_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export LIBGL_DRIVERS_PATH="$MAGICDESK_MESA_PREFIX/lib/dri${LIBGL_DRIVERS_PATH:+:$LIBGL_DRIVERS_PATH}"
fi
exec "$@"
'''


def launch(command):
    if not command:
        raise ValueError('Use magicdesk-steam-game %command% in Steam Launch Options')
    if 'PRESSURE_VESSEL_EMULATOR' not in os.environ:
        # Steam declares its selected tools. argv also covers launchers that omit
        # that variable; never guess the user's Steam library location.
        directories = [Path(p) for p in os.environ.get('STEAM_COMPAT_TOOL_PATHS', '').split(':') if p]
        directories += [Path(p).parent for p in command if os.path.isabs(p)]
        for directory in dict.fromkeys(directories):
            source = directory / 'emulator.json'
            if not source.is_file():
                continue
            manifest = json.loads(source.read_text())
            emulator = manifest.get('emulator_v0', {})
            if 'FEX_ROOTFS' not in emulator.get('container_environment', {}):
                continue
            for key in ('argv', 'container_argv', 'main_argv', 'server_argv'):
                value = emulator.get(key)
                if value is None:
                    continue
                if isinstance(value, str):
                    value = [value]
                if not isinstance(value, list) or not value or not all(isinstance(p, str) for p in value):
                    raise ValueError('Invalid emulator command: ' + key)
                if not os.path.isabs(value[0]):
                    value[0] = str((directory / value[0]).absolute())
                emulator[key] = value
            for key in ('container_argv', 'main_argv'):
                # pressure-vessel maps this native host executable into /run/host.
                emulator[key] = ['/usr/bin/sh', '-c', CONTAINER,
                                 'magicdesk-steam-container', *emulator[key]]
            # SteamOS /bin/sh is Bash; its dependency must be captured with FEX's.
            emulator['required_libraries'] = list(dict.fromkeys([
                *emulator.get('required_libraries', []), 'libreadline.so.8']))
            data = json.dumps(manifest, sort_keys=True, indent=2).encode() + b'\n'
            cache = Path(os.environ.get('XDG_CACHE_HOME') or Path.home() / '.cache') / 'magicdesk/steam-fex'
            cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = cache / (hashlib.sha256(data).hexdigest() + '.json')
            if not target.is_file():
                fd, temporary = tempfile.mkstemp(dir=cache)
                try:
                    with os.fdopen(fd, 'wb') as output:
                        output.write(data)
                    os.replace(temporary, target)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
            os.environ['PRESSURE_VESSEL_EMULATOR'] = str(target)
            break
    os.execvp(command[0], command)


try:
    launch(sys.argv[1:])
except (OSError, ValueError, KeyError, TypeError) as error:
    sys.exit('magicdesk-steam-game: ' + str(error))
STEAM_GAME
}

system_setup() {
    distribution_support
    printf "install_desktop_session() {\ncat > /usr/local/bin/magicdesk-desktop-session <<'MD_DESKTOP_SESSION'\n"
    desktop_session
    cat <<'MD_DESKTOP_INSTALL'
MD_DESKTOP_SESSION
chmod 755 /usr/local/bin/magicdesk-desktop-session
# Normally created by tmpfiles at boot; direct non-root desktop launches need
# the same root-owned shared socket directories without booting the OS.
install -d -o root -g root -m 1777 /tmp/.X11-unix /tmp/.ICE-unix
mkdir -p /etc/magicdesk/root-session/autostart
cat > /etc/magicdesk/root-session/autostart/xfce-polkit.desktop <<'MD_ROOT_AGENT'
[Desktop Entry]
Type=Application
Name=XFCE PolKit
Hidden=true
MD_ROOT_AGENT
}
MD_DESKTOP_INSTALL
    printf "install_audio_session() {\ncat > /usr/local/bin/magicdesk-audio-session <<'MD_AUDIO_SESSION'\n"
    audio_session
    printf 'MD_AUDIO_SESSION\nchmod 755 /usr/local/bin/magicdesk-audio-session\n}\n'
    printf "install_steam_game() {\ncat > /usr/local/bin/magicdesk-steam-game <<'MD_STEAM_GAME'\n"
    steam_game
    printf 'MD_STEAM_GAME\nchmod 755 /usr/local/bin/magicdesk-steam-game\n}\n'
    cat <<'SETUP'
gui=$1
protocol=$2
locale_name=$3
zone=$4
new_user=$5
fonts=$6
cache=$7
extras=$8
# Minimal images may need util-linux first; package managers own their bootstrap locks.
setup_locked=no
if command -v flock >/dev/null 2>&1; then
    mkdir -p /var/lib/magicdesk
    exec 9>/var/lib/magicdesk/installer.lock
    flock -n 9 || { echo 'Another environment setup is running.' >&2; exit 1; }
    setup_locked=yes
fi
trap 'status=$?; package_cleanup; exit "$status"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
case "$family" in
    apt)
        if [ "$locale_name" != keep ] && [ "$locale_name" != C.UTF-8 ]; then
            # Slim images exclude translations from newly installed GUI packages.
            printf 'path-include /usr/share/locale/*\n' > /etc/dpkg/dpkg.cfg.d/zz-magicdesk-locales
        fi
        # Package services belong to Linux, not Android's service manager.
        if [ ! -e /usr/sbin/policy-rc.d ]; then
            printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
            chmod 755 /usr/sbin/policy-rc.d
        fi
        dpkg --configure -a </dev/null
        refresh_packages
        packages ca-certificates bash coreutils util-linux tzdata locales passwd ;;
    apk)
        refresh_packages
        packages ca-certificates bash coreutils util-linux tzdata musl-locales musl-locales-lang lang shadow ;;
    dnf) packages ca-certificates bash coreutils util-linux tzdata glibc-langpack-en shadow-utils ;;
    zypper)
        refresh_packages
        packages ca-certificates bash coreutils util-linux timezone glibc-locale glibc-i18ndata shadow ;;
    xbps)
        refresh_packages
        packages ca-certificates bash coreutils util-linux tzdata glibc-locales shadow ;;
    pacman)
        refresh_packages
        packages ca-certificates bash coreutils util-linux tzdata gzip ;;
    recovery)
        refresh_packages
        dbus-uuidgen --ensure ;;
esac
mkdir -p /var/lib/magicdesk /etc/profile.d /usr/local/bin /usr/local/share/applications
if [ "$family" = recovery ]; then
    mkdir -p /opt/magicdesk
    cat > /opt/magicdesk/fex-thunks.json <<'FEX_DEFAULTS'
{"ThunksDB":{"GL":"1","Vulkan":"1"}}
FEX_DEFAULTS
    install_steam_game
fi
if [ "$setup_locked" = no ]; then
    exec 9>/var/lib/magicdesk/installer.lock
    flock -n 9 || { echo 'Another environment setup is running.' >&2; exit 1; }
fi

if [ "$zone" != keep ]; then
    [ -f "/usr/share/zoneinfo/$zone" ] || { echo "Unknown timezone: $zone" >&2; exit 1; }
    ln -sfn "/usr/share/zoneinfo/$zone" /etc/localtime
    printf '%s\n' "$zone" > /etc/timezone
fi
if [ "$locale_name" != keep ]; then
    if [ "$locale_name" != C.UTF-8 ]; then
        language=${locale_name%%_*}
        case "$family" in
            apt|pacman|recovery|zypper|xbps) localedef -i "${locale_name%.UTF-8}" -f UTF-8 "$locale_name" ;;
            dnf) packages "glibc-langpack-$language" ;;
            apk)
                MUSL_LOCPATH=/usr/share/i18n/locales/musl locale -a | grep -Fqx "${locale_name%.UTF-8}" || {
                    echo "Locale not supplied by musl-locales: $locale_name" >&2; exit 1;
                } ;;
        esac
    fi
    # The selected guest locale must not be masked by Android Shell's LC_ALL.
    printf 'unset LC_ALL\nexport LANG=%s\n' "$locale_name" > /etc/profile.d/magicdesk-locale.sh
    printf 'LANG=%s\n' "$locale_name" > /etc/locale.conf
fi
if [ -n "$new_user" ]; then
    if getent passwd "$new_user" >/dev/null; then
        [ "$(id -u "$new_user")" -ge 1000 ] || {
            echo "Refusing to reuse system account: $new_user" >&2; exit 1;
        }
        printf 'Retaining existing account and home: %s\n' "$new_user"
    else
        useradd -m -U -s /bin/bash "$new_user"
    fi
fi

# Keep the selected desktops on resume, but refresh their shared launch services.
gui_services=no
if { [ "$gui" != none ] && [ "$gui" != keep ]; } || [ -x /usr/local/bin/magicdesk-audio-session ]; then
    gui_services=yes
    case "$family" in
        apt) packages pipewire pipewire-bin pipewire-pulse wireplumber pipewire-alsa pulseaudio-utils \
            libsdl2-2.0-0 libudev1 libdecor-0-plugin-1-cairo ;;
        apk) packages pipewire pipewire-pulse pipewire-tools wireplumber pipewire-alsa pulseaudio-utils \
            sdl2 eudev-libs libdecor ;;
        dnf) packages pipewire pipewire-pulseaudio pipewire-utils wireplumber pipewire-alsa pulseaudio-utils \
            sdl2-compat systemd-libs libdecor ;;
        pacman|recovery)
            udev_package=systemd-libs
            sdl_package=sdl2
            if [ "$ID" = artix ]; then udev_package=libudev; sdl_package=sdl2-compat; fi
            packages pipewire pipewire-pulse wireplumber pipewire-alsa libpulse \
                "$sdl_package" "$udev_package" libdecor ;;
        zypper) packages pipewire pipewire-pulseaudio pipewire-tools wireplumber pipewire-alsa pulseaudio-utils \
            libSDL2-2_0-0 libudev1 libdecor ;;
        xbps) packages pipewire wireplumber alsa-pipewire pulseaudio-utils SDL2 eudev-libudev libdecor ;;
    esac
    install_audio_session
    install_desktop_session
    case "$ID" in
        steamos) ;;
        openkylin) packages pavucontrol-qt ;;
        *) packages pavucontrol ;;
    esac
    if [ "$gui" = xfce ] || [ -f /usr/local/share/applications/magicdesk-xfce.desktop ]; then
        packages xfce4-pulseaudio-plugin
    fi
    if [ "$gui" = plasma ] || [ -f /usr/local/share/applications/magicdesk-plasma-wayland.desktop ]; then
        packages plasma-pa
    fi
fi
if [ "$gui" != none ] && [ "$gui" != keep ]; then
    case "$family" in
        apt) packages dbus-x11 xkb-data adwaita-icon-theme mousepad thunar xfce4-terminal \
            libgl1-mesa-dri libegl-mesa0 libglx-mesa0 libegl1 libgl1 libgles2 ;;
        apk) packages dbus dbus-x11 xkeyboard-config adwaita-icon-theme mousepad thunar xfce4-terminal \
            mesa-dri-gallium mesa-egl mesa-gl ;;
        dnf) packages dbus-daemon dbus-x11 xkeyboard-config adwaita-icon-theme mousepad Thunar xfce4-terminal \
            mesa-dri-drivers mesa-libEGL mesa-libGL ;;
        pacman) packages dbus xkeyboard-config adwaita-icon-theme mousepad thunar xfce4-terminal mesa ;;
        zypper) packages dbus-1-daemon dbus-1-tools xkeyboard-config adwaita-icon-theme mousepad thunar xfce4-terminal \
            Mesa-dri Mesa-libEGL1 Mesa-libGL1 ;;
        xbps) packages dbus xkeyboard-config adwaita-icon-theme mousepad Thunar xfce4-terminal \
            mesa-dri mesa ;;
    esac
    dbus-uuidgen --ensure
    case "$gui:$family" in
        xfce:apt|xfce:apk|xfce:pacman) packages xfce4 ;;
        xfce:dnf|xfce:zypper|xfce:xbps) packages xfce4-session xfce4-panel xfce4-settings xfce4-appfinder xfdesktop xfwm4 ;;
        weston:apk) packages weston weston-shell-desktop weston-backend-wayland weston-clients weston-xwayland xwayland ;;
        weston:apt) packages weston xwayland ;;
        weston:dnf) packages weston xorg-x11-server-Xwayland ;;
        weston:pacman) packages weston xorg-xwayland ;;
        weston:zypper) packages weston xwayland ;;
        weston:xbps) packages weston xorg-server-xwayland ;;
        plasma:apt) packages plasma-desktop plasma-workspace kwin-wayland kwin-x11 \
            dolphin konsole kdialog breeze xwayland qml6-module-qtquick-controls \
            qml6-module-qtquick-layouts qml6-module-qtquick-window ;;
        gnome:dnf) packages gnome-shell mutter-devkit gnome-terminal nautilus gnome-text-editor ;;
    esac
fi
if [ "$gui_services" = yes ]; then
    # Scheduling policy is launch-scoped, not a replacement for distro config.
    for config in client.conf client-rt.conf; do
        rm -f "/etc/pipewire/$config.d/90-magicdesk-scheduling.conf"
    done

    # VLC's relocatable Linux build guesses its plugin directory from native
    # /proc/self/maps. Object-backed stores need its explicit search path.
    mkdir -p /etc/profile.d
    cat > /etc/profile.d/magicdesk-applications.sh <<'APPLICATIONS'
# No realtime portal/RTKit service; PipeWire may still use native scheduling.
export DISABLE_RTKIT=1
if [ "${VLC_PLUGIN_PATH+x}" != x ]; then
    for _md_lib in /usr/lib /usr/lib64 /usr/lib/*-linux-gnu; do
        if [ -d "$_md_lib/vlc/plugins" ]; then
            export VLC_PLUGIN_PATH=$_md_lib/vlc/plugins
            break
        fi
    done
    unset _md_lib
fi
APPLICATIONS

fi
if [ "$gui" != none ] && [ "$gui" != keep ]; then
    # Protocol-specific entries are ours; distribution/user launchers are never rewritten.
    for backend in x11 wayland; do
        apps='mousepad thunar terminal'
        [ "$family" != recovery ] || apps=
        for app in $apps; do
            entry=/usr/local/share/applications/magicdesk-$app-$backend.desktop
            if [ "$protocol" != both ] && [ "$protocol" != "$backend" ]; then
                rm -f "$entry"
                continue
            fi
            case "$app" in
                mousepad) title=Mousepad; cmd='mousepad --disable-server %F'; icon=org.xfce.mousepad ;;
                thunar) title=Thunar; cmd='thunar %F'; icon=org.xfce.thunar ;;
                terminal) title='Xfce Terminal'; cmd='xfce4-terminal --disable-server'; icon=org.xfce.terminal ;;
            esac
            printf '[Desktop Entry]\nType=Application\nName=%s (%s)\nExec=env GDK_BACKEND=%s %s\nIcon=%s\nTerminal=false\nCategories=Utility;\nX-MagicDesk-Graphics=%s\n' \
                "$title" "$backend" "$backend" "$cmd" "$icon" "$backend" > "$entry"
        done
    done
    if [ ! -e /etc/profile.d/magicdesk-graphics.sh ]; then
        printf 'export LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe\n' > /etc/profile.d/magicdesk-graphics.sh
    fi
    if [ "$family" != recovery ]; then
        command -v mousepad
        command -v thunar
        command -v xfce4-terminal
    fi
fi

if [ "$gui_services" = yes ]; then
    # Refresh only installer-owned entries that exist or were explicitly selected.
    for desktop in xfce weston gnome plasma-x11 plasma-wayland; do
        entry=/usr/local/share/applications/magicdesk-$desktop.desktop
        [ "$gui" = "${desktop%%-*}" ] || [ -f "$entry" ] || continue
        case "$desktop" in
            xfce) title='Xfce Desktop'; backend=x11; icon=org.xfce.xfdesktop; program=xfce4-session ;;
            weston) title='Weston Desktop'; backend=wayland; icon=computer; program=weston ;;
            gnome) title='GNOME Shell (development kit)'; backend=wayland; icon=computer; program=gnome-shell ;;
            plasma-*) backend=${desktop#plasma-}; title="Plasma Desktop ($backend)"; icon=preferences-desktop; program=startplasma-$backend ;;
        esac
        command -v "$program"
        printf '[Desktop Entry]\nType=Application\nName=%s - %s\nExec=magicdesk-desktop-session %s\nIcon=%s\nTerminal=false\nCategories=System;\nX-MagicDesk-Graphics=%s\nX-MagicDesk-GraphicsMode=desktop\n' \
            "${NAME:-$ID}" "$title" "$desktop" "$icon" "$backend" > "$entry"
    done
    rm -f /usr/local/bin/magicdesk-plasma /usr/local/bin/magicdesk-weston
fi

if [ "$fonts" != keep ]; then
    case "$family" in
        apt) packages fonts-dejavu-core; [ "$fonts" != cjk ] || packages fonts-noto-cjk ;;
        apk) packages font-dejavu; [ "$fonts" != cjk ] || packages font-noto-cjk ;;
        dnf) packages dejavu-sans-fonts; [ "$fonts" != cjk ] || packages google-noto-sans-cjk-fonts ;;
        pacman) packages ttf-dejavu; [ "$fonts" != cjk ] || packages noto-fonts-cjk ;;
        zypper) packages dejavu-fonts; [ "$fonts" != cjk ] || packages google-noto-sans-cjk-fonts ;;
        xbps) packages dejavu-fonts-ttf; [ "$fonts" != cjk ] || packages noto-fonts-cjk ;;
    esac
fi
# Names were validated before any image mutation; no evaluation of package text.
if [ -n "$extras" ]; then
    set -f
    packages $extras
    set +f
fi
if [ "$cache" = clean ]; then
    case "$family" in
        apt) apt-get clean ;;
        apk) rm -f /var/cache/apk/*.apk ;;
        dnf) dnf clean packages ;;
        pacman) pacman -Sc --noconfirm </dev/null ;;
        zypper) zypper --non-interactive clean ;;
        xbps) xbps-remove -Oy ;;
    esac
fi
SETUP
}

recovery_reader() {
    cat <<'READER'
import base64
import bz2
import hashlib
import io
import json
import mmap
from pathlib import Path
import stat
import struct
import sys
import tarfile
import zlib


def exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError('Truncated recovery image')
    return data


def partition_table(stream):
    header = bytearray(exact(stream, 1024)[512:])
    if header[:8] != b'EFI PART':
        raise ValueError('Expected a GPT recovery image')
    size, checksum = struct.unpack_from('<II', header, 12)
    if not 92 <= size <= 512:
        raise ValueError('Invalid GPT header length')
    struct.pack_into('<I', header, 16, 0)
    if zlib.crc32(header[:size]) != checksum:
        raise ValueError('GPT header checksum mismatch')
    first, last = struct.unpack_from('<QQ', header, 40)
    lba, count, stride, crc = struct.unpack_from('<QIII', header, 72)
    if lba != 2 or not 1 <= count <= 4096 or stride != 128:
        raise ValueError('Unsupported GPT entry layout')
    table = exact(stream, count * stride)
    if zlib.crc32(table) != crc:
        raise ValueError('GPT table checksum mismatch')
    parts = {}
    ranges = []
    for i in range(count):
        entry = table[i * stride:(i + 1) * stride]
        if entry[:16] == bytes(16):
            continue
        start, end = struct.unpack_from('<QQ', entry, 32)
        name = entry[56:128].decode('utf-16-le').rstrip('\0')
        if not first <= start <= end <= last or name in parts:
            raise ValueError('Invalid or duplicate GPT partition')
        parts[name] = (start * 512, (end - start + 1) * 512)
        ranges.append((start, end))
    ranges.sort()
    if any(a[1] >= b[0] for a, b in zip(ranges, ranges[1:])):
        raise ValueError('Overlapping GPT partitions')
    return parts, 1024 + len(table)


def extract_root(archive, target):
    with bz2.open(archive, 'rb') as source:
        parts, offset = partition_table(source)
        start, size = parts['rootfs-A']
        if start < offset or size > 16 * 1024**3:
            raise ValueError('Unsupported recovery root partition')
        print(f'Reading rootfs-A: {size // 1024**2} MiB', flush=True)
        while offset < start:
            offset += len(exact(source, min(start - offset, 4 * 1024**2)))
        with target.open('xb') as output:
            remaining = size
            while remaining:
                block = exact(source, min(remaining, 4 * 1024**2))
                output.write(block)
                remaining -= len(block)
                if (size - remaining) % (256 * 1024**2) == 0 or not remaining:
                    print(f'Read {(size - remaining) // 1024**2}/{size // 1024**2} MiB', flush=True)
        # Consume the tail: a complete bzip2 stream, not just a readable partition.
        while source.read(4 * 1024**2):
            pass


def acl_text(value):
    if len(value) < 4 or struct.unpack_from('<I', value)[0] != 2 or (len(value) - 4) % 8:
        raise ValueError('Invalid POSIX ACL')
    names = {1: 'user', 2: 'user', 4: 'group', 8: 'group', 16: 'mask', 32: 'other'}
    entries = []
    for tag, perm, identifier in struct.iter_unpack('<HHI', value[4:]):
        if tag not in names or perm > 7:
            raise ValueError('Invalid POSIX ACL entry')
        who = str(identifier) if tag in (2, 8) else ''
        mode = ''.join(c if perm & bit else '-' for c, bit in [('r', 4), ('w', 2), ('x', 1)])
        entries.append(f'{names[tag]}:{who}:{mode}')
    return ','.join(entries)


def xattrs(node):
    from dissect.btrfs.c_btrfs import c_btrfs
    for _, data in node.subvolume.tree.cursor().iter(
            node.inum, c_btrfs.BTRFS_XATTR_ITEM_KEY, 0, ignore_offset=True):
        stream = io.BytesIO(data)
        while stream.tell() < len(data):
            item = c_btrfs.btrfs_dir_item(stream)
            yield item.name.decode('utf-8'), item.data


def metadata(node, name):
    info = tarfile.TarInfo(name)
    info.mode = stat.S_IMODE(node.mode)
    info.uid, info.gid = node.uid, node.gid
    info.mtime = node.mtime_ns // 10**9
    for field in ('mtime', 'atime'):
        value = getattr(node, field + '_ns')
        seconds, nanos = divmod(abs(value), 10**9)
        info.pax_headers[field] = f'{"-" if value < 0 else ""}{seconds}.{nanos:09d}'
    for key, value in xattrs(node):
        if key == 'btrfs.compression':
            continue  # Filesystem storage policy, not a userspace file attribute.
        if key in ('system.posix_acl_access', 'system.posix_acl_default'):
            info.pax_headers['SCHILY.acl.' + key.rsplit('_', 1)[1]] = acl_text(value)
        elif key == 'security.capability':
            info.pax_headers['LIBARCHIVE.xattr.' + key] = base64.b64encode(value).decode()
        else:
            raise ValueError(f'Unsupported image attribute {key} on {name}')
    return info


def children(node):
    return {name: child for name, child in node.iterdir() if name not in ('.', '..')}


def export_tree(archive, node, path='', fallback=None, links=None, factory=False):
    links = {} if links is None else links
    name = path or '.'
    info = metadata(node, name)
    kind = stat.S_IFMT(node.mode)
    if kind == stat.S_IFDIR:
        info.type = tarfile.DIRTYPE
    elif kind == stat.S_IFLNK:
        info.type, info.linkname = tarfile.SYMTYPE, node.link
    elif kind == stat.S_IFIFO:
        info.type = tarfile.FIFOTYPE
    elif kind == stat.S_IFREG:
        key = (factory, node.subvolume.objectid, node.inum)
        if key in links:
            info.type, info.linkname = tarfile.LNKTYPE, links[key]
        else:
            info.size = node.size
            links[key] = name
    else:
        raise ValueError(f'Unsupported file type {oct(kind)} at {name}')
    if info.isreg():
        with node.open() as source:
            archive.addfile(info, source)
    else:
        archive.addfile(info)
    if len(archive.members) % 5000 == 0:
        print(f'Exported {len(archive.members)} entries: /{name}', flush=True)
    if kind == stat.S_IFDIR:
        entries = children(node)
        defaults = children(fallback) if fallback else {}
        for child in sorted(entries.keys() | defaults.keys()):
            if not child or '/' in child or '\0' in child or child.startswith('.wh.'):
                raise ValueError('Invalid filesystem name')
            primary = entries.get(child)
            secondary = defaults.get(child)
            if primary is None:
                # Factory contents are copies, not aliases of /usr/share/factory.
                export_tree(archive, secondary, f'{path}/{child}'.lstrip('/'), links=links, factory=True)
            else:
                if not (primary.is_dir() and secondary and secondary.is_dir()):
                    secondary = None
                export_tree(archive, primary, f'{path}/{child}'.lstrip('/'), secondary, links, factory)


class HashWriter:
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def write(self, data):
        self.digest.update(data)
        return self.stream.write(data)


def json_blob(directory, value, media):
    data = json.dumps(value, separators=(',', ':')).encode()
    digest = hashlib.sha256(data).hexdigest()
    (directory / digest).write_bytes(data)
    return {'mediaType': media, 'digest': 'sha256:' + digest, 'size': len(data)}


def convert(image, destination):
    from compression import zstd
    from dissect.btrfs import Btrfs
    blobs = destination / 'blobs/sha256'
    blobs.mkdir(parents=True)
    layer = destination / 'layer.tmp'
    with image.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        fs = Btrfs(mapped)
        release = fs.get('/etc/os-release').open().read().decode()
        if '\nID=steamos\n' not in release or '\nVERSION_ID=0.3.0\n' not in release:
            raise ValueError('Unexpected SteamOS release')
        with zstd.open(layer, 'wb', level=3) as compressed:
            writer = HashWriter(compressed)
            with tarfile.open(fileobj=writer, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                # Recovery /var contains reimaging tools. Populate the installed
                # userspace from rootfs and its factory defaults instead.
                root = fs.get('/')
                info = metadata(root, '.')
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
                links = {}
                for name, node in sorted(children(root).items()):
                    print(f'Exporting /{name}', flush=True)
                    default = fs.get('/usr/share/factory/var') if name == 'var' else None
                    export_tree(tar, node, name, default, links)
        diff_id = writer.digest.hexdigest()
    with layer.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    length = layer.stat().st_size
    layer.rename(blobs / digest)
    config = json_blob(blobs, {
        'architecture': 'arm64', 'os': 'linux',
        'config': {'User': 'steamos', 'WorkingDir': '/home/steamos', 'Cmd': ['/bin/bash'],
                   'Env': ['PATH=/usr/local/sbin:/usr/local/bin:/usr/bin', 'HOME=/home/steamos'],
                   'Labels': {'org.opencontainers.image.title': 'SteamOS ARM64',
                              'org.opencontainers.image.version': '0.3.0',
                              'io.github.mekhontsev.magicdesk.recovery.sha256':
                              '3a4a077f1b1f40688ab3279affcb56776bd97c54db1573e7c65fc52a97106676'}},
        'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + diff_id]}},
        'application/vnd.oci.image.config.v1+json')
    manifest = json_blob(blobs, {'schemaVersion': 2, 'config': config, 'layers': [{
        'mediaType': 'application/vnd.oci.image.layer.v1.tar+zstd',
        'digest': 'sha256:' + digest, 'size': length}]},
        'application/vnd.oci.image.manifest.v1+json')
    (destination / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
    (destination / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
    print(f'Local SteamOS image ready: {length // 1024**2} MiB', flush=True)


if __name__ == '__main__':
    archive, work = Path(sys.argv[1]), Path(sys.argv[2])
    image = work / 'rootfs.img'
    extract_root(archive, image)
    convert(image, work / 'oci')
    image.unlink()
READER
}

download_verified() {
    file="$downloads/${1##*/}"
    if [ -f "$file" ] && [ ! -L "$file" ]; then
        actual=$(sha256sum "$file"); actual=${actual%% *}
        if [ "$actual" = "$2" ]; then printf 'Using verified %s\n' "$file"; return; fi
    fi
    magicdesk download "$1" "$file" --sha256 "$2"
}

import_helper() { MAGICDESK_GUEST_HOME="$import_work/library" shroot "$@"; }

prepare_downloads() {
    environments=$(shroot list)
    if printf '%s\n' "$environments" | cut -f1 | grep -Fxq "$name"; then
        fail "Environment $name already exists; use --resume to continue setup."
    fi
    downloads=${downloads:-${HOME:?}/downloads}
    mkdir -p "$downloads"
    downloads=$(cd "$downloads" && pwd -P)
}

prepare_import_helper() {
    work_parent=${TMPDIR:-$HOME/.cache}
    mkdir -p "$work_parent"
    work_parent=$(cd "$work_parent" && pwd -P)
    case "$work_parent/" in "$downloads/"*) fail 'Temporary work must be outside the read-only download cache.' ;; esac
    import_work=$(mktemp -d "$work_parent/magicdesk-import-XXXXXX")
    mkdir "$import_work/exchange"
    # Validate the selected DNS policy before fetching the multi-GB recovery archive.
    stage='preparing the temporary Python environment'
    import_helper install 'python@sha256:fe368aeff9df1995b57f0aa9bbced949a2a98fb3e6dfd92568e5f6acea6220f7' --name unpack --dns "$dns"
}

prepare_rootfs() {
    prepare_downloads
    stage="downloading the official $distro rootfs"
    download_verified "$source" "$source_sha"
    image="$downloads/${source##*/}"
    case "$source" in
        *.xz)
            prepare_import_helper
            stage='decompressing the rootfs archive'
            # Only change compression. Native import owns tar validation and metadata.
            import_helper exec unpack --bind "$import_work/exchange" /mnt --bind-ro "$downloads" /media \
                -- /usr/local/bin/python3 -c '
import gzip, lzma, shutil, sys
with lzma.open(sys.argv[1], "rb") as source, gzip.open(sys.argv[2], "wb", compresslevel=1) as target:
    shutil.copyfileobj(source, target, 1024 * 1024)
' "/media/${source##*/}" /mnt/rootfs.tar.gz
            image="$import_work/exchange/rootfs.tar.gz" ;;
    esac
}

prepare_recovery() {
    prepare_downloads
    prepare_import_helper
    stage='downloading the official SteamOS recovery image'
    download_verified "$source" '3a4a077f1b1f40688ab3279affcb56776bd97c54db1573e7c65fc52a97106676'
    stage='downloading pinned filesystem readers'
    download_verified 'https://files.pythonhosted.org/packages/a8/24/717afae59efd76fb85d882af52eeea827207776dd8bfdcd24916a0de5288/dissect_btrfs-1.10-py3-none-any.whl' '22569fba43c1740aa998544998beee09b599ff95f45d4fe3e05a47fac689d938'
    download_verified 'https://files.pythonhosted.org/packages/37/1c/dc626b1b0e477546c8e80d8cb028442ef4602af276c405f7a5ccc85b0b5a/dissect_cstruct-4.7-py3-none-any.whl' '0427621ce67baa3106df2dc63a320d0a7f5c2da88ba3faf2ef5886a1a6b458fd'
    download_verified 'https://files.pythonhosted.org/packages/cd/09/926cbb3fed29f762e676fb6a8d62b68c6bf536f817892cd35e89145e30e7/dissect_util-3.24-cp310-abi3-musllinux_1_2_aarch64.whl' 'df4130e896201c44e6b3d8ec1c022b586915abaedd1552f9c1b878bd343ae696'
    stage='installing the verified filesystem readers'
    import_helper exec unpack --bind-ro "$downloads" /mnt -- /usr/local/bin/python3 -m pip install \
        --no-index --no-deps --only-binary=:all: --no-cache-dir --root-user-action=ignore \
        /mnt/dissect_btrfs-1.10-py3-none-any.whl /mnt/dissect_cstruct-4.7-py3-none-any.whl \
        /mnt/dissect_util-3.24-cp310-abi3-musllinux_1_2_aarch64.whl
    stage='converting SteamOS to a local Linux image'
    recovery_reader | import_helper exec unpack --bind "$import_work/exchange" /mnt \
        --bind-ro "$downloads" /media -- /usr/local/bin/python3 - "/media/${source##*/}" /mnt
    image="$import_work/exchange/oci"
}

fail() { printf '%s\n' "$*" >&2; exit 1; }
require_magicdesk_version() {
    command -v magicdesk >/dev/null 2>&1 || fail 'magicdesk is unavailable. Open a MagicDesk Shell console first.'
    installed_magicdesk_version_code=$(magicdesk get_state --field data.app.versionCode) || \
        fail "Cannot determine MagicDesk version. Use MagicDesk $MIN_MAGICDESK_VERSION_NAME or newer and open a new Shell console."
    case "$installed_magicdesk_version_code" in
        ''|*[!0-9]*) fail 'Invalid MagicDesk versionCode; expected a non-negative Android version code.' ;;
    esac
    if [ "${#installed_magicdesk_version_code}" -gt 10 ] || [ "$installed_magicdesk_version_code" -gt 2147483647 ]; then
        fail 'Invalid MagicDesk versionCode; expected a non-negative Android version code.'
    fi
    [ "$installed_magicdesk_version_code" -ge "$MIN_MAGICDESK_VERSION_CODE" ] || \
        fail "This installer requires MagicDesk $MIN_MAGICDESK_VERSION_NAME or newer (versionCode $MIN_MAGICDESK_VERSION_CODE; installed $installed_magicdesk_version_code). Update MagicDesk, open a new Shell console and try again."
}
ask() {
    printf '%s [%s]: ' "$1" "$2"
    IFS= read -r answer || fail 'Input closed.'
    answer=${answer:-$2}
}
check_dns() {
    while ! dns_error=$(shroot dns --check "${dns:-system}" 2>&1); do
        printf '\nCannot prepare guest DNS.\n%s\n' "$dns_error" >&2
        printf '%s\n' \
            'Choose 1-3 numeric DNS server addresses (comma-separated) for ordinary Linux DNS.' \
            'This does not reproduce Android Private DNS; traffic follows Android routing/VPN policy.' \
            'Use preserve only if the image already contains a working resolver.' >&2
        [ "$yes" = no ] || fail 'Retry with --dns IP[,IP...] or --dns preserve. No image has been installed.'
        ask 'Guest DNS: IP[,IP...], preserve, system (retry), or cancel' cancel
        case "$answer" in
            cancel) printf 'Cancelled.\n'; exit 0 ;;
            *) dns=$answer ;;
        esac
    done
}
recipe_defaults() {
    source_kind=oci
    source_sha=
    case "$distro" in
        debian)
            source=https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/cf1f4a45447842b45e9952e0f018ae734a7341c7/trixie/slim/oci/blobs/rootfs.tar.gz
            source_sha=bbeda6b4abb749f743f4547ef5a28070a14de8caef211daa5afb78d5b5fa21ba
            source_kind=rootfs; version=13 ;;
        ubuntu)
            source=https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.5-base-arm64.tar.gz
            source_sha=a91d5a93010193712d346d761372b7c9db6dfcf093893161c64ca107f05914f2
            source_kind=rootfs; version=24.04 ;;
        alpine)
            source=https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/alpine-minirootfs-3.23.6-aarch64.tar.gz
            source_sha=b17a57958e29735ff0e6e64254d958e65903687a70ca30cc430b33a965ad49d7
            source_kind=rootfs; version=3.23 ;;
        fedora) source=registry.fedoraproject.org/fedora:44; version=44 ;;
        arch)
            # Official mirror with working TLS; archive authenticated with upstream's build key.
            source=https://de3.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz
            source_sha=42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319
            source_kind=rootfs; version=rolling ;;
        opensuse)
            source=https://download.opensuse.org/ports/aarch64/tumbleweed/appliances/opensuse-tumbleweed-image.aarch64-1.0.0-lxc-Snapshot20261011.tar.xz
            source_sha=a7b97cc9dfc056d7383b74a549b34572e57bfcfff8067a41e48db79a07e2b179
            source_kind=rootfs; version=Tumbleweed ;;
        openkylin) source=openkylin/openkylin:latest; version=3.0 ;;
        deepin) source=linuxdeepin/deepin:crimson-arm64; version=25 ;;
        manjaro)
            source=https://github.com/manjaro-arm/rootfs/releases/download/20261012/Manjaro-ARM-aarch64-latest.tar.gz
            source_sha=1ae540a80e21e1ca55e0576df9618fd2865cf4596b8204d20780f225aca5164a
            source_kind=rootfs; version=rolling ;;
        void)
            source=https://repo-default.voidlinux.org/live/20250202/void-aarch64-ROOTFS-20250202.tar.xz
            source_sha=01a30f17ae06d4d5b322cd579ca971bc479e02cc284ec1e5a4255bea6bac3ce6
            source_kind=rootfs; version=rolling ;;
        armtix)
            source=https://armtix.artixlinux.org/images/armtix-runit-20260921.tar.xz
            source_sha=8e1de041c64cb8bd8c1766d8f9048e75544de1c162769c02a626ce484aad4465
            source_kind=rootfs; version=rolling ;;
        steamos) source=https://steamdeck-images.steamos.cloud/recovery/steamframe-oobe-repair-20260922.5153644-0.3.0.img.bz2; version=0.3.0; source_kind=recovery ;;
        *) fail 'Unsupported distribution; use --list for available recipes.' ;;
    esac
}
distribution_id() {
    case "$1" in
        archarm) printf 'arch\n' ;;
        opensuse-tumbleweed) printf 'opensuse\n' ;;
        manjaro-arm) printf 'manjaro\n' ;;
        artix) printf 'armtix\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}
gui_notice() {
    [ "$gui" != gnome ] || printf 'GNOME devkit also needs a Linux system bus; this recipe does not boot one.\n'
}
if [ "$#" = 1 ] && [ "$1" = --print-mesa-patch ]; then mesa_patch; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-system-setup ]; then system_setup; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-graphics-setup ]; then graphics_setup; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-desktop-session ]; then desktop_session; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-audio-session ]; then audio_session; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-steam-game ]; then steam_game; exit 0; fi
if [ "$#" -ge 1 ] && [ "$1" = --print-kwin-patch ]; then
    [ "$#" -le 2 ] || fail 'Expected one KWin version.'
    kwin_patch "${2:-6.3.6}" || fail 'KWin version must be 6.3.6 or 6.2.5.'
    exit 0
fi
if [ "$#" = 1 ] && [ "$1" = --print-recovery-reader ]; then recovery_reader; exit 0; fi
distro=
name=
image=
gui=
protocol=both
gpu=
jobs=2
locale_name=
zone=
new_user=
fonts=
cache=keep
extras=
yes=no
resume=no
dns=
downloads=
import_work=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --distro|--name|--image|--downloads|--gui|--protocol|--gpu|--jobs|--locale|--timezone|--create-user|--fonts|--cache|--package|--dns)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail "Missing value for $1"
            case "$1" in
                --distro) distro=$2 ;; --name) name=$2 ;; --image) image=$2 ;; --gui) gui=$2 ;;
                --protocol) protocol=$2 ;; --gpu) gpu=$2 ;; --jobs) jobs=$2 ;; --locale) locale_name=$2 ;;
                --timezone) zone=$2 ;; --create-user) new_user=$2 ;; --fonts) fonts=$2 ;;
                --cache) cache=$2 ;;
                --package) extras="${extras:+$extras }$2" ;; --dns) dns=$2 ;;
                --downloads) downloads=$2 ;;
            esac
            shift 2 ;;
        --yes) yes=yes; shift ;;
        --resume) resume=yes; shift ;;
        --list) configurations; exit 0 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "Unknown argument: $1 (see --help)" ;;
    esac
done
if [ "$resume" = yes ]; then
    [ -n "$name" ] || fail '--resume requires --name NAME.'
    [ -z "$dns" ] && [ -z "$image" ] || fail '--resume retains image and DNS; use shroot dns to change DNS.'
fi

command -v shroot >/dev/null 2>&1 || fail 'Open a MagicDesk Shell console with shell access first.'
case "$(id -u)" in 2000|0) ;; *) fail 'Shroot requires the selected Android shell (UID 2000) or root executor.' ;; esac
require_magicdesk_version
if [ "$yes" = no ]; then
    [ -t 0 ] || fail 'Interactive input is unavailable. Save the script before running it, or use --yes.'
    if [ "$resume" = no ]; then
        configurations
        if [ -z "$distro" ]; then ask 'Distribution' debian; distro=$answer; fi
    fi
    if [ -z "$name" ]; then ask 'Independent environment name' "${distro:-debian}"; name=$answer; fi
    if [ "$distro" = steamos ]; then
        fonts=${fonts:-keep}
        printf 'SteamOS retains its supplied applications and system drivers.\n'
    fi
    if [ -z "$gui" ]; then
        default_gui=apps; [ "$resume" = no ] || default_gui=keep
        [ "$distro" != steamos ] || default_gui=plasma
        ask 'GUI: none/apps/xfce/weston/plasma (Debian/SteamOS)/gnome (Fedora devkit)/keep' "$default_gui"; gui=$answer
    fi
    if [ -z "$gpu" ]; then
        default_gpu=keep
        if [ "$distro" = steamos ] && [ "$resume" = no ]; then default_gpu=auto; fi
        ask 'Graphics: keep/software/auto/turnip (Adreno KGSL; builds Mesa)' "$default_gpu"; gpu=$answer
    fi
    if { [ "$gpu" = turnip ] || [ "$gpu" = auto ]; } && [ "$jobs" = 2 ]; then ask 'Mesa compiler jobs (1-8)' 2; jobs=$answer; fi
    if [ -z "$locale_name" ]; then ask 'Locale, e.g. ru_RU.UTF-8; keep leaves it unchanged' keep; locale_name=$answer; fi
    if [ -z "$zone" ]; then ask 'Timezone: system, IANA zone, or keep' keep; zone=$answer; fi
    if [ -z "$fonts" ]; then
        default_fonts=basic; [ "$resume" = no ] || default_fonts=keep
        [ "$distro" != steamos ] || default_fonts=keep
        ask 'Fonts: basic/cjk/keep' "$default_fonts"; fonts=$answer
    fi
    ask 'Additional settings (guest user, protocol, packages, DNS, cache)? y/N' N
    case "$answer" in
        y|Y|yes|YES)
            if [ -z "$new_user" ]; then ask 'Create guest user (empty = no new account)' ''; new_user=$answer; fi
            if [ "$distro" != steamos ]; then
                ask 'Installer application entries: both/x11/wayland' "$protocol"; protocol=$answer
                ask 'Additional repository packages (space-separated)' "$extras"; extras=$answer
            fi
            if [ "$resume" = no ] && [ -z "$dns" ]; then
                ask 'Guest DNS: system, preserve, or IP[,IP...]' system; dns=$answer
            fi
            if [ "$distro" != steamos ]; then ask 'Downloaded package cache: keep/clean' "$cache"; cache=$answer; fi
            ;;
    esac
fi
name=${name:-${distro:-debian}}
if [ "$resume" = yes ]; then
    gui=${gui:-keep}; fonts=${fonts:-keep}
elif [ "$distro" = steamos ]; then
    gui=${gui:-plasma}; gpu=${gpu:-auto}; fonts=${fonts:-keep}
else gui=${gui:-apps}; fonts=${fonts:-basic}; fi
gpu=${gpu:-keep}
locale_name=${locale_name:-keep}
zone=${zone:-keep}
dns=${dns:-system}
case "$name" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9_.-]*) fail 'Invalid environment name.' ;; esac
[ "${#name}" -le 64 ] || fail 'Name must be at most 64 characters.'
case "$gui" in none|apps|xfce|weston|plasma|gnome|keep) ;; *) fail 'Invalid GUI profile.' ;; esac
case "$protocol" in both|x11|wayland) ;; *) fail 'Protocol must be both, x11 or wayland.' ;; esac
case "$gpu" in keep|software|turnip|auto) ;; *) fail 'GPU must be keep, software, auto or turnip.' ;; esac
case "$jobs" in [1-8]) ;; *) fail 'Jobs must be between 1 and 8.' ;; esac
case "$locale_name" in
    keep|C.UTF-8) ;;
    *) printf '%s\n' "$locale_name" | grep -Eq '^[a-z]{2,3}_[A-Z]{2}\.UTF-8$' || fail 'Expected a UTF-8 locale such as en_US.UTF-8.' ;;
esac
if [ "$zone" = system ]; then
    command -v getprop >/dev/null 2>&1 || fail 'Android timezone is unavailable; supply an IANA timezone.'
    zone=$(getprop persist.sys.timezone)
    [ -n "$zone" ] || fail 'Android timezone is empty; supply an IANA timezone.'
fi
case "$zone" in ''|/*|*..*|*[!A-Za-z0-9_+/-]*) fail 'Invalid IANA timezone.' ;; esac
if [ -n "$new_user" ]; then
    printf '%s\n' "$new_user" | grep -Eq '^[a-z_][a-z0-9_-]{0,30}$' || fail 'Invalid guest account name.'
    [ "$new_user" != root ] || fail 'The root account already exists; --create-user creates an ordinary account.'
fi
case "$fonts" in basic|cjk|keep) ;; *) fail 'Fonts must be basic, cjk or keep.' ;; esac
case "$cache" in keep|clean) ;; *) fail 'Cache must be keep or clean.' ;; esac
if [ -n "$extras" ]; then
    printf '%s\n' "$extras" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9+_.-]*( [A-Za-z0-9][A-Za-z0-9+_.-]*)*$' || fail 'Expected repository package names, not options or shell commands.'
fi

# Read-only validation precedes every existing-environment mutation.
if [ "$resume" = yes ]; then
    detected=$(shroot exec "$name" --user root -- /bin/sh -c '. /etc/os-release; printf "%s\n" "$ID"')
    detected=$(distribution_id "$detected")
    [ -z "$distro" ] || [ "$distro" = "$detected" ] || fail 'Selected distribution does not match the existing environment.'
    distro=$detected
else
    distro=${distro:-debian}
fi
recipe_defaults
if [ "$distro" = steamos ]; then
    [ -z "$image" ] || fail 'SteamOS uses its pinned official recovery archive, not --image.'
    { [ "$gui" = keep ] || [ "$gui" = plasma ]; } && [ "$fonts" = keep ] && [ -z "$extras" ] \
        && [ "$cache" = keep ] || fail 'SteamOS supports plasma/keep with supplied applications and fonts.'
fi
if [ -n "$image" ]; then source_kind=oci; else image=$source; fi
[ "$gui" != gnome ] || [ "$distro" = fedora ] || fail 'The GNOME devkit recipe currently requires Fedora 44. Use apps, Xfce or Weston on other distributions.'
[ "$gui" != plasma ] || [ "$distro" = debian ] || [ "$distro" = steamos ] || fail 'The Plasma recipe requires Debian 13 or SteamOS 0.3.0.'
[ "$gui" != none ] || [ "$gpu" = keep ] || fail 'Choose a GUI profile before installing graphics; use --gui keep for an existing GUI.'
[ "$resume" = yes ] || check_dns

printf '\n%s %s ARM64 | %s | GUI=%s | graphics=%s\n' "$distro" "$version" "$name" "$gui" "$gpu"
printf 'Locale=%s | timezone=%s | fonts=%s | application entries=%s\n' "$locale_name" "$zone" "$fonts" "$protocol"
printf 'Guest account=%s | extra packages=%s | package cache=%s\n' "${new_user:-unchanged}" "${extras:-none}" "$cache"
[ "$gpu" != turnip ] || printf 'Mesa compiler jobs: %s\n' "$jobs"
if [ "$resume" = yes ]; then printf 'Continue the existing environment without replacing user data.\n'
else printf 'Source: %s\nGuest DNS: %s\n' "$image" "$dns"; fi
[ "$distro" != armtix ] || printf 'Armtix retains its upstream repository signature policy (the supplied rootfs disables package signatures).\n'
[ "$gui" != gnome ] || printf 'GNOME development kit is experimental; it is not a booted systemd/GDM desktop.\n'
gui_notice
if [ "$yes" = no ]; then
    ask 'Continue? y/N' N
    case "$answer" in y|Y|yes|YES) ;; *) printf 'Cancelled.\n'; exit 0 ;; esac
fi

stage='checking Shroot'
ready=no
finish() {
    status=$?
    if [ -n "$import_work" ]; then
        if [ "$status" -eq 0 ] || [ "$ready" = yes ]; then
            if import_helper remove unpack && import_helper prune; then
                rm -rf "$import_work"
            else
                printf 'Temporary converter retained: %s\n' "$import_work" >&2
            fi
        else
            printf 'Image conversion work retained for inspection: %s\n' "$import_work" >&2
        fi
    fi
    if [ "$status" -ne 0 ]; then
        printf '\nInstallation stopped while %s (exit %s).\n' "$stage" "$status" >&2
        if [ "$ready" = yes ]; then
            printf 'Environment retained. Repeat your options with --name %s --resume (do not reinstall).\n' "$name" >&2
            printf 'GUI=%s GPU=%s jobs=%s locale=%s timezone=%s fonts=%s\n' \
                "$gui" "$gpu" "$jobs" "$locale_name" "$zone" "$fonts" >&2
        else
            printf 'Inspect shroot list before retrying an interrupted installation.\n' >&2
        fi
    fi
}
trap finish 0
trap 'exit 130' INT
trap 'exit 143' TERM
shroot --probe
if [ "$resume" = no ]; then
    case "$source_kind" in
        recovery) prepare_recovery ;;
        rootfs) prepare_rootfs ;;
    esac
    stage='installing the Linux image'
    case "$source_kind" in
        recovery) shroot install "$image" --oci --name "$name" --dns "$dns" ;;
        rootfs) shroot install "$image" --rootfs --name "$name" --dns "$dns" ;;
        oci) shroot install "$image" --name "$name" --dns "$dns" ;;
    esac
    if [ "$dns" != preserve ]; then
        stage='applying selected DNS to the new environment'
        shroot dns "$name" "$dns" --replace
    fi
fi
stage='validating the selected environment'
shroot exec "$name" --user root -- /bin/sh -c '
    set -eu
    . /etc/os-release
    case "$ID" in archarm) ID=arch ;; opensuse-tumbleweed) ID=opensuse ;; manjaro-arm) ID=manjaro ;; artix) ID=armtix ;; esac
    [ "$ID" = "$1" ] || exit 1
    case "$ID" in
        debian|ubuntu|openkylin|deepin) [ "$VERSION_ID" = "$2" ] && [ "$(dpkg --print-architecture)" = arm64 ] ;;
        alpine) case "$VERSION_ID" in "$2".*) ;; *) exit 1 ;; esac; [ "$(apk --print-arch)" = aarch64 ] ;;
        fedora) [ "$VERSION_ID" = "$2" ] && [ "$(rpm --eval "%{_arch}")" = aarch64 ] ;;
        opensuse) [ "$(rpm --eval "%{_arch}")" = aarch64 ] ;;
        arch|manjaro|armtix) [ "$(uname -m)" = aarch64 ] ;;
        void) [ "$(xbps-uhelper arch)" = aarch64 ] ;;
        steamos) [ "$VERSION_ID" = "$2" ] && [ "$(uname -m)" = aarch64 ] ;;
    esac || { echo "Unexpected distribution version or architecture; setup was not applied." >&2; exit 1; }
' sh "$distro" "$version"
ready=yes
setup_exec() {
    set -- -- /bin/sh -s -- "$@"
    # Explicit XBPS network preference; never inherit the whole Android environment.
    [ "${FORCE_IPV4:-}" != 1 ] || set -- --env FORCE_IPV4=1 "$@"
    # Only these setup processes run in an unbooted rootfs. Do not persist this
    # hint in login profiles: an eventual systemd boot must discover its own state.
    shroot exec "$name" --user root --env DEBIAN_FRONTEND=noninteractive --env SYSTEMD_IN_CHROOT=1 "$@"
}
stage='installing packages and guest settings'
while :; do
    if system_setup | setup_exec \
            "$gui" "$protocol" "$locale_name" "$zone" "$new_user" "$fonts" "$cache" "$extras"; then
        break
    else
        setup_status=$?
    fi
    [ "$yes" = no ] || exit "$setup_status"
    printf '\nPackage setup failed (exit %s). The environment and your choices are retained.\n' "$setup_status" >&2
    printf 'Review the error above. Changing DNS only helps resolver problems.\n' >&2
    while :; do
        ask 'Package setup: retry, dns (change resolver and retry), or cancel' cancel
        case "$answer" in
            retry) break ;;
            dns)
                ask 'Guest DNS: system, preserve (keep current resolver), or IP[,IP...]' "$dns"
                dns=$answer
                check_dns
                [ "$dns" = preserve ] || shroot dns "$name" "$dns" --replace
                break ;;
            cancel) exit "$setup_status" ;;
            *) printf 'Choose retry, dns, or cancel.\n' >&2 ;;
        esac
    done
done

if [ "$distro" = steamos ]; then
    stage='preparing the supplied Steam client'
    printf 'Preparing the supplied Steam client for the steamos account...\n'
    shroot exec "$name" -- /bin/sh -c '
        set -eu
        [ "$(id -un)" = steamos ]
        mkdir -p "$HOME/.steam" "$HOME/.local/share"
        exec 9>"$HOME/.steam/installer.lock"
        flock -n 9 || { echo "Another Steam setup is running." >&2; exit 1; }
        if [ ! -d "$HOME/.local/share/Steam" ]; then
            work=$(mktemp -d "$HOME/.local/share/.steam-XXXXXX")
            trap '\''rm -rf "$work"'\'' 0
            tar --zstd --checkpoint=10000 -xf /usr/lib/steam/steam.tar.zst -C "$work"
            [ -x "$work/steamrtarm64/steam" ]
            mv "$work" "$HOME/.local/share/Steam"
        fi
        if [ ! -e "$HOME/.steam/steam" ] && [ ! -L "$HOME/.steam/steam" ]; then
            ln -s ../.local/share/Steam "$HOME/.steam/steam"
        fi
        # Desktop launches need the SDK paths too, without RUNSTEAM session policy.
        for link in root sdk32 sdk64 sdkarm64 bin32 bin64 binarm64; do
            case "$link" in
                root) target=. ;;
                sdk32) target=linux32 ;; sdk64) target=linux64 ;; sdkarm64) target=linuxarm64 ;;
                bin32) target=ubuntu12_32 ;; bin64) target=ubuntu12_64 ;; binarm64) target=steamrtarm64 ;;
            esac
            if [ ! -e "$HOME/.steam/$link" ] && [ ! -L "$HOME/.steam/$link" ]; then
                ln -s "steam/$target" "$HOME/.steam/$link"
            fi
        done
    '
fi

if [ "$gpu" != keep ]; then
    stage="preparing the $gpu graphics profile"
    recipe=$(graphics_setup | sha256sum)
    recipe=${recipe%% *}
    graphics_setup | setup_exec "$gpu" "$jobs" "$recipe"
fi

if [ "$gui" = plasma ] || [ "$gpu" != keep ]; then
    stage='preparing the nested Plasma compositor'
    recipe=$(plasma_setup | sha256sum)
    recipe=${recipe%% *}
    plasma_setup | setup_exec "$jobs" "$recipe"
fi

stage=complete
printf '\nLinux is ready: %s (%s %s)\n' "$name" "$distro" "$version"
gui_notice
printf '\nNext steps:\n'
if [ "$gui" != none ]; then
    printf 'In MagicDesk Control Panel, select a display and open Apps (Start).\n'
    printf 'Press Refresh beside the search field to load installed Linux entries.\n'
    printf 'Audio connects to Android automatically. Desktop volume controls use their private PipeWire graph.\n'
    printf 'Android gamepads are available in the focused Shroot window, on X11 and Wayland.\n'
fi
case "$gui" in
    none) printf 'No GUI was installed by this run. Use a terminal below.\n' ;;
    keep) printf 'Existing GUI entries were preserved; choose an installed application or desktop.\n' ;;
    *)
        app_backends='x11 wayland'
        [ "$distro" != steamos ] || app_backends=
        for backend in $app_backends; do
            if [ "$protocol" = both ] || [ "$protocol" = "$backend" ]; then
                printf 'Individual apps: Mousepad (%s), Thunar (%s), Xfce Terminal (%s).\n' "$backend" "$backend" "$backend"
            fi
        done
        case "$gui" in
            apps) printf 'The apps profile adds individual applications, not a whole Linux desktop.\n' ;;
            xfce) printf 'Whole desktop: search for Xfce Desktop (X11), environment %s.\n' "$name" ;;
            weston) printf 'Whole desktop: search for Weston Desktop (Wayland), environment %s.\n' "$name" ;;
            plasma) printf 'Whole desktop: search for Plasma Desktop (x11) or Plasma Desktop (wayland), environment %s.\n' "$name" ;;
            gnome) printf 'Experimental desktop: search for GNOME Shell (development kit), environment %s; requires a Linux system bus.\n' "$name" ;;
        esac ;;
esac
printf 'Terminal: Terminal sessions > New session > Shroot environments > %s > New session.\n' "$name"
printf 'Keep privileged access available; no MagicDesk Desktop session or installer rerun is needed.\n'
printf 'Console: shroot login %s\n' "$name"
[ "$distro" != steamos ] || printf '%s\n' 'SteamOS uses the steamos guest account. Open Steam from Apps; its own updater may download client components.' 'For x86 Linux games using FEX, set Steam Launch Options: magicdesk-steam-game %command%' 'This installs Linux userspace, not SteamOS boot, recovery or VR services. GPU/game compatibility is a separate check.'
if [ -n "$new_user" ]; then printf 'User console: shroot login %s --user %s\n' "$name" "$new_user"; fi
printf 'Folder attachment: shroot login %s --bind /sdcard/Download /mnt\n' "$name"
printf 'Optional Android command access: shroot login %s --magicdesk\n' "$name"
printf 'Backup (close its applications first): shroot backup %s /sdcard/Download/%s.tar.zst\n' "$name" "$name"
if [ "$gpu" = turnip ]; then
    printf 'Software fallback: sh install_linux.sh --name %s --resume --gpu software\n' "$name"
fi
