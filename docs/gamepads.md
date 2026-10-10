# Linux Gamepads

Shroot graphical launches receive Android gamepad input through a shared
launch-scoped service. It works with the shell executor, without root, Termux,
Desktop or access to Android's physical `/dev/input` nodes. X11 and Wayland use
the same Android host binding. Termux, PRoot and chroot do not consume this
bridge.

## Ownership

`LinuxLaunchServices` retains audio and gamepad capabilities independently of
viewer placement. `LinuxGamepads` owns executor-authenticated socket admission
and subscribes to Android device callbacks only while Shroot is connected.
`HostedSurfaceView` selects the recipient from actual window/view focus. Losing
focus releases pressed controls and stops feedback. Closing a viewer does not
destroy a retained graphical session; it relinquishes input.

The wire protocol carries bounded capability snapshots, changed input frames,
device removal, neutralization and rumble requests. Queue overflow disconnects
the affected consumer instead of dropping a release event. No periodic device
scan runs. Without a connected guest there are no reader/writer threads or
Android input-device subscription. Events use the controller's reported ranges;
duplicate Android trigger aliases map to one Linux axis.

## Guest Devices

The Shroot supervisor owns one input bus per attached launch. `--gamepad-endpoint`
explicitly selects its endpoint; the graphical shell wrapper supplies it when
`MAGICDESK_GAMEPAD_ENDPOINT` is present. A launch without the option keeps its
ordinary device view. Descendants share the bus, but another launch does not
inherit its virtual devices merely by using the same distribution store.

Private provider mounts expose `/dev/input/eventN`, `/dev/input/jsN`, input
sysfs attributes and `/run/udev` discovery records. The launch-private sysfs
inventory describes the published devices, without importing Android's PCI,
DRM or other host device trees. Host `/dev` entries outside the provider's input
subtree retain their existing access boundaries; guest `/dev/shm` remains
inode-backed. Device nodes are typed control files, not
host character devices. Namespace placeholders retain path identity; per-open
native socket carriers supply `poll`/`epoll` readiness.
Descriptor passing inside the launch retains the original provider-bearing
mount view through local IPC custody, including ordinary files and shared
memory. Such private views are not flattened into host paths for other launches.

Evdev and joydev are two views of each controller. Independent opens have
independent bounded queues; dup/fork retain one open description. Read copying
commits only delivered events. Overflow reports `SYN_DROPPED`; removal/revoke
terminates old descriptions even when a replacement reuses the same slot.
Capability/state queries, axis metadata, grab/revoke and event clocks are typed
ioctls. Unknown operations fail explicitly.

Launch-private `NETLINK_KOBJECT_UEVENT` monitors expose kernel and libudev event
formats over retained datagram carriers. Only provider-published packets receive
the trusted source identity. Guest publication is denied; these monitors do not
listen to Android's global device events. Metadata is published before add and
retired before remove.

## Feedback and Virtual Controllers

`FF_RUMBLE` supports upload, replacement, erase, gain and playback. Android uses
the controller's vibrator, never the phone's. When only a combined actuator is
exposed, strong/weak channels reduce to their maximum amplitude. Devices without
vibration do not advertise rumble. Timing advances at effect boundaries; it is
not a frame-rate poll.

Guest `/dev/uinput` creates launch-private controllers with key/absolute-axis
capabilities and rumble. Modern setup and legacy `uinput_user_dev` use the same
device model, sysfs publication, evdev/joydev and hotplug path. `UI_SET_PHYS`
retains a bounded string; unsupported relative-motion/device classes return
explicit errors. There are up to 32 physical and 32 virtual slots.

Virtual force-feedback requests use `UI_BEGIN_FF_UPLOAD`/`UI_END_FF_UPLOAD` and
the corresponding erase handshake. An asynchronous typed-control request owns
the pending effect without holding file-table or open-description turns. Owner
closure, cancellation and a bounded response deadline release that request.
The final uinput description close removes its device; session teardown closes
both configured and still-unconfigured handles.

This provides the controller-facing mechanism needed by Steam Input, not a
claim that every Steam Input profile, HID extension or controller is verified.
Raw HID, sensors, LEDs, touch surfaces and adaptive-trigger effects are outside
the current gamepad contract.

## Verification

- `GamepadWireTest`: capability framing, normalization and optional launch export.
- `test_input_devices`: evdev/joydev, independent queues, copy failure,
  neutralization, hotplug, grab/revoke, overflow and rumble.
- `test_input_uinput`: virtual-device lifetime, feedback acknowledgement/error,
  cancellation, erase, recreate and session teardown.
- `fs_dispatch --input`: actual shell-owned mounts, discovery, typed opens,
  retained shared memory, lower host devices, sysfs isolation and udev removal.
- `test_input_guest`: real guest syscalls, sysfs discovery, poll/epoll, EFAULT
  rollback and cross-thread force feedback, including owner-close cancellation.
- `test_input_hotplug.py`: live SDL/libudev add, open and remove through the same
  guest device model.
- `test_gamepad_sdl.py`: interactive axes, buttons, hat and button-triggered
  vibration. Requires Python 3, SDL2 and the selected graphical client's normal
  runtime dependencies inside the distribution. Debian Wayland clients need
  `libegl1`, `libgl1`, `libgles2`, `libegl-mesa0`, `libgl1-mesa-dri` and a libdecor
  plugin. SDL's software renderer can still use EGL for window presentation;
  installing only Mesa's vendor library does not supply the GLVND loaders.

Physical verification includes the connected Xbox controller through Shroot/X11
on RM11: buttons, sticks, triggers, D-pad and controller vibration. Multi-controller
hardware and additional firmware coverage remain distinct from simulated buses.
The same fixture creates and presents a Wayland window and discovers the
controller in Debian with the distribution's software Mesa stack. Its Android
host creation, protocol close and repeated launch in one retained session are
checked through normal SDL destruction with a successful process exit. Native
Wayland fixtures separately verify stable primary-monitor identity across host
attachment, hiding, release and workspace ownership.
