# PLANK host configuration

The host reads `/etc/plank/host.conf`. It uses INI-style
section headings and globally scoped `key = value` entries. Section names are
organizational only. Blank lines and text following `#` are ignored.

This document is the complete accepted runtime key set. A setting absent from
this document is intentionally rejected, including inherited Sunshine options
for unsupported platforms, encoders, display control, update notifications,
consumer NAT discovery, and product behaviors fixed by PLANK.

## General

### host_name

Host name returned during PLANK negotiation and used for mDNS service
advertisement. Default: the operating-system hostname.

### min_log_level

Minimum logged severity. Accepted values: `verbose`, `debug`, `info`,
`warning`, `error`, `fatal`, `none`, or the corresponding integer `0` through
`6`. Default: `info`.

## Network

### port

Base port used by PLANK HTTPS authentication and native QUIC. Default:
`28989`. Changing it requires matching firewall policy and client reachability.

### mdns_discovery

Publish the host through mDNS/Avahi for automatic client discovery. Accepted
values: `true` or `false`. Default: `false`. This controls advertisement only;
manually configured hostname/IP bookmarks continue to work while disabled.

### ping_timeout

Milliseconds allowed for initial media-channel pings and established-client
inactivity before the host cleans up the stream. Default: `10000`.

## NDI screen output (Windows)

Optional. Publishes the host's screens as NDI sources on the LAN so they can be
picked up in Evercast's desktop app (Stream, then Stream NDI) or any other NDI
receiver. Sources are published whether or not a PLANK client is connected, and
alongside an active PLANK stream.

How it works: with `ndi_output = on` the host starts a small helper program,
`tools\plank-ndi.exe`, and restarts it if it dies. The helper does its own
screen capture in a separate process (so it never interferes with PLANK's
capture) and loads the free NDI runtime itself. The NDI runtime is not part of
PLANK; install NDI Tools from <https://ndi.video>. If it is missing the helper
logs "NDI output is on but the NDI runtime is not installed; install NDI Tools"
and the host carries on normally. There is no audio in this version. Restart
the PLANK service after changing these options.

**NDI has no authentication.** Anyone on the same network who runs an NDI
receiver can see the published screens. Only turn this on for networks you
trust, and use `ndi_groups` to narrow who sees the source. While the Windows
secure desktop is up (lock screen, UAC prompt, sign-in) the helper sends a
black picture instead of the screen.

NDI(R) is a registered trademark of Vizrt NDI AB. See <https://ndi.video>.

### ndi_output

Publish NDI sources. Accepted values: `on` or `off`. Default: `off`.

### ndi_outputs

Which displays to publish: `primary` or `all`. Default: `primary`.

### ndi_source_name

Name of the NDI source. Default: `<COMPUTERNAME> - Screen N`. A custom name is
used as is for one display; with `ndi_outputs = all` and several displays a
number is appended. NDI receivers also show the machine name in front.

### ndi_groups

Comma separated NDI groups the sources are published into. Default: empty (the
default NDI group, visible to all receivers). Receivers must be set to the same
group to see the source. This narrows visibility; it is not access control.

### ndi_fps

Frames per second sent to NDI, 1 to 60. Default: `30`. Higher values cost more
CPU and network bandwidth.

## Security and state

### allow_root_login

Allow PAM authentication as root. Default: `false`. Enabling this does not
bypass PAM/SSSD/HBAC policy or active-desktop ownership checks.

### second_factor_resume_minutes

Minutes a reconnect ticket stays valid after the last streaming activity. A
client that closes and reconnects within this window does not require
second-factor authentication again. Valid range: `0` through `1440`. Default:
`10`. Set to `0` to disable ticket-based reconnection and always require
second-factor authentication.

### second_factor_resume_max_hours

Hours after the original sign-in at which reconnect tickets stop working and
the second-factor authentication is always required, regardless of recent
activity. Valid range: `1` through `720`. Default: `12`. This setting limits
how long a single sign-in session remains valid.

### second_factor_round_wait_ms

Longest milliseconds one authentication round waits for a second-factor push
decision from a provider. Allows clients to time out and retry if a push is slow.
Valid range: `500` through `4500`. Default: `3800`. For a 16-round client
authentication, this timing covers a Duo Security 60-second push timeout.

### admin_desktop_override

Allow members of the host administrator group to stream the active desktop even
when another account owns it. Set to `true` to let admins take control of any
running desktop; `false` restricts streaming to the desktop owner. Accepted
values: `true` or `false`. Default: `false`.

### shared_screen

Allow multiple client connections to view a single running stream simultaneously
(view-only mode). When enabled, extra clients watch the primary client's view
without interfering. Accepted values: `true` or `false`. Default: `false`.

### shared_screen_max_viewers

Maximum number of view-only clients that can attach to a single active stream.
Valid range: `1` through `8`. Default: `4`. Only applies when `shared_screen` is
enabled.

### pkey

Path to the host TLS private key. The packaged profile uses
`/etc/plank/tls/key.pem`.

### cert

Path to the host TLS certificate. The packaged profile uses
`/etc/plank/tls/cert.pem`.

### file_state

Path to mutable workstation identity state. The packaged profile uses
`/var/lib/plank/plank-state.json`.

### log_path

Path to the persistent host log. The packaged profile uses
`/var/log/plank/host.log`.

## Audio

### audio_sink

Optional PipeWire/Pulse-compatible host sink name to capture. Empty selects the
operating system's current output sink.

## Input

### keybindings

Optional comma-separated client-keycode/host-keycode replacement pairs. The
default PLANK modifier mappings remain in effect when omitted.

### key_repeat_delay

Milliseconds before a held remote key begins repeating. Default: `500`.

### key_repeat_frequency

Remote key-repeat events per second. Default: approximately `24.9`.

Keyboard, mouse, high-resolution scrolling, and native scancodes are mandatory
PLANK behaviors and are not configurable.

## Display

### startup_layout

Display policy applied before the display manager starts. `physical` preserves
connected displays. `virtual` prepares one internal 1920x1080 login output;
the authenticated bookmark then supplies the active virtual layout. Default:
`physical`.

### adapter_name

Optional GPU/display adapter selector for multi-GPU hosts. Empty uses automatic
selection.

## Common video behavior

### one_screen

How a host with two or more monitors serves clients that cannot show our two-screen
mode (Alan's Mac and Linux clients, and Windows clients older than 1.0.103.41).
`auto` (recommended) gives those clients just the primary monitor, so the picture
and the mouse line up; current Windows clients still get both screens. `always`
gives every client just the primary monitor. `never` turns the automatic choice
off, so those clients get the old stretched two-monitor picture. In every mode the
file `C:\ProgramData\PLANK\one-screen`, if it exists, forces one screen for
everyone. Accepted values: `auto`, `always`, or `never`. Default: `auto`.

### minimum_fps_target

Minimum capture cadence used when the desktop is static. Valid range: `0`
through `1000`. `0` derives the target from half the requested stream rate.

### min_threads

Minimum software-encoder thread/slice count. The packaged PLANK
profile uses `16`.

## NVIDIA NVENC

These settings tune both the qualified direct NVENC path and the retained
NVIDIA compatibility encoder where applicable. They do not select a codec or
backend; the bookmark's encoding profile does that.

### nvenc_preset

NVENC quality preset number from `1` through `7`. Default: `1`.

### nvenc_twopass

NVENC multipass mode: `disabled`, `quarter_res`, or `full_res`. Default:
`quarter_res`.

### nvenc_spatial_aq

Enable spatial adaptive quantization. Accepted values: `true` or `false`.
Default: `false`.

### nvenc_vbv_increase

Percentage added to the NVENC VBV buffer size. Valid range: `0` through `400`.
Default: `0`.

### nvenc_split_encode

Split-frame encoding policy: `disabled`, `driver_decides`, or `enabled`.
Default: `driver_decides`.

### nvenc_h264_cavlc

Use CAVLC rather than CABAC for H.264 when supported. Accepted values: `true`
or `false`. Default: `false`.

## x264 software encoder

### sw_preset

x264 speed/quality preset. The packaged PLANK profile uses
`ultrafast`.

### sw_tune

x264 tuning policy. The packaged PLANK profile uses `zerolatency`.

### sw_vbv_maxrate_percentage

Peak x264 rate as a percentage of the bookmark/session encoder target. Valid
range: `100` through `400`; the packaged value is `150`.

### sw_vbv_buffer_frames

VBV reservoir expressed in average-rate frame units. Valid range: `0` through
`16`; the packaged value is `4`.

### sw_scenecut

x264 scene-change threshold. Valid range: `0` through `100`; `0` disables
adaptive scene-change keyframes. The packaged value is `40`.
