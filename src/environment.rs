/// Anti-debugging and environment integrity checks for Android.
///
/// Three public entry points are provided:
///
/// - [`is_debugger_attached`] — six checks for live ptrace tracers and injected
///   instrumentation frameworks (Frida, Xposed, Substrate). Called at VM startup
///   and periodically during execution.
/// - [`is_rooted`] — five checks for a modified boot environment: verified boot
///   state, overlay mounts, `su` binaries, `ro.debuggable`/`ro.secure`, and
///   build signing tags.
/// - [`is_emulator`] — three checks for virtual Android environments (AVD,
///   Genymotion, QEMU). Emulators are not inherently rooted but are the primary
///   platform for firmware reverse engineering and dynamic analysis.
///
/// All `/proc` paths, detection strings, and library names are obfuscated with
/// `obfstr::obfstr!` — XOR-encrypted at compile time, decrypted onto the stack
/// at runtime. The strings never appear as readable literals in `.rodata`.
use obfstr::obfstr;

/// Returns `true` when any check detects a tracer, injected framework, or
/// tampered environment.
///
/// Checks are combined with short-circuit OR: the first positive result
/// returns immediately. The OR policy means a debugger is flagged if *any*
/// method detects it — an attacker must defeat all six simultaneously.
///
/// 1. `TracerPid` in `/proc/self/status` — kernel-maintained ptrace record
/// 2. Process state in `/proc/self/stat` — ptrace-stop flag
/// 3. Wait-channel in `/proc/self/wchan` — blocking syscall name
/// 4. Memory map in `/proc/self/maps` — injected framework library paths
/// 5. `LD_PRELOAD` environment variable — preloaded injection libraries
/// 6. `.so` load path — our library loaded from an unexpected location
pub fn is_debugger_attached() -> bool {
    // Fast checks that don't need /proc/self/maps short-circuit first.
    if check_tracer_pid() || check_process_state() || check_wchan() {
        return true;
    }
    // Read /proc/self/maps once and share between check_proc_maps and
    // check_so_path so the file is not opened twice.
    let maps = read_proc_maps();
    let maps = maps.as_deref().unwrap_or("");
    check_proc_maps(maps) || check_ld_preload() || check_so_path(maps)
}

/// Reads `TracerPid` from `/proc/self/status`.
///
/// The kernel writes the PID of any attached ptrace tracer into this field.
/// Under normal execution it is `0`. A non-zero value means gdb, strace, or
/// Frida's ptrace backend is currently attached. Forging a zero here requires
/// kernel-level code.
fn check_tracer_pid() -> bool {
    let path = obfstr!("/proc/self/status").to_owned();
    let Ok(status) = std::fs::read_to_string(&path) else {
        return false;
    };
    let prefix = obfstr!("TracerPid:").to_owned();
    status
        .lines()
        .find(|line| line.starts_with(&*prefix))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|pid| pid != 0)
}

/// Reads the process state character from `/proc/self/stat`.
///
/// The kernel sets it to `'t'` (tracing stop) or `'T'` (signal stop) when
/// the process is being controlled by ptrace. Under normal execution it is
/// `'R'` (running) or `'S'` (sleeping). Parsing skips the process-name field
/// (which can contain spaces and parentheses) by searching from the last `)`.
fn check_process_state() -> bool {
    let path = obfstr!("/proc/self/stat").to_owned();
    let Ok(stat) = std::fs::read_to_string(&path) else {
        return false;
    };
    let after_comm = match stat.rfind(')') {
        Some(pos) => pos + 1,
        None => return false,
    };
    matches!(
        stat[after_comm..].trim_start().chars().next(),
        Some('t') | Some('T')
    )
}

/// Reads `/proc/self/wchan` — the kernel wait-channel.
///
/// A process stopped by ptrace is blocked inside `ptrace_stop` or
/// `trace_stop`. Forging the wait-channel requires hooking the kernel
/// scheduler, which is non-trivial even with root access.
fn check_wchan() -> bool {
    let path = obfstr!("/proc/self/wchan").to_owned();
    let Ok(wchan) = std::fs::read_to_string(&path) else {
        return false;
    };
    let wchan = wchan.trim();
    let ptrace = obfstr!("ptrace_stop").to_owned();
    let trace  = obfstr!("trace_stop").to_owned();
    wchan.contains(&*ptrace) || wchan.contains(&*trace)
}

/// Reads `/proc/self/maps` into a `String`. Returns `None` on I/O error.
fn read_proc_maps() -> Option<String> {
    let path = obfstr!("/proc/self/maps").to_owned();
    std::fs::read_to_string(&path).ok()
}

/// Checks `maps` content for memory regions belonging to known injection
/// and instrumentation frameworks.
///
/// `maps` is the caller-supplied content of `/proc/self/maps`, read once
/// and shared with [`check_so_path`] to avoid a second file open. Patterns
/// covered (all strings obfuscated at compile time):
///
/// - `frida` / `gadget`: Frida agent and Frida Gadget
/// - `xposed` / `edxposed` / `lsposed`: Xposed framework variants
/// - `substrate` / `cydia`: Cydia Substrate tweak injector
/// - `magisk`: Magisk root framework (often used to inject)
/// - `/data/local/tmp/`: common staging path for injected libraries
fn check_proc_maps(maps: &str) -> bool {
    // All search patterns are already lowercase, so we avoid allocating a
    // full lowercase copy of /proc/self/maps (which can be several MB).
    // Case-sensitive matching is intentional: injection tools (Frida, Magisk,
    // Substrate) use lowercase filenames on Android, so a case-sensitive
    // scan catches real injections without the allocation overhead.
    let frida     = obfstr!("frida").to_owned();
    let gadget    = obfstr!("gadget").to_owned();
    let xposed    = obfstr!("xposed").to_owned();
    let substrate = obfstr!("substrate").to_owned();
    let cydia     = obfstr!("cydia").to_owned();
    let magisk    = obfstr!("magisk").to_owned();
    let tmp_path  = obfstr!("/data/local/tmp/").to_owned();

    maps.contains(&*frida)
        || maps.contains(&*gadget)
        || maps.contains(&*xposed)
        || maps.contains(&*substrate)
        || maps.contains(&*cydia)
        || maps.contains(&*magisk)
        || maps.contains(&*tmp_path)
}

/// Checks whether `LD_PRELOAD` is set to a non-empty value.
///
/// `LD_PRELOAD` is the standard Linux mechanism for injecting a shared library
/// into a process before any other library loads. Any non-empty value is
/// suspicious in a production Android app context. The environment variable
/// name is obfuscated so a tool cannot locate and clear it by scanning the
/// binary for the string literal `LD_PRELOAD`.
fn check_ld_preload() -> bool {
    let key = obfstr!("LD_PRELOAD").to_owned();
    std::env::var(&key)
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Verifies that our `.so` is loaded from the expected Android app directory.
///
/// On a production Android device, the system installs APKs and their native
/// libraries under `/data/app/`. A Frida gadget or patching tool might load a
/// modified copy of our library from `/data/local/tmp/` or another path it
/// controls. If we find our own library name in `maps` but it is NOT under
/// `/data/app/`, we treat that as evidence of tampering.
///
/// `maps` is the caller-supplied content of `/proc/self/maps`, shared with
/// [`check_proc_maps`] to avoid a second file open. Both the library name and
/// the expected path prefix are obfuscated at compile time.
fn check_so_path(maps: &str) -> bool {
    let lib_name  = obfstr!("libsecure_android_vm.so").to_owned();
    let valid_dir = obfstr!("/data/app/").to_owned();
    for line in maps.lines() {
        if line.contains(&*lib_name) && !line.contains(&*valid_dir) {
            return true;
        }
    }
    false
}

// ── Root / boot-integrity detection ──────────────────────────────────────────

/// Returns `true` when the device shows indicators of a modified or rooted
/// boot environment.
///
/// Five independent checks are combined:
///
/// 1. **Verified boot state** (`/proc/cmdline`): the bootloader writes
///    `androidboot.verifiedbootstate=green|orange|red` before Android starts.
///    Any value other than `green` means the bootloader is unlocked or boot
///    verification failed. Kernel-written — cannot be altered by userspace.
///
/// 2. **System partition mount integrity** (`/proc/self/mountinfo`): scans for
///    `overlay` on `/system`, `/vendor`, or `/product` and `tmpfs` directly on
///    `/system`. Characteristic of Magisk Magic Mount, absent on stock Android.
///
/// 3. **`su` binary presence**: checks 12 paths where superuser binaries are
///    commonly installed. Catches non-Magisk roots and devices with unstripped
///    `su` binaries. Defeated by Magisk Hide on a fully configured root setup.
///
/// 4. **Dangerous system properties** (`ro.debuggable`, `ro.secure`): read via
///    `__system_property_get` directly from the bionic property map, bypassing
///    the Java `getprop` hook point. `ro.debuggable=1` = eng/userdebug build
///    with root shell; `ro.secure=0` = ADB runs as root.
///
/// 5. **Build signing tag** (`ro.build.tags`): `test-keys` means the OS kernel
///    was signed with a custom key — a prerequisite for most low-level root
///    methods on unmodified hardware.
///
/// When the checked files and properties are unavailable (host-machine CI,
/// non-Android test runs), all five sub-checks return `false`.
pub fn is_rooted() -> bool {
    check_verified_boot()
        || check_system_mounts()
        || check_su_paths()
        || check_dangerous_props()
        || check_build_tags()
}

/// Reads `androidboot.verifiedbootstate` from the kernel command line.
///
/// The bootloader writes this into `/proc/cmdline` before handing off to
/// Android. `green` = locked bootloader, OS verified. `orange` = unlocked
/// bootloader (a prerequisite for most root methods). `red` = boot verification
/// failed. If the parameter is absent (non-Android host or emulator without
/// verified boot support) the function returns `false` to avoid false positives.
fn check_verified_boot() -> bool {
    let path = obfstr!("/proc/cmdline").to_owned();
    let Ok(cmdline) = std::fs::read_to_string(&path) else {
        return false;
    };
    let key = obfstr!("androidboot.verifiedbootstate=").to_owned();
    let Some(start) = cmdline.find(&*key) else {
        return false;
    };
    let value_start = start + key.len();
    let value = cmdline[value_start..]
        .split([' ', '\0'])
        .next()
        .unwrap_or("");
    let green = obfstr!("green").to_owned();
    !value.is_empty() && value != &*green
}

/// Scans `/proc/self/mountinfo` for mount patterns associated with Magisk.
///
/// Mountinfo format: `<id> <parent> <major:minor> <root> <mountpoint> <opts>
/// [<optional-fields>]* - <fstype> <source> <super-opts>`. The filesystem type
/// sits after the first ` - ` separator, which is unambiguous in this format.
///
/// Flags:
/// - `overlay` fstype on `/system`, `/vendor`, or `/product` — Magisk Magic
///   Mount bind-overlays these to hide injected files.
/// - `tmpfs` fstype on `/system` — an older Magisk technique.
/// - Any line whose lowercase text contains `magisk` in a path component.
///
/// Returns `false` if the file is unreadable, avoiding false positives in
/// non-Android environments.
fn check_system_mounts() -> bool {
    let path = obfstr!("/proc/self/mountinfo").to_owned();
    let Ok(info) = std::fs::read_to_string(&path) else {
        return false;
    };

    let overlay = obfstr!("overlay").to_owned();
    let tmpfs   = obfstr!("tmpfs").to_owned();
    let system  = obfstr!("/system").to_owned();
    let vendor  = obfstr!("/vendor").to_owned();
    let product = obfstr!("/product").to_owned();
    let magisk  = obfstr!("magisk").to_owned();

    for line in info.lines() {
        // Magisk path in any field (mount source, root, or optional tags).
        if line.to_lowercase().contains(&*magisk) {
            return true;
        }

        // Mount point is the 5th whitespace-separated field (index 4).
        let mut fields = line.split_whitespace();
        let mount_point = match fields.nth(4) {
            Some(mp) => mp,
            None => continue,
        };

        // Filesystem type follows the first " - " separator.
        let Some(sep) = line.find(" - ") else { continue };
        let fs_type = line[sep + 3..].split_whitespace().next().unwrap_or("");

        if fs_type == &*overlay
            && (mount_point.starts_with(&*system)
                || mount_point.starts_with(&*vendor)
                || mount_point.starts_with(&*product))
        {
            return true;
        }

        if fs_type == &*tmpfs && mount_point == &*system {
            return true;
        }
    }
    false
}

/// Checks 12 paths where `su` binaries are commonly installed.
///
/// All path strings are obfuscated. Returns `false` if none of the paths
/// exist, which is always the case on stock Android and on non-Android hosts
/// (where the paths do not exist).
///
/// Note: Magisk Hide bind-mounts these paths away on a fully configured root
/// setup. This check is most effective against non-Magisk root methods or
/// devices where Magisk's deny list has not been applied to this process.
fn check_su_paths() -> bool {
    [
        obfstr!("/system/bin/su").to_owned(),
        obfstr!("/system/xbin/su").to_owned(),
        obfstr!("/system/sbin/su").to_owned(),
        obfstr!("/sbin/su").to_owned(),
        obfstr!("/su/bin/su").to_owned(),
        obfstr!("/data/local/su").to_owned(),
        obfstr!("/data/local/bin/su").to_owned(),
        obfstr!("/data/local/xbin/su").to_owned(),
        obfstr!("/system/bin/.ext/su").to_owned(),
        obfstr!("/system/bin/failsafe/su").to_owned(),
        obfstr!("/system/sd/xbin/su").to_owned(),
        obfstr!("/system/usr/we-need-root/su").to_owned(),
    ]
    .iter()
    .any(|p| std::path::Path::new(p.as_str()).exists())
}

/// Reads an Android system property via `__system_property_get` from bionic
/// libc. On non-Android targets, always returns `None` so that all callers
/// gracefully return `false` during host-machine tests.
///
/// `__system_property_get` reads directly from the shared-memory property
/// area that bionic maps into every process at startup. This bypasses the
/// Java `getprop` command and the Binder-based `PropertyServiceManager` hook
/// points that root-cloaking tools typically intercept.
fn get_system_property(name: &str) -> Option<String> {
    system_property_impl(name)
}

#[cfg(target_os = "android")]
fn system_property_impl(name: &str) -> Option<String> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // PROP_VALUE_MAX from <sys/system_properties.h> is 92 bytes including NUL.
    const PROP_VALUE_MAX: usize = 92;
    let mut buf = [0 as libc::c_char; PROP_VALUE_MAX];
    // SAFETY: c_name is null-terminated; buf is exactly PROP_VALUE_MAX bytes.
    #[allow(deprecated)]
    let len = unsafe { libc::__system_property_get(c_name.as_ptr(), buf.as_mut_ptr()) };
    if len <= 0 {
        return None;
    }
    let bytes: Vec<u8> = buf[..len as usize].iter().map(|&c| c as u8).collect();
    String::from_utf8(bytes).ok()
}

#[cfg(not(target_os = "android"))]
fn system_property_impl(_name: &str) -> Option<String> {
    None
}

/// Reads `ro.debuggable` and `ro.secure` via the native property API.
///
/// `ro.debuggable=1` means the build is `eng` or `userdebug` — a root shell
/// is available via ADB and many security restrictions are relaxed.
/// `ro.secure=0` means ADB runs as root even on user builds.
///
/// Both properties are read with `get_system_property`, which bypasses the
/// `getprop` command and Binder-layer hook points.
fn check_dangerous_props() -> bool {
    let debuggable = obfstr!("ro.debuggable").to_owned();
    let secure     = obfstr!("ro.secure").to_owned();
    let one        = obfstr!("1").to_owned();
    let zero       = obfstr!("0").to_owned();

    get_system_property(&debuggable).as_deref() == Some(&*one)
        || get_system_property(&secure).as_deref() == Some(&*zero)
}

/// Reads `ro.build.tags` and flags if it contains `"test-keys"`.
///
/// A production Android build is signed with Google's release keys and has
/// `ro.build.tags = release-keys`. A build signed with a custom key reports
/// `test-keys` — this is a prerequisite for most low-level root methods that
/// require a custom kernel or modified system image.
fn check_build_tags() -> bool {
    let key       = obfstr!("ro.build.tags").to_owned();
    let test_keys = obfstr!("test-keys").to_owned();
    get_system_property(&key)
        .is_some_and(|v| v.contains(&*test_keys))
}

// ── Emulator detection ────────────────────────────────────────────────────────

/// Returns `true` when the process appears to be running inside an Android
/// emulator or virtual device.
///
/// Emulators are the primary platform for firmware reverse engineering: they
/// allow memory inspection, snapshot/restore, and dynamic tracing without the
/// noise of real hardware. Six independent checks cover the four most common
/// emulator families:
///
/// 1. **QEMU kernel property** (`ro.kernel.qemu = "1"`): set by the QEMU
///    hypervisor before userspace starts. Catches AVD (Android Studio). Cannot
///    be spoofed without modifying the kernel image.
///
/// 2. **Virtual hardware name** (`ro.hardware`): `goldfish`/`ranchu` = AVD;
///    `vbox86` = Genymotion. No production device uses these identifiers.
///
/// 3. **QEMU device nodes** (`/dev/goldfish_pipe`, `/dev/qemu_pipe`,
///    `/dev/socket/qemud`): character devices created by the goldfish/ranchu
///    guest kernel driver. Present only inside a QEMU-based virtual device.
///
/// 4. **BlueStacks device nodes** (`/dev/bst_gps`, `/dev/bst_time`,
///    `/dev/bst_audio`): virtual devices created by the BST hypervisor driver.
///    Also checks `ro.bluestacks.bp`, a BlueStacks-only system property.
///    BlueStacks uses its own hypervisor — it sets none of the QEMU signals.
///
/// 5. **Nox Player** (`ro.nox.version`): a system property present only in
///    Nox. Nox shares a QEMU base but strips the standard QEMU markers.
///
/// 6. **MEmu** (`ro.microvirt.hardware`, `ro.product.manufacturer = Microvirt`):
///    MEmu uses its own hypervisor (Microvirt) and sets neither QEMU nor BST
///    signals.
///
/// 7. **LDPlayer** (`ro.ldplayer.version`): QEMU-based but strips the standard
///    QEMU markers in most versions. Its own version property is absent on all
///    production devices.
///
/// Returns `false` on non-Android hosts so that CI and unit tests are
/// unaffected.
pub fn is_emulator() -> bool {
    check_qemu_prop()
        || check_emulator_hardware()
        || check_qemu_devices()
        || check_bluestacks()
        || check_nox()
        || check_memu()
        || check_ldplayer()
}

/// Checks `ro.kernel.qemu` — set to `"1"` by the QEMU kernel itself.
fn check_qemu_prop() -> bool {
    let key = obfstr!("ro.kernel.qemu").to_owned();
    let one = obfstr!("1").to_owned();
    get_system_property(&key).as_deref() == Some(&*one)
}

/// Checks `ro.hardware` against known virtual hardware identifiers.
///
/// - `goldfish` / `ranchu` — Android Virtual Device (QEMU-based, AVD)
/// - `vbox86`              — Genymotion (VirtualBox-based)
fn check_emulator_hardware() -> bool {
    let key     = obfstr!("ro.hardware").to_owned();
    let goldfish = obfstr!("goldfish").to_owned();
    let ranchu   = obfstr!("ranchu").to_owned();
    let vbox     = obfstr!("vbox86").to_owned();
    match get_system_property(&key).as_deref() {
        Some(v) => v == &*goldfish || v == &*ranchu || v == &*vbox,
        None => false,
    }
}

/// Checks for QEMU guest kernel device nodes.
///
/// These character devices are created by the goldfish/ranchu kernel driver
/// and are only present when the running kernel was built for QEMU. No stock
/// Android ROM ships these nodes.
fn check_qemu_devices() -> bool {
    [
        obfstr!("/dev/goldfish_pipe").to_owned(),
        obfstr!("/dev/qemu_pipe").to_owned(),
        obfstr!("/dev/socket/qemud").to_owned(),
    ]
    .iter()
    .any(|p| std::path::Path::new(p.as_str()).exists())
}

/// Detects BlueStacks, which uses its own hypervisor and sets none of the
/// QEMU/VirtualBox signals.
///
/// Two signal types are checked:
/// - **Device nodes** (`/dev/bst_gps`, `/dev/bst_time`, `/dev/bst_audio`):
///   virtual character devices created by the BST kernel driver. Present in
///   all BlueStacks versions (4 and 5) on both Windows and macOS hosts.
/// - **`ro.bluestacks.bp`**: a system property set only by BlueStacks. Any
///   non-empty value is conclusive.
fn check_bluestacks() -> bool {
    let bst_found = [
        obfstr!("/dev/bst_gps").to_owned(),
        obfstr!("/dev/bst_time").to_owned(),
        obfstr!("/dev/bst_audio").to_owned(),
    ]
    .iter()
    .any(|p| std::path::Path::new(p.as_str()).exists());

    if bst_found {
        return true;
    }

    let bp_key = obfstr!("ro.bluestacks.bp").to_owned();
    get_system_property(&bp_key).is_some()
}

/// Detects Nox Player via `ro.nox.version`.
///
/// Nox shares a QEMU base with AVD but strips the standard `ro.kernel.qemu`
/// and goldfish hardware markers. It does however set its own version property,
/// which is absent on all production devices.
fn check_nox() -> bool {
    let key = obfstr!("ro.nox.version").to_owned();
    get_system_property(&key).is_some()
}

/// Detects MEmu (Microvirt) via hardware and manufacturer properties.
///
/// MEmu uses a proprietary hypervisor branded "Microvirt". It sets
/// `ro.microvirt.hardware` to identify its virtual hardware layer and
/// `ro.product.manufacturer` to `"Microvirt"`. Neither appears on production
/// devices.
fn check_memu() -> bool {
    let hw_key       = obfstr!("ro.microvirt.hardware").to_owned();
    let mfr_key      = obfstr!("ro.product.manufacturer").to_owned();
    let microvirt    = obfstr!("microvirt").to_owned();

    get_system_property(&hw_key).is_some()
        || get_system_property(&mfr_key)
            .is_some_and(|v| v.to_lowercase().contains(&*microvirt))
}

/// Detects LDPlayer via `ro.ldplayer.version`.
///
/// LDPlayer is QEMU-based but strips `ro.kernel.qemu` and the goldfish/ranchu
/// hardware identifiers in most versions, so it evades the generic QEMU checks.
/// It does set its own version property, which is absent on all production
/// devices and on every other emulator family.
fn check_ldplayer() -> bool {
    let key = obfstr!("ro.ldplayer.version").to_owned();
    get_system_property(&key).is_some()
}
