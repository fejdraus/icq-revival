//! The one wgpu device of the process.
//!
//! It is created on a dedicated thread that never exits, and it is never
//! dropped. Two reasons:
//!
//! - A device kept in a thread-local was destroyed by Rust's thread-local
//!   destructors when the thread exited. Those run from the DLL's TLS callback
//!   while ntdll holds the loader lock, and the Vulkan driver's
//!   vkDestroyInstance waits there for its own worker thread to exit, which
//!   needs the loader lock: a deadlock that froze ICQ as soon as an avatar
//!   snapshot job (a worker thread) finished.
//! - Opening a device takes 0.3-1.5 s. On its own thread it does not block
//!   the client's UI thread; loads wait for it on their background thread.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ruffle_render::backend::RenderBackend;
use ruffle_render_wgpu::backend::create_wgpu_instance;
use ruffle_render_wgpu::descriptors::Descriptors;
use ruffle_render_wgpu::target::TextureTarget;
use ruffle_render_wgpu::wgpu;

use crate::log;
use crate::movie::Renderer;

enum State {
    NotStarted,
    Starting,
    Ready(Arc<Descriptors>),
    Failed(String),
}

static STATE: Mutex<State> = Mutex::new(State::NotStarted);
static CHANGED: Condvar = Condvar::new();

/// wgpu errors reported by a device (validation, out of memory, internal).
/// wgpu's default handler panics; ours only counts and logs.
static GPU_ERRORS: AtomicU64 = AtomicU64::new(0);

fn lock() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether a renderer exists, for FPCIsFlashInstalled on the client's UI
/// thread: starts the probe and waits for it at most 250 ms.
///
/// Undecided after that counts as yes. Saying yes and failing later is
/// harmless: every load then ends without events (`FPC_IsPlaying` turns false,
/// a snapshot is blank), which is how a movie that cannot load behaves.
/// Saying no on a working machine is not harmless: the client would hide
/// tZers and Flash avatars. WARP (always present on Windows 10+) makes a
/// renderer available almost everywhere; only a failed probe answers no.
pub fn available() -> bool {
    start();
    let s = lock();
    let (s, _) = CHANGED
        .wait_timeout_while(s, Duration::from_millis(250), |s| {
            matches!(s, State::Starting)
        })
        .unwrap_or_else(|e| e.into_inner());
    let answer = !matches!(*s, State::Failed(_));
    static LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) || !answer {
        let state = match &*s {
            State::Ready(_) => "ready",
            State::Failed(_) => "failed",
            _ => "still probing",
        };
        log(&format!(
            "FPCIsFlashInstalled -> {answer} (renderer {state})"
        ));
    }
    answer
}

/// Starts opening the device in the background (once). Returns immediately.
pub fn start() {
    let mut s = lock();
    if !matches!(*s, State::NotStarted) {
        return;
    }
    *s = State::Starting;
    drop(s);
    let spawned = std::thread::Builder::new()
        .name("FlashPlayerControl gpu".into())
        .spawn(|| {
            crate::install_panic_hook();
            let result = std::panic::catch_unwind(open)
                .unwrap_or_else(|_| Err("panic while opening a graphics device".into()));
            {
                let mut s = lock();
                *s = match result {
                    Ok(d) => State::Ready(d),
                    Err(e) => {
                        log(&format!("no graphics device: {e}"));
                        State::Failed(e)
                    }
                };
            }
            CHANGED.notify_all();
            // Keep the thread (and the device) alive for the life of the process.
            loop {
                std::thread::park();
            }
        });
    if let Err(e) = spawned {
        *lock() = State::Failed(format!("cannot start gpu thread: {e}"));
        CHANGED.notify_all();
    }
}

/// Blocks until the device is open or failed. Call only from a background thread.
pub fn wait(timeout: Duration) -> Result<Arc<Descriptors>, String> {
    start();
    let s = lock();
    let (s, _) = CHANGED
        .wait_timeout_while(s, timeout, |s| matches!(s, State::Starting))
        .unwrap_or_else(|e| e.into_inner());
    state_result(&s)
}

/// The device if it is ready; never blocks.
pub fn get() -> Result<Arc<Descriptors>, String> {
    state_result(&lock())
}

fn state_result(s: &State) -> Result<Arc<Descriptors>, String> {
    match s {
        State::Ready(d) => Ok(d.clone()),
        State::Failed(e) => Err(e.clone()),
        State::NotStarted | State::Starting => Err("graphics device not ready yet".into()),
    }
}

/// One way to get a graphics device.
#[derive(Clone, Copy, Debug)]
pub enum Choice {
    Vulkan,
    Dx12,
    Gl,
    /// DX12 on WARP, Windows' software rasterizer (`force_fallback_adapter`).
    /// What a virtual machine without a GPU has.
    Warp,
    /// Test only: behave as if the adapter request failed.
    Fail,
}

/// The ways to try, in order. FLASHPLAYERCONTROL_BACKEND overrides the order
/// with a comma-separated list of `vulkan`, `dx12`, `gl`, `warp`, `fail`, or
/// `none` (no renderer at all).
pub fn choices() -> Vec<Choice> {
    // DX12 on a hardware GPU is left out: in this 32-bit build it failed at
    // run time on the test machine (buffer mapping). GL comes after WARP and
    // only with a hardware GPU: without one it would be Windows' GDI OpenGL
    // 1.1, which cannot run Ruffle and is the least tested driver path.
    let mut default = vec![Choice::Vulkan, Choice::Warp];
    if has_hardware_gpu() {
        default.push(Choice::Gl);
    }
    let Ok(list) = std::env::var("FLASHPLAYERCONTROL_BACKEND") else {
        return default;
    };
    if list.trim().eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    let picked: Vec<_> = list
        .split(',')
        .filter_map(|b| match b.trim().to_ascii_lowercase().as_str() {
            "vulkan" => Some(Choice::Vulkan),
            "dx12" => Some(Choice::Dx12),
            "gl" => Some(Choice::Gl),
            "warp" => Some(Choice::Warp),
            "fail" => Some(Choice::Fail),
            _ => None,
        })
        .collect();
    if picked.is_empty() { default } else { picked }
}

/// Whether DXGI lists a real (not software) graphics adapter.
fn has_hardware_gpu() -> bool {
    std::panic::catch_unwind(|| {
        let instance =
            create_wgpu_instance(wgpu::Backends::DX12, wgpu::BackendOptions::default(), None);
        let adapters =
            futures::executor::block_on(instance.enumerate_adapters(wgpu::Backends::DX12));
        let hw = adapters
            .iter()
            .any(|a| a.get_info().device_type != wgpu::DeviceType::Cpu);
        std::mem::forget(adapters);
        std::mem::forget(instance);
        hw
    })
    .unwrap_or(false)
}

fn open() -> Result<Arc<Descriptors>, String> {
    let mut errors = Vec::new();
    for choice in choices() {
        let attempt = std::panic::catch_unwind(|| open_choice(choice))
            .unwrap_or_else(|_| Err("panic while opening the device".into()));
        match attempt {
            Ok(d) => return Ok(d),
            Err(e) => {
                log(&format!("gpu {choice:?} unusable: {e}"));
                errors.push(format!("{choice:?}: {e}"));
            }
        }
    }
    if errors.is_empty() {
        errors.push("no graphics API allowed (FLASHPLAYERCONTROL_BACKEND=none)".into());
    }
    Err(errors.join("; "))
}

/// Ruffle's device request (`request_device` in ruffle_render_wgpu), without
/// the profiler's optional timer features.
async fn request_device(adapter: &wgpu::Adapter) -> Result<(wgpu::Device, wgpu::Queue), String> {
    let mut limits = wgpu::Limits::downlevel_webgl2_defaults();
    limits = limits.using_resolution(adapter.limits());
    limits = limits.using_alignment(adapter.limits());
    limits.max_uniform_buffer_binding_size = adapter.limits().max_uniform_buffer_binding_size;
    limits.max_inter_stage_shader_variables = adapter.limits().max_inter_stage_shader_variables;
    limits.max_color_attachments = 4;
    let optional = wgpu::Features::TEXTURE_ADAPTER_SPECIFIC_FORMAT_FEATURES
        | wgpu::Features::TEXTURE_COMPRESSION_BC
        | wgpu::Features::FLOAT32_FILTERABLE;
    adapter
        .request_device(&wgpu::DeviceDescriptor {
            label: None,
            required_features: optional & adapter.features(),
            required_limits: limits,
            memory_hints: Default::default(),
            trace: wgpu::Trace::Off,
            experimental_features: wgpu::ExperimentalFeatures::disabled(),
        })
        .await
        .map_err(|e| e.to_string())
}

/// Opens a device and checks that Ruffle's pipelines build on it. A device
/// that fails the check is leaked rather than dropped: dropping a
/// half-working driver instance is exactly what can hang.
fn open_choice(choice: Choice) -> Result<Arc<Descriptors>, String> {
    let (backend, fallback) = match choice {
        Choice::Vulkan => (wgpu::Backends::VULKAN, false),
        Choice::Dx12 => (wgpu::Backends::DX12, false),
        Choice::Gl => (wgpu::Backends::GL, false),
        Choice::Warp => (wgpu::Backends::DX12, true),
        Choice::Fail => return Err("simulated adapter request failure".into()),
    };
    let started = std::time::Instant::now();
    let instance = create_wgpu_instance(backend, wgpu::BackendOptions::from_env_or_default(), None);
    let adapter =
        futures::executor::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::LowPower,
            compatible_surface: None,
            force_fallback_adapter: fallback,
            apply_limit_buckets: false,
        }))
        .map_err(|e| format!("no adapter: {e}"))?;
    let (device, queue) = futures::executor::block_on(request_device(&adapter))?;
    device.on_uncaptured_error(Arc::new(|e: wgpu::Error| {
        let n = GPU_ERRORS.fetch_add(1, Ordering::Relaxed);
        if n < 20 {
            log(&format!("gpu error: {e}"));
        }
    }));
    let info = adapter.get_info();
    let name = format!("{:?} {} ({:?})", info.backend, info.name, info.device_type);
    let d = Arc::new(Descriptors::new(instance, adapter, device, queue));
    // Building a renderer compiles the shaders; some drivers fail here. Warm up
    // the high-quality (multisampled) pipelines too, so the first movie does
    // not compile them on the client's thread.
    // Then render a frame and read it back: some devices build pipelines but
    // fail at run time (32-bit DX12 on the test machine failed to map the
    // readback buffer).
    let probe = d.clone();
    let errors_before = GPU_ERRORS.load(Ordering::Relaxed);
    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let target = TextureTarget::new(&probe.device, (256, 256)).map_err(|e| e.to_string())?;
        let mut r = Renderer::new(probe, target).map_err(|e| e.to_string())?;
        r.set_quality(ruffle_render::quality::StageQuality::High);
        // Two frames, like a movie's first frames, each read back.
        for rgba in [0xFFFF0000u32, 0xFF00FF00] {
            let color = ruffle_core::Color::from_rgba(rgba);
            r.submit_frame(
                color,
                ruffle_render::commands::CommandList::new(),
                Vec::new(),
            );
            let px = crate::movie::read_back(&r).ok_or("no readback buffer")?;
            let want = [color.b, color.g, color.r, color.a];
            let last = px.pixels.len().saturating_sub(4);
            if px.pixels.get(..4) != Some(&want[..]) || px.pixels.get(last..) != Some(&want[..]) {
                return Err(format!(
                    "test frame read back wrong: {:?}",
                    px.pixels.get(..4)
                ));
            }
        }
        if GPU_ERRORS.load(Ordering::Relaxed) != errors_before {
            return Err("device reported errors during the test frame".into());
        }
        Ok::<_, String>(())
    }));
    match ok {
        Ok(Ok(())) => {
            log(&format!(
                "gpu: {name}, ready in {} ms",
                started.elapsed().as_millis()
            ));
            Ok(d)
        }
        Ok(Err(e)) => {
            std::mem::forget(d);
            Err(format!("{name}: {e}"))
        }
        Err(_) => {
            std::mem::forget(d);
            Err(format!("{name}: shader/pipeline creation failed"))
        }
    }
}
