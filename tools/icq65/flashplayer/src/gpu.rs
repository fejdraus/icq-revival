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

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ruffle_render::backend::RenderBackend;
use ruffle_render_wgpu::backend::{create_wgpu_instance, request_adapter_and_device};
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

/// Starts opening the device in the background (once). Returns immediately.
pub fn start() {
    let mut s = STATE.lock().unwrap();
    if !matches!(*s, State::NotStarted) {
        return;
    }
    *s = State::Starting;
    drop(s);
    let spawned = std::thread::Builder::new()
        .name("FlashPlayerControl gpu".into())
        .spawn(|| {
            let result = open();
            {
                let mut s = STATE.lock().unwrap();
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
        *STATE.lock().unwrap() = State::Failed(format!("cannot start gpu thread: {e}"));
        CHANGED.notify_all();
    }
}

/// Blocks until the device is open or failed. Call only from a background thread.
pub fn wait(timeout: Duration) -> Result<Arc<Descriptors>, String> {
    start();
    let s = STATE.lock().unwrap();
    let (s, _) = CHANGED
        .wait_timeout_while(s, timeout, |s| matches!(s, State::Starting))
        .unwrap();
    state_result(&s)
}

/// The device if it is ready; never blocks.
pub fn get() -> Result<Arc<Descriptors>, String> {
    state_result(&STATE.lock().unwrap())
}

fn state_result(s: &State) -> Result<Arc<Descriptors>, String> {
    match s {
        State::Ready(d) => Ok(d.clone()),
        State::Failed(e) => Err(e.clone()),
        State::NotStarted | State::Starting => Err("graphics device not ready yet".into()),
    }
}

/// Graphics APIs to try, in order. FLASHPLAYERCONTROL_BACKEND (e.g. "vulkan"
/// or "gl,dx12") overrides the order.
fn backends() -> Vec<wgpu::Backends> {
    let default = vec![
        wgpu::Backends::VULKAN,
        wgpu::Backends::DX12,
        wgpu::Backends::GL,
    ];
    let Ok(list) = std::env::var("FLASHPLAYERCONTROL_BACKEND") else {
        return default;
    };
    let picked: Vec<_> = list
        .split(',')
        .filter_map(|b| match b.trim().to_ascii_lowercase().as_str() {
            "vulkan" => Some(wgpu::Backends::VULKAN),
            "dx12" => Some(wgpu::Backends::DX12),
            "gl" => Some(wgpu::Backends::GL),
            _ => None,
        })
        .collect();
    if picked.is_empty() { default } else { picked }
}

fn open() -> Result<Arc<Descriptors>, String> {
    let mut errors = Vec::new();
    for backend in backends() {
        match open_backend(backend) {
            Ok(d) => return Ok(d),
            Err(e) => {
                log(&format!("gpu {backend:?} unusable: {e}"));
                errors.push(format!("{backend:?}: {e}"));
            }
        }
    }
    Err(errors.join("; "))
}

/// Opens a device on `backend` and checks that Ruffle's pipelines build on it.
/// A device that fails the check is leaked rather than dropped: dropping a
/// half-working driver instance is exactly what can hang.
fn open_backend(backend: wgpu::Backends) -> Result<Arc<Descriptors>, String> {
    let started = std::time::Instant::now();
    let instance = create_wgpu_instance(backend, wgpu::BackendOptions::from_env_or_default(), None);
    let (adapter, device, queue) = futures::executor::block_on(request_adapter_and_device(
        backend,
        &instance,
        None,
        wgpu::PowerPreference::LowPower,
    ))
    .map_err(|e| e.to_string())?;
    let info = adapter.get_info();
    let name = format!("{:?} {} ({:?})", info.backend, info.name, info.device_type);
    let d = Arc::new(Descriptors::new(instance, adapter, device, queue));
    // Building a renderer compiles the shaders; some drivers fail here. Warm up
    // the high-quality (multisampled) pipelines too, so the first movie does
    // not compile them on the client's thread.
    let probe = d.clone();
    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let target = TextureTarget::new(&probe.device, (4, 4)).map_err(|e| e.to_string())?;
        let mut r = Renderer::new(probe, target).map_err(|e| e.to_string())?;
        r.set_quality(ruffle_render::quality::StageQuality::High);
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
