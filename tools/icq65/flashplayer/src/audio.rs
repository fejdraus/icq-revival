//! Sound output through cpal (WASAPI).
//!
//! One output stream for the whole process, owned by a dedicated thread that
//! never exits. Each player gets its own Ruffle `AudioMixer`; the stream's
//! callback sums the mixers of all playing players. Nothing audio-related runs
//! on the client's threads, so no COM initialisation and no thread-local
//! cleanup happens there (cpal uninitialises COM from a thread-local
//! destructor, which runs under the loader lock when a thread exits).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use ruffle_core::backend::audio::{
    AudioBackend, AudioMixer, AudioMixerProxy, DecodeError, NullAudioBackend, RegisterError,
    SoundHandle, SoundInstanceHandle, SoundStreamInfo, SoundTransform, swf,
};
use ruffle_core::impl_audio_mixer_backend;

use crate::log;

/// Audio streams opened so far.
pub static STREAMS_STARTED: AtomicU64 = AtomicU64::new(0);
/// Samples the device asked for.
pub static SAMPLES_MIXED: AtomicU64 = AtomicU64::new(0);
/// Of those, samples that were not silence.
pub static SAMPLES_AUDIBLE: AtomicU64 = AtomicU64::new(0);

struct Voice {
    id: u64,
    mixer: AudioMixerProxy,
    active: Arc<AtomicBool>,
}

struct Output {
    channels: u16,
    sample_rate: u32,
    voices: Arc<Mutex<Vec<Voice>>>,
    commands: Mutex<Sender<bool>>, // true = play, false = pause
}

enum State {
    NotStarted,
    Starting,
    Ready(Arc<Output>),
    Failed,
}

static STATE: Mutex<State> = Mutex::new(State::NotStarted);
static CHANGED: Condvar = Condvar::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Starts the audio thread (once). Returns immediately.
pub fn start() {
    let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if !matches!(*s, State::NotStarted) {
        return;
    }
    *s = State::Starting;
    drop(s);
    let spawned = std::thread::Builder::new()
        .name("FlashPlayerControl audio".into())
        .spawn(|| {
            crate::install_panic_hook();
            if std::panic::catch_unwind(audio_thread).is_err() {
                log("no sound: the audio thread failed");
                let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
                if matches!(*s, State::Starting) {
                    *s = State::Failed;
                }
                drop(s);
                CHANGED.notify_all();
                // Stay alive: a thread exit runs TLS destructors under the loader lock.
                loop {
                    std::thread::park();
                }
            }
        });
    if let Err(e) = spawned {
        log(&format!("no sound: cannot start audio thread: {e}"));
        *STATE.lock().unwrap_or_else(|e| e.into_inner()) = State::Failed;
        CHANGED.notify_all();
    }
}

/// Waits (up to `timeout`) until the audio thread has opened the device.
pub fn wait(timeout: Duration) {
    start();
    let s = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let _ = CHANGED
        .wait_timeout_while(s, timeout, |s| matches!(s, State::Starting))
        .unwrap_or_else(|e| e.into_inner());
}

fn output() -> Option<Arc<Output>> {
    match &*STATE.lock().unwrap_or_else(|e| e.into_inner()) {
        State::Ready(o) => Some(o.clone()),
        _ => None,
    }
}

fn audio_thread() {
    // This thread owns the stream (cpal streams must stay on one thread) and
    // parks forever, so it never runs thread-exit cleanup.
    unsafe {
        windows_sys::Win32::System::Com::CoInitializeEx(
            std::ptr::null(),
            windows_sys::Win32::System::Com::COINIT_MULTITHREADED as u32,
        )
    };
    let (tx, rx) = channel::<bool>();
    let stream = match open(tx) {
        Ok((stream, output)) => {
            *STATE.lock().unwrap_or_else(|e| e.into_inner()) = State::Ready(output);
            CHANGED.notify_all();
            stream
        }
        Err(e) => {
            log(&format!("no sound: {e}"));
            *STATE.lock().unwrap_or_else(|e| e.into_inner()) = State::Failed;
            CHANGED.notify_all();
            loop {
                std::thread::park();
            }
        }
    };
    // Play while any player is registered, pause otherwise.
    for play in rx {
        let r = if play {
            stream.play().map_err(|e| e.to_string())
        } else {
            stream.pause().map_err(|e| e.to_string())
        };
        if let Err(e) = r {
            log(&format!(
                "audio {} failed: {e}",
                if play { "play" } else { "pause" }
            ));
        }
    }
    loop {
        std::thread::park();
    }
}

fn open(tx: Sender<bool>) -> Result<(cpal::Stream, Arc<Output>), String> {
    let host = cpal::default_host();
    let device = host
        .default_output_device()
        .ok_or("no audio output device")?;
    let config = device.default_output_config().map_err(|e| e.to_string())?;
    let sample_format = config.sample_format();
    let config = cpal::StreamConfig::from(config);
    let voices: Arc<Mutex<Vec<Voice>>> = Arc::new(Mutex::new(Vec::new()));

    let mut scratch: Vec<f32> = Vec::new();
    let mut sum: Vec<f32> = Vec::new();
    let v = voices.clone();
    let mut mix_into = move |len: usize| -> Vec<f32> {
        sum.clear();
        sum.resize(len, 0.0);
        let mixed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(voices) = v.lock() {
                for voice in voices.iter().filter(|v| v.active.load(Ordering::Relaxed)) {
                    scratch.clear();
                    scratch.resize(len, 0.0);
                    voice.mixer.mix::<f32>(&mut scratch);
                    for (s, x) in sum.iter_mut().zip(&scratch) {
                        *s += *x;
                    }
                }
            }
        }));
        if mixed.is_err() {
            sum.clear();
            sum.resize(len, 0.0); // silence rather than a dead audio thread
        }
        let audible = sum.iter().filter(|s| **s != 0.0).count();
        SAMPLES_MIXED.fetch_add(len as u64, Ordering::Relaxed);
        SAMPLES_AUDIBLE.fetch_add(audible as u64, Ordering::Relaxed);
        std::mem::take(&mut sum)
    };
    let on_error = |err| crate::log(&format!("audio stream error: {err}"));
    let stream = match sample_format {
        cpal::SampleFormat::F32 => device.build_output_stream(
            &config,
            move |buffer: &mut [f32], _| {
                let m = mix_into(buffer.len());
                for (o, s) in buffer.iter_mut().zip(&m) {
                    *o = s.clamp(-1.0, 1.0);
                }
            },
            on_error,
            None,
        ),
        cpal::SampleFormat::I16 => device.build_output_stream(
            &config,
            move |buffer: &mut [i16], _| {
                let m = mix_into(buffer.len());
                for (o, s) in buffer.iter_mut().zip(&m) {
                    *o = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
                }
            },
            on_error,
            None,
        ),
        cpal::SampleFormat::U16 => device.build_output_stream(
            &config,
            move |buffer: &mut [u16], _| {
                let m = mix_into(buffer.len());
                for (o, s) in buffer.iter_mut().zip(&m) {
                    *o = ((s.clamp(-1.0, 1.0) * 32767.0) as i16 as u16).wrapping_add(32768);
                }
            },
            on_error,
            None,
        ),
        other => return Err(format!("unsupported sample format {other:?}")),
    }
    .map_err(|e| e.to_string())?;
    stream.pause().ok();
    STREAMS_STARTED.fetch_add(1, Ordering::Relaxed);
    log(&format!(
        "audio: {} Hz, {} channels, {sample_format:?}",
        config.sample_rate.0, config.channels
    ));
    Ok((
        stream,
        Arc::new(Output {
            channels: config.channels,
            sample_rate: config.sample_rate.0,
            voices,
            commands: Mutex::new(tx),
        }),
    ))
}

/// A player's audio: its own mixer, registered with the shared output.
pub struct MixerBackend {
    mixer: AudioMixer,
    id: u64,
    active: Arc<AtomicBool>,
    output: Arc<Output>,
}

impl MixerBackend {
    fn new(output: Arc<Output>) -> Self {
        let mixer = AudioMixer::new(output.channels as u8, output.sample_rate);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let active = Arc::new(AtomicBool::new(true));
        let first = {
            let mut voices = output.voices.lock().unwrap_or_else(|e| e.into_inner());
            voices.push(Voice {
                id,
                mixer: mixer.proxy(),
                active: active.clone(),
            });
            voices.len() == 1
        };
        if first {
            let _ = output
                .commands
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .send(true);
        }
        Self {
            mixer,
            id,
            active,
            output,
        }
    }
}

impl Drop for MixerBackend {
    fn drop(&mut self) {
        let empty = {
            let mut voices = self.output.voices.lock().unwrap_or_else(|e| e.into_inner());
            voices.retain(|v| v.id != self.id);
            voices.is_empty()
        };
        if empty {
            let _ = self
                .output
                .commands
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .send(false);
        }
    }
}

impl AudioBackend for MixerBackend {
    impl_audio_mixer_backend!(mixer);

    fn play(&mut self) {
        self.active.store(true, Ordering::Relaxed);
    }

    fn pause(&mut self) {
        self.active.store(false, Ordering::Relaxed);
    }
}

/// The audio backend for a new player; silent when `muted` or without a device.
pub fn backend(muted: bool) -> Box<dyn AudioBackend> {
    match output() {
        Some(o) if !muted => Box::new(MixerBackend::new(o)),
        _ => Box::new(NullAudioBackend::new()),
    }
}
