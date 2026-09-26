//! Sound output through cpal (WASAPI), the way Ruffle's desktop player does it.
//!
//! This is Ruffle's `CpalAudioBackend` from `ruffle_frontend_utils`, copied so
//! the DLL does not pull that crate's HTTP stack. It also counts what the
//! mixer produced, which the test host reads to check that sound was played.

use std::sync::atomic::{AtomicU64, Ordering};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use ruffle_core::backend::audio::{
    AudioBackend, AudioMixer, DecodeError, RegisterError, SoundHandle, SoundInstanceHandle,
    SoundStreamInfo, SoundTransform, swf,
};
use ruffle_core::impl_audio_mixer_backend;

/// Audio streams opened so far.
pub static STREAMS_STARTED: AtomicU64 = AtomicU64::new(0);
/// Samples the device asked the mixer for.
pub static SAMPLES_MIXED: AtomicU64 = AtomicU64::new(0);
/// Of those, samples that were not silence.
pub static SAMPLES_AUDIBLE: AtomicU64 = AtomicU64::new(0);

pub struct CpalAudioBackend {
    stream: cpal::Stream,
    mixer: AudioMixer,
}

fn count<T: Copy + PartialEq + Default>(buffer: &[T]) {
    let silent = T::default();
    let audible = buffer.iter().filter(|s| **s != silent).count();
    SAMPLES_MIXED.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    SAMPLES_AUDIBLE.fetch_add(audible as u64, Ordering::Relaxed);
}

impl CpalAudioBackend {
    pub fn new() -> Result<Self, String> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or("no audio output device")?;
        let config = device.default_output_config().map_err(|e| e.to_string())?;
        let sample_format = config.sample_format();
        let config = cpal::StreamConfig::from(config);
        let mixer = AudioMixer::new(config.channels as u8, config.sample_rate.0);

        let stream = {
            let mixer = mixer.proxy();
            let on_error = |err| crate::log(&format!("audio stream error: {err}"));
            match sample_format {
                cpal::SampleFormat::F32 => device.build_output_stream(
                    &config,
                    move |buffer: &mut [f32], _| {
                        mixer.mix::<f32>(buffer);
                        count(buffer);
                    },
                    on_error,
                    None,
                ),
                cpal::SampleFormat::I16 => device.build_output_stream(
                    &config,
                    move |buffer: &mut [i16], _| {
                        mixer.mix::<i16>(buffer);
                        count(buffer);
                    },
                    on_error,
                    None,
                ),
                cpal::SampleFormat::U16 => device.build_output_stream(
                    &config,
                    move |buffer: &mut [u16], _| {
                        let samples: &mut [i16] = bytemuck_cast(buffer);
                        mixer.mix::<i16>(samples);
                        count(samples);
                        for s in buffer.iter_mut() {
                            *s = s.wrapping_add(32768);
                        }
                    },
                    on_error,
                    None,
                ),
                other => return Err(format!("unsupported sample format {other:?}")),
            }
            .map_err(|e| e.to_string())?
        };
        stream.play().map_err(|e| e.to_string())?;
        STREAMS_STARTED.fetch_add(1, Ordering::Relaxed);
        Ok(Self { stream, mixer })
    }
}

fn bytemuck_cast(buffer: &mut [u16]) -> &mut [i16] {
    // u16 and i16 have the same size and alignment.
    unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast(), buffer.len()) }
}

impl AudioBackend for CpalAudioBackend {
    impl_audio_mixer_backend!(mixer);

    fn play(&mut self) {
        if let Err(e) = self.stream.play() {
            crate::log(&format!("audio play failed: {e}"));
        }
    }

    fn pause(&mut self) {
        if let Err(e) = self.stream.pause() {
            crate::log(&format!("audio pause failed: {e}"));
        }
    }
}
