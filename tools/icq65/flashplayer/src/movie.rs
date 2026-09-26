//! One loaded SWF: a Ruffle player that renders offscreen through wgpu.

use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ruffle_core::config::Letterbox;
use ruffle_core::external::FsCommandProvider;
use ruffle_core::limits::ExecutionLimit;
use ruffle_core::tag_utils::SwfMovie;
use ruffle_core::{FloatDuration, Player, PlayerBuilder, StageScaleMode, ViewportDimensions};
use ruffle_render_wgpu::backend::WgpuRenderBackend;
use ruffle_render_wgpu::target::TextureTarget;
use ruffle_render_wgpu::utils::capture_image;

pub(crate) type Renderer = WgpuRenderBackend<TextureTarget>;

/// fscommands raised while the player ran, delivered after it is unlocked.
pub type FsQueue = Rc<RefCell<VecDeque<(String, String)>>>;

struct QueueFsCommands(FsQueue);

impl FsCommandProvider for QueueFsCommands {
    fn on_fs_command(&self, command: &str, args: &str) -> bool {
        self.0
            .borrow_mut()
            .push_back((command.to_owned(), args.to_owned()));
        true
    }
}

/// Premultiplied BGRA pixels, top-down, tightly packed.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

pub struct Movie {
    player: Arc<Mutex<Player>>,
    pub total_frames: u16,
    pub frame_rate: f64,
    pub width: u32,
    pub height: u32,
}

impl Movie {
    /// Parses `data` and builds a player that renders `width`x`height` pixels.
    pub fn new(
        data: &[u8],
        url: &str,
        width: u32,
        height: u32,
        fs: FsQueue,
        muted: bool,
    ) -> Result<Self, String> {
        let swf =
            SwfMovie::from_data(data, url.to_owned(), None, None).map_err(|e| e.to_string())?;
        let total_frames = swf.num_frames();
        let frame_rate = swf.frame_rate().to_f64();
        let movie_width = swf.width().to_pixels().round().max(1.0) as u32;
        let movie_height = swf.height().to_pixels().round().max(1.0) as u32;
        let (width, height) = if width == 0 || height == 0 {
            (movie_width, movie_height)
        } else {
            (width, height)
        };

        // Ready by now: the load thread waited for it (see instance.rs).
        let descriptors = crate::gpu::get()?;
        let target =
            TextureTarget::new(&descriptors.device, (width, height)).map_err(|e| e.to_string())?;
        let renderer = Renderer::new(descriptors, target).map_err(|e| e.to_string())?;

        let builder = PlayerBuilder::new()
            .with_renderer(renderer)
            .with_movie(swf)
            .with_fs_commands(Box::new(QueueFsCommands(fs)))
            .with_viewport_dimensions(width, height, 1.0)
            .with_letterbox(Letterbox::Off)
            .with_scale_mode(StageScaleMode::ShowAll, false)
            .with_max_execution_duration(Duration::from_secs(5))
            .with_autoplay(true)
            .with_boxed_audio(crate::audio::backend(muted));
        let player = builder.build();
        {
            let mut p = player.lock().map_err(|_| "player lock poisoned")?;
            // Flash's wmode=transparent: the stage colour is not drawn.
            p.set_window_mode("transparent");
            p.preload(&mut ExecutionLimit::none());
        }
        Ok(Self {
            player,
            total_frames,
            frame_rate,
            width,
            height,
        })
    }

    fn with<R>(&self, f: impl FnOnce(&mut Player) -> R) -> R {
        let mut p = self.player.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut p)
    }

    /// Advances the player by `dt`. Returns true when the picture changed.
    pub fn tick(&self, dt: Duration) -> bool {
        self.with(|p| {
            p.tick(FloatDuration::from_secs(dt.as_secs_f64()));
            p.needs_render()
        })
    }

    /// The root timeline's current frame (1-based) and whether it is playing.
    pub fn root_state(&self) -> (u16, bool) {
        self.with(|p| {
            p.mutate_with_update_context(|ctx| {
                match ctx.stage.root_clip().and_then(|r| r.as_movie_clip()) {
                    Some(mc) => (mc.current_frame(), mc.playing()),
                    None => (0, false),
                }
            })
        })
    }

    /// Whether the player is running at all (not suspended).
    pub fn running(&self) -> bool {
        self.with(|p| p.is_playing())
    }

    pub fn play(&self) {
        self.with(|p| {
            p.set_is_playing(true);
            p.update(|ctx| {
                if let Some(mc) = ctx.stage.root_clip().and_then(|r| r.as_movie_clip()) {
                    mc.play();
                }
            });
        })
    }

    /// Stops the root timeline where it is (the player keeps running).
    pub fn stop_root(&self) {
        self.with(|p| {
            p.update(|ctx| {
                if let Some(mc) = ctx.stage.root_clip().and_then(|r| r.as_movie_clip()) {
                    mc.stop(ctx);
                }
            });
        })
    }

    /// Pauses everything, like Flash's StopPlay.
    pub fn pause(&self) {
        self.stop_root();
        self.with(|p| p.set_is_playing(false));
    }

    /// Shows 1-based `frame` of the root timeline and stops there.
    ///
    /// Ruffle does not expose a direct goto, so this steps with the public
    /// next/prev frame calls (each one is a goto-and-stop by one frame).
    pub fn goto_frame(&self, frame: u16) {
        let frame = frame.clamp(1, self.total_frames.max(1));
        self.with(|p| {
            p.update(|ctx| {
                let Some(mc) = ctx.stage.root_clip().and_then(|r| r.as_movie_clip()) else {
                    return;
                };
                mc.stop(ctx);
                let mut guard = 0;
                while mc.current_frame() != frame && guard < 2 * u16::MAX as u32 {
                    let before = mc.current_frame();
                    if before < frame {
                        mc.next_frame(ctx);
                    } else {
                        mc.prev_frame(ctx);
                    }
                    if mc.current_frame() == before {
                        break; // frame not loaded / cannot move
                    }
                    guard += 1;
                }
            });
        })
    }

    pub fn resize(&mut self, width: u32, height: u32) {
        if width == 0 || height == 0 || (width == self.width && height == self.height) {
            return;
        }
        self.width = width;
        self.height = height;
        self.with(|p| {
            p.set_viewport_dimensions(ViewportDimensions {
                width,
                height,
                scale_factor: 1.0,
            })
        });
    }

    /// Renders the current frame and reads it back from the GPU.
    pub fn render(&self) -> Option<Frame> {
        // Test only: FLASHPLAYERCONTROL_TEST_PANIC=<n> makes the n-th render
        // (and every one after it) panic, as a failing GPU would.
        static RENDERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = RENDERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if let Some(at) = std::env::var("FLASHPLAYERCONTROL_TEST_PANIC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            if n >= at {
                panic!("FLASHPLAYERCONTROL_TEST_PANIC: render {n}");
            }
        }
        self.with(|p| {
            p.render();
            let renderer = <dyn Any>::downcast_mut::<Renderer>(p.renderer_mut())?;
            read_back(renderer)
        })
    }
}

/// Reads the last submitted frame of `renderer` back from the GPU.
pub fn read_back(renderer: &Renderer) -> Option<Frame> {
    let target = renderer.target();
    let info = target.buffer.as_ref()?;
    let (buffer, dims) = info.buffer.inner();
    let (width, height) = (target.size.width, target.size.height);
    let row = width as usize * 4;
    let pixels = capture_image(renderer.device(), buffer, dims, None, |rgba, padded| {
        let mut out = Vec::with_capacity(row * height as usize);
        for line in rgba.chunks(padded as usize).take(height as usize) {
            for px in line[..row].chunks_exact(4) {
                // RGBA (already premultiplied) -> BGRA
                out.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
            }
        }
        out
    });
    Some(Frame {
        width,
        height,
        pixels,
    })
}
