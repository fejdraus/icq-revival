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

/// fscommand the DLL's own AVM1 snippets use to hand a value back.
const RESULT_COMMAND: &str = "__FlashPlayerControl_result";

struct QueueFsCommands {
    queue: FsQueue,
    result: Rc<RefCell<Option<String>>>,
}

impl FsCommandProvider for QueueFsCommands {
    fn on_fs_command(&self, command: &str, args: &str) -> bool {
        if command == RESULT_COMMAND {
            *self.result.borrow_mut() = Some(args.to_owned());
            return true;
        }
        self.queue
            .borrow_mut()
            .push_back((command.to_owned(), args.to_owned()));
        true
    }
}

/// How a movie is shown: Flash's WMode and Scale parameters.
#[derive(Clone, Copy, Debug)]
pub struct Display {
    /// WMode transparent: the stage colour is not drawn.
    pub transparent: bool,
    pub scale: StageScaleMode,
}

impl Default for Display {
    fn default() -> Self {
        Display {
            transparent: true,
            scale: StageScaleMode::ShowAll,
        }
    }
}

/// Parses Flash's Scale parameter ("showall", "noborder", "exactfit", "noscale").
pub fn scale_mode(s: &str) -> Option<StageScaleMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "showall" | "default" | "" => Some(StageScaleMode::ShowAll),
        "noborder" => Some(StageScaleMode::NoBorder),
        "exactfit" => Some(StageScaleMode::ExactFit),
        "noscale" => Some(StageScaleMode::NoScale),
        _ => None,
    }
}

/// Builds AVM1 bytecode (SWF action records).
struct Avm1Code(Vec<u8>);

impl Avm1Code {
    fn new() -> Self {
        Avm1Code(Vec::new())
    }

    fn record(&mut self, code: u8, payload: &[u8]) -> &mut Self {
        self.0.push(code);
        if code >= 0x80 {
            self.0
                .extend_from_slice(&(payload.len() as u16).to_le_bytes());
            self.0.extend_from_slice(payload);
        }
        self
    }

    fn cstr(s: &str) -> Vec<u8> {
        s.bytes().filter(|&b| b != 0).chain(Some(0)).collect()
    }

    /// ActionPush of one string.
    fn push(&mut self, s: &str) -> &mut Self {
        let mut p = vec![0u8];
        p.extend(Self::cstr(s));
        self.record(0x96, &p)
    }

    /// ActionSetTarget2 to `target`, then `body`, then back to the original
    /// target (ActionSetTarget "").
    fn with_target(&mut self, target: &str, body: impl FnOnce(&mut Self)) -> &mut Self {
        self.push(target).record(0x20, &[]);
        body(self);
        self.record(0x8B, &[0])
    }

    /// Hands the value on top of the stack back through RESULT_COMMAND:
    /// getURL("FSCommand:<result>", value) calls the fscommand provider.
    fn return_top(&mut self) -> &mut Self {
        let url = format!("FSCommand:{RESULT_COMMAND}");
        // Stack: value. Push the URL and swap, so GetURL2 pops the value as
        // the target and the URL below it.
        self.push(&url).record(0x4D, &[]).record(0x9A, &[0])
    }

    fn end(&mut self) -> Vec<u8> {
        self.0.push(0);
        std::mem::take(&mut self.0)
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
    result: Rc<RefCell<Option<String>>>,
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
        display: Display,
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

        let result = Rc::new(RefCell::new(None));
        let builder = PlayerBuilder::new()
            .with_renderer(renderer)
            .with_movie(swf)
            .with_fs_commands(Box::new(QueueFsCommands {
                queue: fs,
                result: result.clone(),
            }))
            .with_viewport_dimensions(width, height, 1.0)
            .with_letterbox(Letterbox::Off)
            .with_scale_mode(display.scale, false)
            .with_max_execution_duration(Duration::from_secs(5))
            .with_autoplay(true)
            .with_boxed_audio(crate::audio::backend(muted));
        let player = builder.build();
        {
            let mut p = player.lock().map_err(|_| "player lock poisoned")?;
            // Flash's wmode=transparent: the stage colour is not drawn.
            p.set_window_mode(if display.transparent {
                "transparent"
            } else {
                "opaque"
            });
            p.preload(&mut ExecutionLimit::none());
        }
        Ok(Self {
            player,
            result,
            total_frames,
            frame_rate,
            width,
            height,
        })
    }

    /// Runs AVM1 `code` on the root timeline, the way a frame script runs:
    /// paths, `addProperty` setters and gotos behave as in Flash. Nothing
    /// happens for an ActionScript 3 movie. Returns false if it could not run.
    fn run_avm1(&self, code: Vec<u8>) -> bool {
        use ruffle_core::context::ActionType;
        use ruffle_core::tag_utils::SwfSlice;
        self.with(|p| {
            p.update(|ctx| {
                if ctx.root_swf.is_action_script_3() {
                    return false;
                }
                let Some(root) = ctx.stage.root_clip() else {
                    return false;
                };
                let version = ctx.root_swf.version();
                let code = Arc::new(SwfMovie::fake_with_compressed_data(version, None, code));
                ctx.action_queue.queue_action(
                    root,
                    ActionType::Normal {
                        bytecode: SwfSlice::from(code),
                        name: "[FlashPlayerControl]",
                    },
                    false,
                );
                true
            })
        })
    }

    /// Flash's SetVariable: ActionSetVariable with `path` (`a.b`, `/a:b`,
    /// `_root.a.b`) resolved from the root timeline.
    pub fn set_variable(&self, path: &str, value: &str) -> bool {
        self.run_avm1(
            Avm1Code::new()
                .push(path)
                .push(value)
                .record(0x1D, &[])
                .end(),
        )
    }

    /// Flash's GetVariable: the value as a string; None if it could not run.
    pub fn get_variable(&self, path: &str) -> Option<String> {
        self.result.borrow_mut().take();
        let ok = self.run_avm1(
            Avm1Code::new()
                .push(path)
                .record(0x1C, &[])
                .return_top()
                .end(),
        );
        let value = self.result.borrow_mut().take();
        if ok { value } else { None }
    }

    /// Flash's TGotoLabel: `target` goes to frame `label`.
    pub fn t_goto_label(&self, target: &str, label: &str) -> bool {
        let mut c = Avm1Code::new();
        c.with_target(target, |c| {
            c.record(0x8C, &Avm1Code::cstr(label));
        });
        self.run_avm1(c.end())
    }

    /// Flash's TGotoFrame: `target` goes to 0-based `frame`.
    pub fn t_goto_frame(&self, target: &str, frame: u16) -> bool {
        let mut c = Avm1Code::new();
        c.with_target(target, |c| {
            c.record(0x81, &frame.to_le_bytes());
        });
        self.run_avm1(c.end())
    }

    /// Flash's TPlay (`play`) or TStopPlay on `target`.
    pub fn t_play(&self, target: &str, play: bool) -> bool {
        let mut c = Avm1Code::new();
        c.with_target(target, |c| {
            c.record(if play { 0x06 } else { 0x07 }, &[]);
        });
        self.run_avm1(c.end())
    }

    /// Changes WMode/Scale of a loaded movie.
    pub fn set_display(&self, display: Display) {
        self.with(|p| {
            p.set_window_mode(if display.transparent {
                "transparent"
            } else {
                "opaque"
            });
            p.set_scale_mode(display.scale);
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
