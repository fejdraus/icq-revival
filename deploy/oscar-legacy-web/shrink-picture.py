"""Fit a picture into what a buddy icon should be.

Reads an image on standard input and writes a JPEG on standard output. Large
photographs are what people pick, and the client sends whatever it is given
straight to the server, where every other client then downloads it - so the
image is scaled down and re-encoded here instead.

The shape is not ours to choose: ICQ 6 draws the picture in frames of 85x106 in
the profile and 50x64 in the contact list, and stretches whatever it is given to
fill them. A square picture therefore comes out visibly pulled upwards. So the
image is cropped from the middle to those proportions, which the client then
shows untouched, and other clients - which scale to fit rather than stretch -
show as an ordinary upright picture.

Falls back to writing the input through unchanged if it cannot be decoded, so a
format we do not understand is still the client's decision to make, not ours.

The picture editor of the picture page uses two more modes:

  shrink-picture.py work
      The picture the editor works on: turned upright by its EXIF
      orientation, flattened onto white, RGB, no longer than WORK_MAX on its
      long side, as a JPEG. Exits with status 2, writing nothing, when the
      input cannot be decoded.
  shrink-picture.py crop <left> <top> <right> <bottom>
      The buddy icon from a working copy: that box of it (picture pixels,
      fractions allowed, from picture-crop.js) scaled to 52x64.

An animated GIF stays animated (a buddy icon may be one: GIF, at most 64x64
and 7168 bytes, which AIM, Pidgin and Miranda play):

  work    writes an animated working copy (a GIF, frames composed and
          flattened onto white, at most ANIM_WORK_MAX long, at most
          FRAMES_MAX frames and SECONDS_MAX seconds) and, on standard error,
          one line of JSON: {"animated": true, "frames": n, "fits": bool,
          "cut": bool}. "fits" is an upload that is already a valid icon;
          "cut" says frames were dropped past the limits.
  crop    on an animated working copy cuts every frame to the box, keeps
          the durations and the loop, and makes it fit ICON_BYTES: a
          shared palette of 64, 32 or 16 colours, then every other frame,
          then only the first seconds. Exits with status 3, writing
          nothing, when nothing reasonable fits.
  crop-still <left> <top> <right> <bottom>
          the first frame of an animated working copy, as the JPEG icon.
"""

import io
import json
import sys

# What the client itself sends: whatever it is handed, ICQ 6 re-encodes to a
# 52x64 JPEG before uploading - that is what ends up in the database and what
# every other client downloads. Handing it exactly that size keeps the picture
# from being scaled twice, which is the difference between a readable face and
# a smudge. The profile window then stretches those 52x64 into its 85x106 frame,
# and nothing can be done about that from here.
WIDTH = 52
HEIGHT = 64
TARGET = 48 * 1024  # buddy icons travel with presence, so keep them small
# The editor's copy: plenty for a 52x64 cut even at the largest zoom, and
# small enough to show in the page and keep for a few minutes.
WORK_MAX = 800
# Animated GIFs: a buddy icon's limit, and the bounds on the work.
ICON_BYTES = 7168
ICON_BOX = 64
ANIM_WORK_MAX = 400
FRAMES_MAX = 200
SECONDS_MAX = 10.0


def finish(image):
    """The icon as JPEG bytes: sharpened a little, as small as it can be."""
    if image.mode not in ('RGB', 'L'):
        image = image.convert('RGB')

    # A little sharpening to survive what comes next. The client re-encodes the
    # picture into a JPEG of its own before uploading, so the image is
    # compressed twice however carefully it is prepared here; shrinking softens
    # it and the second pass softens it again. PNG would avoid one of those
    # passes, but the client silently refuses it - it downloads the file and
    # uploads nothing - so JPEG at a high quality it is.
    try:
        from PIL import ImageFilter
        image = image.filter(ImageFilter.UnsharpMask(radius=0.7, percent=70, threshold=2))
    except Exception:
        pass

    for quality in (95, 90, 85, 75):
        out = io.BytesIO()
        image.save(out, 'JPEG', quality=quality, optimize=True, subsampling=0)
        if out.tell() <= TARGET:
            break
    return out.getvalue()


def flatten(frame):
    """A frame as RGB on white."""
    from PIL import Image
    frame = frame.convert('RGBA')
    flat = Image.new('RGB', frame.size, (255, 255, 255))
    flat.paste(frame, mask=frame.split()[3])
    return flat


def gif_frames(image):
    """The composed frames of an animated GIF as (RGB image, duration ms),
    within FRAMES_MAX and SECONDS_MAX, and whether any were left out."""
    frames = []
    total = 0.0
    cut = False
    for i in range(image.n_frames):
        if len(frames) >= FRAMES_MAX or total >= SECONDS_MAX * 1000:
            cut = True
            break
        image.seek(i)
        duration = int(image.info.get('duration') or 100)
        frames.append((flatten(image), duration))
        total += duration
    return frames, cut


def save_gif(frames, loop, colors):
    """GIF bytes of RGB frames with one shared adaptive palette."""
    from PIL import Image
    width, height = frames[0][0].size
    # The palette from all frames at once, so it does not flicker.
    sheet = Image.new('RGB', (width, height * len(frames)))
    for i, (frame, _) in enumerate(frames):
        sheet.paste(frame, (0, i * height))
    method = getattr(getattr(Image, 'Quantize', Image), 'MEDIANCUT', 0)
    palette = sheet.quantize(colors=colors, method=method)
    nodither = getattr(getattr(Image, 'Dither', Image), 'NONE', 0)
    pal = [f.quantize(palette=palette, dither=nodither) for f, _ in frames]
    out = io.BytesIO()
    extra = {'loop': loop} if loop is not None else {}
    pal[0].save(out, 'GIF', save_all=True, append_images=pal[1:],
                duration=[d for _, d in frames], optimize=True, disposal=1, **extra)
    return out.getvalue()


def animated_work(raw, image):
    from PIL import Image
    frames, cut = gif_frames(image)
    loop = image.info.get('loop')
    width, height = image.size
    fits = width <= ICON_BOX and height <= ICON_BOX and len(raw) <= ICON_BYTES and not cut
    scale = min(1.0, ANIM_WORK_MAX / max(width, height))
    if scale < 1:
        size = (max(1, round(width * scale)), max(1, round(height * scale)))
        frames = [(f.resize(size, Image.LANCZOS), d) for f, d in frames]
    sys.stdout.buffer.write(save_gif(frames, loop, 256))
    sys.stderr.write(json.dumps({'animated': True, 'frames': len(frames), 'fits': fits, 'cut': cut}) + '\n')


def is_animated_gif(image):
    return image.format == 'GIF' and getattr(image, 'n_frames', 1) > 1


def work(raw):
    from PIL import Image, ImageOps
    try:
        image = Image.open(io.BytesIO(raw))
        image.load()
    except Exception:
        sys.exit(2)
    if is_animated_gif(image):
        animated_work(raw, image)
        return
    try:
        image = ImageOps.exif_transpose(image)
    except Exception:
        pass
    if image.mode in ('RGBA', 'LA', 'P', 'PA'):
        image = image.convert('RGBA')
        flat = Image.new('RGB', image.size, (255, 255, 255))
        flat.paste(image, mask=image.split()[3])
        image = flat
    elif image.mode != 'RGB':
        image = image.convert('RGB')
    image.thumbnail((WORK_MAX, WORK_MAX), Image.LANCZOS)
    out = io.BytesIO()
    image.save(out, 'JPEG', quality=90)
    sys.stdout.buffer.write(out.getvalue())


def crop(raw, box, still=False):
    from PIL import Image
    image = Image.open(io.BytesIO(raw))
    image.load()
    # Rounding may put an edge a hair outside the picture.
    width, height = image.size
    box = (max(0.0, box[0]), max(0.0, box[1]), min(float(width), box[2]), min(float(height), box[3]))
    if is_animated_gif(image) and not still:
        crop_animated(image, box)
        return
    image = flatten(image).resize((WIDTH, HEIGHT), Image.LANCZOS, box=box)
    sys.stdout.buffer.write(finish(image))


def crop_animated(image, box):
    """Every frame cut to the box, as small a GIF as fits ICON_BYTES."""
    from PIL import Image
    frames, _ = gif_frames(image)
    loop = image.info.get('loop')
    frames = [(f.resize((WIDTH, HEIGHT), Image.LANCZOS, box=box), d) for f, d in frames]

    def every_other(fs):
        out = []
        for i in range(0, len(fs), 2):
            out.append((fs[i][0], fs[i][1] + (fs[i + 1][1] if i + 1 < len(fs) else 0)))
        return out

    def first_seconds(fs, seconds):
        out, total = [], 0
        for f, d in fs:
            if total >= seconds * 1000:
                break
            out.append((f, d))
            total += d
        return out

    halved = every_other(frames) if len(frames) > 2 else frames
    tries = [(frames, 64), (frames, 32), (frames, 16), (halved, 32), (halved, 16)]
    for seconds in (4, 2):
        short = first_seconds(halved, seconds)
        if len(short) > 1:
            tries.append((short, 16))
    for fs, colors in tries:
        body = save_gif(fs, loop, colors)
        if len(body) <= ICON_BYTES:
            sys.stdout.buffer.write(body)
            return
    sys.exit(3)


def main():
    raw = sys.stdin.buffer.read()
    if len(sys.argv) > 1 and sys.argv[1] == 'work':
        work(raw)
        return
    if len(sys.argv) == 6 and sys.argv[1] in ('crop', 'crop-still'):
        crop(raw, tuple(float(v) for v in sys.argv[2:6]), still=sys.argv[1] == 'crop-still')
        return
    try:
        from PIL import Image
        image = Image.open(io.BytesIO(raw))
        image.load()
    except Exception:
        sys.stdout.buffer.write(raw)
        return

    # Crop from the middle to the shape of the client's frame, losing as little
    # of the picture as possible, then scale.
    width, height = image.size
    wanted = WIDTH / HEIGHT
    if width / height > wanted:
        keep = int(round(height * wanted))
        left = (width - keep) // 2
        image = image.crop((left, 0, left + keep, height))
    else:
        keep = int(round(width / wanted))
        top = (height - keep) // 2
        image = image.crop((0, top, width, top + keep))

    image = image.resize((WIDTH, HEIGHT), Image.LANCZOS)
    sys.stdout.buffer.write(finish(image))


if __name__ == '__main__':
    main()
