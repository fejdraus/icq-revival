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
"""

import io
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


def work(raw):
    from PIL import Image, ImageOps
    try:
        image = Image.open(io.BytesIO(raw))
        image.load()
    except Exception:
        sys.exit(2)
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


def crop(raw, box):
    from PIL import Image
    image = Image.open(io.BytesIO(raw))
    image.load()
    image = image.convert('RGB').resize((WIDTH, HEIGHT), Image.LANCZOS, box=box)
    sys.stdout.buffer.write(finish(image))


def main():
    raw = sys.stdin.buffer.read()
    if len(sys.argv) > 1 and sys.argv[1] == 'work':
        work(raw)
        return
    if len(sys.argv) == 6 and sys.argv[1] == 'crop':
        crop(raw, tuple(float(v) for v in sys.argv[2:6]))
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
