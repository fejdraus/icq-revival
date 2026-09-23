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


def main():
    raw = sys.stdin.buffer.read()
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

    sys.stdout.buffer.write(out.getvalue())


if __name__ == '__main__':
    main()
