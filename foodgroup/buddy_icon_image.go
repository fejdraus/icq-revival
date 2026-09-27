package foodgroup

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
)

const (
	// maxBuddyIconSide is the largest width and height of a buddy icon
	// (wire.BARTTypesBuddyIcon) the old clients take: 64 pixels.
	maxBuddyIconSide = 64
	// maxBuddyIconBytes is the largest buddy icon the old clients take: 7 KB.
	maxBuddyIconBytes = 7 << 10
	// maxBuddyIconDecodeSide is the largest width and height of a picture the
	// server decodes to make a normalised copy of it, so that a small file
	// can't make it allocate a huge image.
	maxBuddyIconDecodeSide = 2048
)

var (
	errUnknownPictureFormat = errors.New("not a JPEG, PNG, GIF or BMP picture")
	errPictureTooLarge      = fmt.Errorf("picture larger than %dx%d pixels", maxBuddyIconDecodeSide, maxBuddyIconDecodeSide)
	// buddyIconJPEGQualities are the qualities a normalised copy is encoded
	// with, best first, until one fits in maxBuddyIconBytes.
	buddyIconJPEGQualities = []int{90, 80, 70, 60, 50, 40, 30, 20, 10}
)

// pictureFormat is a picture file format the server knows.
type pictureFormat int

const (
	formatUnknown pictureFormat = iota
	formatJPEG
	formatPNG
	formatGIF
	formatBMP
)

// sniffPictureFormat tells the format of the picture data by its signature.
func sniffPictureFormat(data []byte) pictureFormat {
	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return formatJPEG
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return formatPNG
	case bytes.HasPrefix(data, []byte("GIF8")):
		return formatGIF
	case bytes.HasPrefix(data, []byte("BM")):
		return formatBMP
	default:
		return formatUnknown
	}
}

// buddyIconConforms reports whether the old clients take the picture data
// as a buddy icon as it is: a GIF, baseline JPEG or BMP of at most
// maxBuddyIconSide pixels each way and maxBuddyIconBytes. A picture whose
// format or size can't be read returns an error.
func buddyIconConforms(data []byte) (bool, error) {
	format := sniffPictureFormat(data)
	width, height, err := pictureSize(data, format)
	if err != nil {
		return false, err
	}
	if len(data) > maxBuddyIconBytes || width > maxBuddyIconSide || height > maxBuddyIconSide {
		return false, nil
	}
	switch format {
	case formatJPEG:
		return isBaselineJPEG(data), nil
	case formatGIF, formatBMP:
		return true, nil
	default: // PNG
		return false, nil
	}
}

// pictureSize returns the width and height of the picture data in format.
func pictureSize(data []byte, format pictureFormat) (int, int, error) {
	switch format {
	case formatJPEG, formatPNG, formatGIF:
		cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return 0, 0, err
		}
		return cfg.Width, cfg.Height, nil
	case formatBMP:
		h, err := parseBMPHeader(data)
		if err != nil {
			return 0, 0, err
		}
		return h.width, h.height, nil
	default:
		return 0, 0, errUnknownPictureFormat
	}
}

// isBaselineJPEG reports whether the JPEG data is a sequential (baseline or
// extended) Huffman-coded one, which every client decodes, rather than a
// progressive, lossless or arithmetic-coded one, which the old ones don't.
func isBaselineJPEG(data []byte) bool {
	i := 2 // past SOI
	for i+4 <= len(data) {
		if data[i] != 0xFF {
			return false
		}
		marker := data[i+1]
		switch {
		case marker == 0xFF: // fill byte
			i++
			continue
		case marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7): // no length
			i += 2
			continue
		case marker == 0xC0 || marker == 0xC1:
			return true
		case marker >= 0xC2 && marker <= 0xCF && marker != 0xC4 && marker != 0xC8 && marker != 0xCC:
			return false // another start of frame
		case marker == 0xDA || marker == 0xD9: // start of scan, end of image before a frame
			return false
		}
		i += 2 + int(binary.BigEndian.Uint16(data[i+2:]))
	}
	return false
}

// normaliseBuddyIcon makes a copy of the picture data that the old clients
// take as a buddy icon: a baseline JPEG of at most maxBuddyIconSide pixels
// each way, keeping the picture's aspect, and at most maxBuddyIconBytes. A
// transparent picture is laid on white. A smaller picture is not enlarged.
func normaliseBuddyIcon(data []byte) ([]byte, error) {
	format := sniffPictureFormat(data)
	width, height, err := pictureSize(data, format)
	if err != nil {
		return nil, err
	}
	if width > maxBuddyIconDecodeSide || height > maxBuddyIconDecodeSide {
		return nil, errPictureTooLarge
	}
	if width < 1 || height < 1 {
		return nil, errors.New("empty picture")
	}

	var src image.Image
	switch format {
	case formatJPEG:
		src, err = jpeg.Decode(bytes.NewReader(data))
	case formatPNG:
		src, err = png.Decode(bytes.NewReader(data))
	case formatGIF:
		src, err = gif.Decode(bytes.NewReader(data))
	default: // BMP
		src, err = decodeBMP(data)
	}
	if err != nil {
		return nil, err
	}

	// lay the picture on white, so that transparency comes out white
	b := src.Bounds()
	flat := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(flat, flat.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(flat, flat.Bounds(), src, b.Min, draw.Over)

	w, h := fitWithin(b.Dx(), b.Dy(), maxBuddyIconSide)
	scaled := boxDownscale(flat, w, h)

	var buf bytes.Buffer
	for _, quality := range buddyIconJPEGQualities {
		buf.Reset()
		if err := jpeg.Encode(&buf, scaled, &jpeg.Options{Quality: quality}); err != nil {
			return nil, err
		}
		out := withJFIF(buf.Bytes())
		if len(out) <= maxBuddyIconBytes {
			return out, nil
		}
	}
	return nil, fmt.Errorf("the copy doesn't fit in %d bytes", maxBuddyIconBytes)
}

// jfifAPP0 is a JFIF APP0 segment: version 1.1, no density, no thumbnail.
var jfifAPP0 = []byte{0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00}

// withJFIF returns a copy of the JPEG b with a JFIF APP0 segment after its
// start-of-image marker, which Go's encoder doesn't write. Clients tell a
// picture's format by its first bytes: QIP 2012 looks for "JFIF" or "Exif"
// and, finding neither, saves the picture without an extension its cache
// never finds again.
func withJFIF(b []byte) []byte {
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 || (b[2] == 0xFF && b[3] == 0xE0) {
		return bytes.Clone(b)
	}
	out := make([]byte, 0, len(b)+len(jfifAPP0))
	out = append(out, b[:2]...)
	out = append(out, jfifAPP0...)
	return append(out, b[2:]...)
}

// fitWithin returns the size of a width x height picture scaled down to fit
// within side x side, keeping its aspect. A picture that fits is not
// enlarged.
func fitWithin(width, height, side int) (int, int) {
	if width <= side && height <= side {
		return width, height
	}
	if width >= height {
		return side, max(1, (height*side+width/2)/width)
	}
	return max(1, (width*side+height/2)/height), side
}

// boxDownscale scales src down to w x h pixels, each one the average of the
// box of src pixels it covers. w and h are at most src's size.
func boxDownscale(src *image.RGBA, w, h int) *image.RGBA {
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()
	if w == sw && h == sh {
		return src
	}
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for dy := 0; dy < h; dy++ {
		y0, y1 := dy*sh/h, max((dy+1)*sh/h, dy*sh/h+1)
		for dx := 0; dx < w; dx++ {
			x0, x1 := dx*sw/w, max((dx+1)*sw/w, dx*sw/w+1)
			var r, g, b, a, n uint32
			for y := y0; y < y1; y++ {
				row := src.Pix[y*src.Stride:]
				for x := x0; x < x1; x++ {
					p := row[x*4 : x*4+4]
					r += uint32(p[0])
					g += uint32(p[1])
					b += uint32(p[2])
					a += uint32(p[3])
					n++
				}
			}
			o := dst.PixOffset(dx, dy)
			dst.Pix[o] = uint8((r + n/2) / n)
			dst.Pix[o+1] = uint8((g + n/2) / n)
			dst.Pix[o+2] = uint8((b + n/2) / n)
			dst.Pix[o+3] = uint8((a + n/2) / n)
		}
	}
	return dst
}

// bmpHeader is what the server reads of a BMP file's headers.
type bmpHeader struct {
	width, height int
	// topDown is set for a picture stored from its top row down
	topDown     bool
	bitCount    int
	compression uint32
	// pixelOffset is where the pixels start in the file
	pixelOffset int
	// palette is where the color table starts in the file, and colors how
	// many colors it has
	palette, colors int
}

// parseBMPHeader reads the headers of the BMP file data. Only the Windows
// BITMAPINFOHEADER and its later versions are read.
func parseBMPHeader(data []byte) (bmpHeader, error) {
	if len(data) < 54 || data[0] != 'B' || data[1] != 'M' {
		return bmpHeader{}, errors.New("BMP: truncated header")
	}
	le := binary.LittleEndian
	infoSize := int(le.Uint32(data[14:]))
	if infoSize < 40 || 14+infoSize > len(data) {
		return bmpHeader{}, errors.New("BMP: unsupported header")
	}
	h := bmpHeader{
		width:       int(int32(le.Uint32(data[18:]))),
		height:      int(int32(le.Uint32(data[22:]))),
		bitCount:    int(le.Uint16(data[28:])),
		compression: le.Uint32(data[30:]),
		pixelOffset: int(le.Uint32(data[10:])),
		palette:     14 + infoSize,
		colors:      int(le.Uint32(data[46:])),
	}
	if h.height < 0 {
		h.height, h.topDown = -h.height, true
	}
	if h.width <= 0 || h.height <= 0 {
		return bmpHeader{}, errors.New("BMP: bad size")
	}
	if h.colors == 0 && h.bitCount <= 8 {
		h.colors = 1 << h.bitCount
	}
	return h, nil
}

// decodeBMP decodes an uncompressed BMP file of 1, 4, 8, 24 or 32 bits per
// pixel.
func decodeBMP(data []byte) (image.Image, error) {
	h, err := parseBMPHeader(data)
	if err != nil {
		return nil, err
	}
	if h.compression != 0 {
		return nil, errors.New("BMP: compressed pictures are not supported")
	}
	switch h.bitCount {
	case 1, 4, 8, 24, 32:
	default:
		return nil, fmt.Errorf("BMP: %d bits per pixel is not supported", h.bitCount)
	}
	if h.width > maxBuddyIconDecodeSide || h.height > maxBuddyIconDecodeSide {
		return nil, errPictureTooLarge
	}
	stride := (h.bitCount*h.width + 31) / 32 * 4
	if h.pixelOffset < 0 || h.pixelOffset+stride*h.height > len(data) {
		return nil, errors.New("BMP: truncated pixels")
	}
	var palette []color.RGBA
	if h.bitCount <= 8 {
		if h.colors > 256 || h.palette+4*h.colors > len(data) {
			return nil, errors.New("BMP: bad color table")
		}
		for i := 0; i < h.colors; i++ {
			p := data[h.palette+4*i:]
			palette = append(palette, color.RGBA{R: p[2], G: p[1], B: p[0], A: 0xFF})
		}
	}

	img := image.NewRGBA(image.Rect(0, 0, h.width, h.height))
	for row := 0; row < h.height; row++ {
		y := h.height - 1 - row
		if h.topDown {
			y = row
		}
		line := data[h.pixelOffset+row*stride:]
		for x := 0; x < h.width; x++ {
			var c color.RGBA
			switch h.bitCount {
			case 24, 32:
				p := line[x*h.bitCount/8:]
				c = color.RGBA{R: p[2], G: p[1], B: p[0], A: 0xFF}
			default:
				bit := x * h.bitCount
				index := int(line[bit/8]>>(8-h.bitCount-bit%8)) & (1<<h.bitCount - 1)
				if index >= len(palette) {
					return nil, errors.New("BMP: color outside the color table")
				}
				c = palette[index]
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img, nil
}
