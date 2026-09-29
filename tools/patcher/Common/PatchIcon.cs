// The icon every client patch carries, in the window and on its exe.
//
// The picture is the flower of the ICQ Revival logo, drawn from a PNG the
// patch carries (flower.png, embedded), with the client version on a pill
// under it from 48 pixels up. It is drawn into the window's header and into
// its title bar, and the app.ico each exe is built with was written from it
// once, by WriteFile below.

using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;
using System.Runtime.InteropServices;

namespace IcqRevival.Patch
{
    internal static class PatchIcon
    {
        public static Color ColorOf(string hex) { return ColorTranslator.FromHtml(hex); }

        // The flower of the ICQ Revival logo, 256 pixels square on a
        // transparent ground: flower.png next to this file, embedded in each
        // patch under that name. Loaded once.
        static Bitmap flower;

        static Bitmap Flower
        {
            get
            {
                if (flower == null)
                {
                    using (Stream s = typeof(PatchIcon).Assembly.GetManifestResourceStream("flower.png"))
                    using (var png = new Bitmap(s))
                    {
                        // A copy, so that the stream may be closed.
                        flower = new Bitmap(png);
                    }
                }
                return flower;
            }
        }

        // The flower of the ICQ Revival logo, filling the icon. From 48 pixels
        // up the flower moves up and the version is written under it, white on
        // a pill in the colour of the client version, so the exe of each patch
        // can be told apart at a glance in Explorer.
        public static Bitmap Draw(int size, string badge, string top, string bottom)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.CompositingQuality = CompositingQuality.HighQuality;
                g.Clear(Color.Transparent);

                double pad = Math.Max(0.5, size / 32.0);
                bool withText = size >= 48;
                double side = withText ? size * 0.80 : size - 2 * pad;
                double fx = (size - side) / 2;
                double fy = withText ? pad : (size - side) / 2;
                Bitmap f = Flower;
                using (var attrs = new ImageAttributes())
                {
                    // No half-transparent seam where the edge pixels are sampled.
                    attrs.SetWrapMode(WrapMode.TileFlipXY);
                    var dest = new[]
                    {
                        new PointF((float)fx, (float)fy),
                        new PointF((float)(fx + side), (float)fy),
                        new PointF((float)fx, (float)(fy + side)),
                    };
                    g.DrawImage(f, dest, new RectangleF(0, 0, f.Width, f.Height), GraphicsUnit.Pixel, attrs);
                }

                if (withText)
                {
                    // The pill: the dark outline and the white rim of the logo's
                    // shapes around the colour of the client version.
                    // Under 64 pixels there is no room for the rim.
                    double h = size * 0.32;
                    double y = size - pad - h;
                    double maxW = size - 2 * pad;
                    double line = Math.Max(1.0, size / 40.0);
                    int rings = size >= 64 ? 2 : 1;
                    double inset = rings * line;
                    // The digits stand about 0.7 em tall: 0.6 of the inside.
                    double em = (h - 2 * inset) * 0.85;
                    using (var fmt = (StringFormat)StringFormat.GenericTypographic.Clone())
                    {
                        fmt.Alignment = StringAlignment.Center;
                        fmt.LineAlignment = StringAlignment.Near;
                        fmt.FormatFlags |= StringFormatFlags.NoWrap;
                        double textW;
                        using (var probe = new Font("Segoe UI", (float)em, FontStyle.Bold, GraphicsUnit.Pixel))
                        {
                            textW = g.MeasureString(badge, probe, PointF.Empty, fmt).Width;
                        }
                        double room = maxW - h * 0.7;
                        if (textW > room)
                        {
                            em *= room / textW;
                            textW = room;
                        }
                        double w = Math.Min(maxW, Math.Max(h * 1.8, textW + h * 0.7));
                        double x = (size - w) / 2;
                        using (GraphicsPath outer = Pill(x, y, w, h))
                        using (GraphicsPath rim = Pill(x + line, y + line, w - 2 * line, h - 2 * line))
                        using (GraphicsPath inner = Pill(x + inset, y + inset, w - 2 * inset, h - 2 * inset))
                        using (var dark = new SolidBrush(Color.FromArgb(255, 2, 33, 25)))
                        using (var white = new SolidBrush(Color.White))
                        using (var fill = new LinearGradientBrush(
                            new PointF(0, (float)(y + inset - 1)), new PointF(0, (float)(y + h - inset + 1)), ColorOf(top), ColorOf(bottom)))
                        using (var font = new Font("Segoe UI", (float)em, FontStyle.Bold, GraphicsUnit.Pixel))
                        {
                            g.FillPath(dark, outer);
                            if (rings > 1) g.FillPath(white, rim);
                            g.FillPath(fill, inner);
                            // The line is laid out from the top of its ascent;
                            // the digits are centred by their own height.
                            FontFamily family = font.FontFamily;
                            double ascent = em * family.GetCellAscent(FontStyle.Bold) / family.GetEmHeight(FontStyle.Bold);
                            double baseline = y + h / 2 + em * 0.70 / 2;
                            var box = new RectangleF((float)x, (float)(baseline - ascent), (float)w, (float)h);
                            g.DrawString(badge, font, white, box, fmt);
                        }
                    }
                }
            }
            return bmp;
        }

        // A rectangle with fully rounded ends.
        static GraphicsPath Pill(double x, double y, double w, double h)
        {
            var path = new GraphicsPath();
            float d = (float)h;
            path.AddArc((float)x, (float)y, d, d, 90, 180);
            path.AddArc((float)(x + w - h), (float)y, d, d, 270, 180);
            path.CloseFigure();
            return path;
        }

        // An .ico with one frame per size: 32-bit bitmaps for the small ones,
        // which every part of Windows reads, and PNG for 256.
        public static byte[] Bytes(string badge, string top, string bottom)
        {
            int[] sizes = { 16, 20, 24, 32, 40, 48, 64, 256 };
            var frames = new byte[sizes.Length][];
            for (int n = 0; n < sizes.Length; n++)
            {
                int s = sizes[n];
                using (Bitmap bmp = Draw(s, badge, top, bottom))
                using (var ms = new MemoryStream())
                {
                    if (s >= 256)
                    {
                        bmp.Save(ms, ImageFormat.Png);
                    }
                    else
                    {
                        BitmapData data = bmp.LockBits(new Rectangle(0, 0, s, s), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
                        var pixels = new byte[s * s * 4];
                        Marshal.Copy(data.Scan0, pixels, 0, pixels.Length);
                        bmp.UnlockBits(data);
                        int maskRow = (int)(Math.Floor((s + 31) / 32.0) * 4);
                        var bw = new BinaryWriter(ms);
                        bw.Write((uint)40); bw.Write(s); bw.Write(2 * s);
                        bw.Write((ushort)1); bw.Write((ushort)32); bw.Write((uint)0);
                        bw.Write((uint)(pixels.Length + maskRow * s));
                        bw.Write(0); bw.Write(0); bw.Write((uint)0); bw.Write((uint)0);
                        for (int y = s - 1; y >= 0; y--) bw.Write(pixels, y * s * 4, s * 4);
                        bw.Write(new byte[maskRow * s]);
                        bw.Flush();
                    }
                    frames[n] = ms.ToArray();
                }
            }
            using (var ms = new MemoryStream())
            {
                var bw = new BinaryWriter(ms);
                bw.Write((ushort)0); bw.Write((ushort)1); bw.Write((ushort)sizes.Length);
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    byte dim = (byte)(sizes[i] >= 256 ? 0 : sizes[i]);
                    bw.Write(dim); bw.Write(dim); bw.Write((byte)0); bw.Write((byte)0);
                    bw.Write((ushort)1); bw.Write((ushort)32);
                    bw.Write((uint)frames[i].Length); bw.Write((uint)offset);
                    offset += frames[i].Length;
                }
                foreach (byte[] f in frames) bw.Write(f);
                bw.Flush();
                return ms.ToArray();
            }
        }

        public static void WriteFile(string path, string badge, string top, string bottom)
        {
            File.WriteAllBytes(path, Bytes(badge, top, bottom));
        }
    }
}
