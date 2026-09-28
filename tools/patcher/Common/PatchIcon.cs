// The icon every client patch carries, in the window and on its exe.
//
// The icon is drawn, not stored: the same picture is drawn into the window's
// header and into its title bar, and the app.ico each exe is built with was
// written from it once, by WriteFile below.

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

        // A flower of eight petals on a rounded tile in the colour of the client
        // version. From 48 pixels up the version is written under the flower, so
        // the exe of each patch can be told apart at a glance in Explorer.
        public static Bitmap Draw(int size, string badge, string top, string bottom)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
                g.Clear(Color.Transparent);

                double pad = Math.Max(0.5, size / 32.0);
                double w = size - 2 * pad;
                double r = w * 0.22;
                using (var tile = new GraphicsPath())
                {
                    tile.AddArc((float)pad, (float)pad, (float)(2 * r), (float)(2 * r), 180, 90);
                    tile.AddArc((float)(pad + w - 2 * r), (float)pad, (float)(2 * r), (float)(2 * r), 270, 90);
                    tile.AddArc((float)(pad + w - 2 * r), (float)(pad + w - 2 * r), (float)(2 * r), (float)(2 * r), 0, 90);
                    tile.AddArc((float)pad, (float)(pad + w - 2 * r), (float)(2 * r), (float)(2 * r), 90, 90);
                    tile.CloseFigure();
                    using (var fill = new LinearGradientBrush(
                        new PointF(0, (float)pad), new PointF(0, (float)(size - pad)), ColorOf(top), ColorOf(bottom)))
                    {
                        g.FillPath(fill, tile);
                    }
                }

                bool withText = size >= 48;
                double cx = size / 2.0;
                double cy = withText ? size * 0.40 : size / 2.0;
                double petalLen = withText ? size * 0.19 : size * 0.25;
                double petalWid = petalLen * 0.72;
                using (var white = new SolidBrush(Color.FromArgb(250, 255, 255, 255)))
                {
                    for (int i = 0; i < 8; i++)
                    {
                        GraphicsState state = g.Save();
                        g.TranslateTransform((float)cx, (float)cy);
                        g.RotateTransform(45 * i);
                        g.FillEllipse(white, (float)(-petalWid / 2), (float)(-petalLen * 1.55), (float)petalWid, (float)(petalLen * 1.1));
                        g.Restore(state);
                    }
                    double heart = petalLen * 0.62;
                    using (var heartBrush = new SolidBrush(ColorOf(bottom)))
                    {
                        g.FillEllipse(heartBrush, (float)(cx - heart / 2), (float)(cy - heart / 2), (float)heart, (float)heart);
                    }

                    if (withText)
                    {
                        double em = size * 0.20;
                        if (badge.Length > 3) em = size * 0.165;
                        using (var font = new Font("Segoe UI", (float)em, FontStyle.Bold, GraphicsUnit.Pixel))
                        using (var fmt = new StringFormat())
                        {
                            fmt.Alignment = StringAlignment.Center;
                            fmt.LineAlignment = StringAlignment.Center;
                            var box = new RectangleF(0, (float)(size * 0.70), size, (float)(size * 0.24));
                            g.DrawString(badge, font, white, box, fmt);
                        }
                    }
                }
            }
            return bmp;
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
