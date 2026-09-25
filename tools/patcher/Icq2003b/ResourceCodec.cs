// Reading and writing the text resources of ICQ Pro 2003b - string tables,
// menus and dialogs - so the patch builds each translated resource from the
// client's own English one, following the recipe. The port of
// tools\icq2003b\translate\icqres.py; the bytes it writes are the ones that
// tool's build.py recorded the recipe from, so a translated resource comes out
// exactly as before.
//
// Only what the translation needs: a resource is parsed into its texts plus
// everything else kept as it was, and written back with other texts. The
// layout of a dialog - positions, sizes, styles - stays as it is unless the
// recipe gives a control another width.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IcqRevival.Patch
{
    internal static class ResourceCodec
    {
        public const int RtMenu = 4, RtDialog = 5, RtString = 6;

        static readonly Encoding Utf16 = Encoding.Unicode;

        // A little-endian cursor over the resource bytes.
        sealed class Reader
        {
            readonly byte[] b;
            public int I;
            public Reader(byte[] data, int at = 0) { b = data; I = at; }
            public bool End { get { return I >= b.Length; } }
            public ushort U16() { ushort v = (ushort)(b[I] | (b[I + 1] << 8)); I += 2; return v; }
            public short S16() { return (short)U16(); }
            public uint U32() { uint v = (uint)b[I] | ((uint)b[I + 1] << 8) | ((uint)b[I + 2] << 16) | ((uint)b[I + 3] << 24); I += 4; return v; }
            public byte U8() { return b[I++]; }
            public byte[] Take(int n) { var r = new byte[n]; Array.Copy(b, I, r, 0, n); I += n; return r; }
            // A NUL-terminated UTF-16 string; the cursor lands past the terminator.
            public string WStr()
            {
                int j = I;
                while (!(b[j] == 0 && b[j + 1] == 0)) j += 2;
                string s = Utf16.GetString(b, I, j - I);
                I = j + 2;
                return s;
            }
            public void Align4() { I = (I + 3) & ~3; }
        }

        sealed class Writer
        {
            readonly List<byte> b = new List<byte>();
            public int Length { get { return b.Count; } }
            public void U16(int v) { b.Add((byte)v); b.Add((byte)(v >> 8)); }
            public void U32(uint v) { b.Add((byte)v); b.Add((byte)(v >> 8)); b.Add((byte)(v >> 16)); b.Add((byte)(v >> 24)); }
            public void U8(int v) { b.Add((byte)v); }
            public void Raw(byte[] d) { b.AddRange(d); }
            public void WStr(string s) { b.AddRange(Utf16.GetBytes(s)); b.Add(0); b.Add(0); }
            public void Align4() { while (b.Count % 4 != 0) b.Add(0); }
            public byte[] ToArray() { return b.ToArray(); }
        }

        // --- string tables --------------------------------------------------------

        public static string[] ReadStrings(byte[] data)
        {
            var r = new Reader(data);
            var outp = new List<string>();
            while (outp.Count < 16 && r.I + 2 <= data.Length)
            {
                int n = r.U16();
                outp.Add(Utf16.GetString(r.Take(2 * n)));
            }
            while (outp.Count < 16) outp.Add("");
            return outp.ToArray();
        }

        public static byte[] WriteStrings(IList<string> texts)
        {
            var w = new Writer();
            foreach (string t in texts)
            {
                byte[] u = Utf16.GetBytes(t);
                w.U16(u.Length / 2);
                w.Raw(u);
            }
            return w.ToArray();
        }

        // --- menus ----------------------------------------------------------------

        sealed class MenuItem
        {
            public bool HasId;
            public ushort Flags;
            public ushort Id;
            public string Text;
            // extended
            public uint Type, State, Mid;
            public bool HasHelp;
            public uint Help;
        }

        sealed class Menu
        {
            public bool Ex;
            public ushort Offset;
            public byte[] Head;
            public List<MenuItem> Items = new List<MenuItem>();
        }

        static Menu ReadMenu(byte[] data)
        {
            var r = new Reader(data);
            ushort version = r.U16();
            ushort offset = r.U16();
            var m = new Menu();
            if (version == 0)
            {
                m.Ex = false;
                r.I = 4;
                while (!r.End)
                {
                    var it = new MenuItem { Flags = r.U16() };
                    if ((it.Flags & 0x10) == 0)  // not MF_POPUP
                    {
                        it.HasId = true;
                        it.Id = r.U16();
                    }
                    it.Text = r.WStr();
                    m.Items.Add(it);
                }
                return m;
            }
            m.Ex = true;
            m.Offset = offset;
            m.Head = new byte[offset];
            Array.Copy(data, 4, m.Head, 0, offset);
            r.I = 4 + offset;
            while (!r.End)
            {
                var it = new MenuItem { Type = r.U32(), State = r.U32(), Mid = r.U32(), Flags = r.U16() };
                it.Text = r.WStr();
                r.Align4();
                if ((it.Flags & 0x01) != 0)  // has a submenu: a help id before it
                {
                    it.HasHelp = true;
                    it.Help = r.U32();
                }
                m.Items.Add(it);
            }
            return m;
        }

        static byte[] WriteMenu(Menu m)
        {
            var w = new Writer();
            if (!m.Ex)
            {
                w.U16(0); w.U16(0);
                foreach (MenuItem it in m.Items)
                {
                    w.U16(it.Flags);
                    if (it.HasId) w.U16(it.Id);
                    w.WStr(it.Text);
                }
                return w.ToArray();
            }
            w.U16(1); w.U16(m.Offset); w.Raw(m.Head);
            foreach (MenuItem it in m.Items)
            {
                w.U32(it.Type); w.U32(it.State); w.U32(it.Mid); w.U16(it.Flags);
                w.WStr(it.Text);
                w.Align4();
                if (it.HasHelp) w.U32(it.Help);
            }
            return w.ToArray();
        }

        // --- dialogs --------------------------------------------------------------
        //
        // A name that is either none (0), an ordinal (0xFFFF + number) or a string.
        // Kept as: null, ("ord", number) via Ordinal, or a string.

        struct SzOrd
        {
            public bool None;
            public bool IsOrd;
            public ushort Ord;
            public string Str;
        }

        static SzOrd ReadSzOrd(Reader r)
        {
            ushort w = r.U16();
            if (w == 0) return new SzOrd { None = true };
            if (w == 0xFFFF) return new SzOrd { IsOrd = true, Ord = r.U16() };
            r.I -= 2;
            return new SzOrd { Str = r.WStr() };
        }

        static void WriteSzOrd(Writer w, SzOrd v)
        {
            if (v.None) { w.U16(0); return; }
            if (v.IsOrd) { w.U16(0xFFFF); w.U16(v.Ord); return; }
            w.WStr(v.Str);
        }

        sealed class Control
        {
            public bool ExHasHelp;
            public uint Help;
            public uint Style, ExStyle;
            public short X, Y, Cx, Cy;
            public uint Id;
            public SzOrd Cls;
            public SzOrd Text;
            public byte[] Extra;
        }

        sealed class Dialog
        {
            public bool Ex;
            public uint Help, ExStyle, Style;
            public short X, Y, Cx, Cy;
            public SzOrd Menu;
            public SzOrd Cls;
            public string Text;
            public bool HasFont;
            public ushort Size, Weight;
            public byte Italic, Charset;
            public string Font;
            public List<Control> Controls = new List<Control>();
        }

        static Dialog ReadDialog(byte[] data)
        {
            var r = new Reader(data);
            var d = new Dialog();
            // DIALOGEX starts 0x0001 0xFFFF.
            d.Ex = data.Length >= 4 && data[0] == 0x01 && data[1] == 0x00 && data[2] == 0xFF && data[3] == 0xFF;
            int n;
            if (d.Ex)
            {
                r.I = 4;
                d.Help = r.U32(); d.ExStyle = r.U32(); d.Style = r.U32();
                n = r.U16();
                d.X = r.S16(); d.Y = r.S16(); d.Cx = r.S16(); d.Cy = r.S16();
            }
            else
            {
                d.Style = r.U32(); d.ExStyle = r.U32();
                n = r.U16();
                d.X = r.S16(); d.Y = r.S16(); d.Cx = r.S16(); d.Cy = r.S16();
            }
            d.Menu = ReadSzOrd(r);
            d.Cls = ReadSzOrd(r);
            d.Text = r.WStr();
            if ((d.Style & 0x40) != 0)  // DS_SETFONT, also part of DS_SHELLFONT
            {
                if (d.Ex)
                {
                    d.Size = r.U16(); d.Weight = r.U16(); d.Italic = r.U8(); d.Charset = r.U8();
                }
                else
                {
                    d.Size = r.U16();
                }
                d.HasFont = true;
                d.Font = r.WStr();
            }
            for (int k = 0; k < n; k++)
            {
                r.Align4();
                var c = new Control();
                if (d.Ex)
                {
                    c.ExHasHelp = true;
                    c.Help = r.U32(); c.ExStyle = r.U32(); c.Style = r.U32();
                    c.X = r.S16(); c.Y = r.S16(); c.Cx = r.S16(); c.Cy = r.S16();
                    c.Id = r.U32();
                }
                else
                {
                    c.Style = r.U32(); c.ExStyle = r.U32();
                    c.X = r.S16(); c.Y = r.S16(); c.Cx = r.S16(); c.Cy = r.S16();
                    c.Id = r.U16();
                }
                c.Cls = ReadSzOrd(r);
                c.Text = ReadSzOrd(r);
                int extra = r.U16();
                c.Extra = r.Take(extra);
                d.Controls.Add(c);
            }
            return d;
        }

        static byte[] WriteDialog(Dialog d)
        {
            var w = new Writer();
            int n = d.Controls.Count;
            if (d.Ex)
            {
                w.U16(1); w.U16(0xFFFF); w.U32(d.Help); w.U32(d.ExStyle); w.U32(d.Style);
                w.U16(n); w.U16((ushort)d.X); w.U16((ushort)d.Y); w.U16((ushort)d.Cx); w.U16((ushort)d.Cy);
            }
            else
            {
                w.U32(d.Style); w.U32(d.ExStyle);
                w.U16(n); w.U16((ushort)d.X); w.U16((ushort)d.Y); w.U16((ushort)d.Cx); w.U16((ushort)d.Cy);
            }
            WriteSzOrd(w, d.Menu);
            WriteSzOrd(w, d.Cls);
            w.WStr(d.Text);
            if (d.HasFont)
            {
                if (d.Ex)
                {
                    w.U16(d.Size); w.U16(d.Weight); w.U8(d.Italic); w.U8(d.Charset);
                }
                else
                {
                    w.U16(d.Size);
                }
                w.WStr(d.Font);
            }
            foreach (Control c in d.Controls)
            {
                w.Align4();
                if (d.Ex)
                {
                    w.U32(c.Help); w.U32(c.ExStyle); w.U32(c.Style);
                    w.U16((ushort)c.X); w.U16((ushort)c.Y); w.U16((ushort)c.Cx); w.U16((ushort)c.Cy);
                    w.U32(c.Id);
                }
                else
                {
                    w.U32(c.Style); w.U32(c.ExStyle);
                    w.U16((ushort)c.X); w.U16((ushort)c.Y); w.U16((ushort)c.Cx); w.U16((ushort)c.Cy);
                    w.U16((ushort)c.Id);
                }
                WriteSzOrd(w, c.Cls);
                WriteSzOrd(w, c.Text);
                w.U16(c.Extra.Length);
                w.Raw(c.Extra);
            }
            return w.ToArray();
        }

        // --- applying the recipe --------------------------------------------------

        // A string table with the given strings replaced by index.
        public static byte[] TranslateStrings(byte[] data, IDictionary<int, string> changes)
        {
            string[] texts = ReadStrings(data);
            foreach (KeyValuePair<int, string> kv in changes) texts[kv.Key] = kv.Value;
            return WriteStrings(texts);
        }

        // A menu with the given item texts replaced by index.
        public static byte[] TranslateMenu(byte[] data, IDictionary<int, string> changes)
        {
            Menu m = ReadMenu(data);
            foreach (KeyValuePair<int, string> kv in changes) m.Items[kv.Key].Text = kv.Value;
            return WriteMenu(m);
        }

        // A dialog with its caption, some control captions and some control
        // widths replaced. A control index is 0-based; the caption is separate.
        public static byte[] TranslateDialog(byte[] data, string caption,
            IDictionary<int, string> controls, IDictionary<int, int> widths)
        {
            Dialog d = ReadDialog(data);
            if (caption != null) d.Text = caption;
            if (controls != null)
            {
                foreach (KeyValuePair<int, string> kv in controls)
                {
                    Control c = d.Controls[kv.Key];
                    if (!c.Text.None && !c.Text.IsOrd) c.Text = new SzOrd { Str = kv.Value };
                }
            }
            if (widths != null)
            {
                foreach (KeyValuePair<int, int> kv in widths) d.Controls[kv.Key].Cx = (short)kv.Value;
            }
            return WriteDialog(d);
        }
    }
}
