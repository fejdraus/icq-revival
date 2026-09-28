// See ResourceCodec.h.

#include "ResourceCodec.h"

#include <cstdint>

namespace ResourceCodec
{
    namespace
    {
        // What the C# port let through when a resource ends too soon or the
        // recipe names an index the resource does not have.
        [[noreturn]] void Truncated() { throw PatchError{ L"Index was outside the bounds of the array." }; }
        [[noreturn]] void NoIndex()
        {
            throw PatchError{ L"Index was out of range. Must be non-negative and less than the size of the collection." };
        }

        // A little-endian cursor over the resource bytes.
        class Reader
        {
        public:
            explicit Reader(const Bytes& data, size_t at = 0) : b_(data), I(at) {}

            size_t I;

            bool End() const { return I >= b_.size(); }
            uint16_t U16()
            {
                Need(2);
                uint16_t v = (uint16_t)(b_[I] | (b_[I + 1] << 8));
                I += 2;
                return v;
            }
            int16_t S16() { return (int16_t)U16(); }
            uint32_t U32()
            {
                Need(4);
                uint32_t v = (uint32_t)b_[I] | ((uint32_t)b_[I + 1] << 8) | ((uint32_t)b_[I + 2] << 16) | ((uint32_t)b_[I + 3] << 24);
                I += 4;
                return v;
            }
            uint8_t U8()
            {
                Need(1);
                return b_[I++];
            }
            Bytes Take(size_t n)
            {
                Need(n);
                Bytes r(b_.begin() + I, b_.begin() + I + n);
                I += n;
                return r;
            }
            // n UTF-16 characters.
            std::wstring Chars(size_t n)
            {
                Need(2 * n);
                std::wstring s(n, L'\0');
                for (size_t k = 0; k < n; k++) s[k] = (wchar_t)(b_[I + 2 * k] | (b_[I + 2 * k + 1] << 8));
                I += 2 * n;
                return s;
            }
            // A NUL-terminated UTF-16 string; the cursor lands past the terminator.
            std::wstring WStr()
            {
                size_t j = I;
                while (true)
                {
                    if (j + 2 > b_.size()) Truncated();
                    if (b_[j] == 0 && b_[j + 1] == 0) break;
                    j += 2;
                }
                std::wstring s = Chars((j - I) / 2);
                I = j + 2;
                return s;
            }
            void Align4() { I = (I + 3) & ~(size_t)3; }

        private:
            void Need(size_t n) const
            {
                if (I + n > b_.size()) Truncated();
            }

            const Bytes& b_;
        };

        class Writer
        {
        public:
            void U16(unsigned v)
            {
                b_.push_back((unsigned char)v);
                b_.push_back((unsigned char)(v >> 8));
            }
            void U32(uint32_t v)
            {
                for (int k = 0; k < 4; k++) b_.push_back((unsigned char)(v >> (8 * k)));
            }
            void U8(unsigned v) { b_.push_back((unsigned char)v); }
            void Raw(const Bytes& d) { b_.insert(b_.end(), d.begin(), d.end()); }
            void Chars(const std::wstring& s)
            {
                for (wchar_t c : s) U16(c);
            }
            void WStr(const std::wstring& s)
            {
                Chars(s);
                U16(0);
            }
            void Align4()
            {
                while (b_.size() % 4 != 0) b_.push_back(0);
            }
            Bytes& Data() { return b_; }

        private:
            Bytes b_;
        };

        // --- menus ------------------------------------------------------------

        struct MenuItem
        {
            bool HasId = false;
            uint16_t Flags = 0;
            uint16_t Id = 0;
            std::wstring Text;
            // extended
            uint32_t Type = 0, State = 0, Mid = 0;
            bool HasHelp = false;
            uint32_t Help = 0;
        };

        struct Menu
        {
            bool Ex = false;
            uint16_t Offset = 0;
            Bytes Head;
            std::vector<MenuItem> Items;
        };

        Menu ReadMenu(const Bytes& data)
        {
            Reader r(data);
            uint16_t version = r.U16();
            uint16_t offset = r.U16();
            Menu m;
            if (version == 0)
            {
                r.I = 4;
                while (!r.End())
                {
                    MenuItem it;
                    it.Flags = r.U16();
                    if ((it.Flags & 0x10) == 0)  // not MF_POPUP
                    {
                        it.HasId = true;
                        it.Id = r.U16();
                    }
                    it.Text = r.WStr();
                    m.Items.push_back(it);
                }
                return m;
            }
            m.Ex = true;
            m.Offset = offset;
            m.Head = r.Take(offset);
            r.I = 4 + (size_t)offset;
            while (!r.End())
            {
                MenuItem it;
                it.Type = r.U32();
                it.State = r.U32();
                it.Mid = r.U32();
                it.Flags = r.U16();
                it.Text = r.WStr();
                r.Align4();
                if ((it.Flags & 0x01) != 0)  // has a submenu: a help id before it
                {
                    it.HasHelp = true;
                    it.Help = r.U32();
                }
                m.Items.push_back(it);
            }
            return m;
        }

        Bytes WriteMenu(const Menu& m)
        {
            Writer w;
            if (!m.Ex)
            {
                w.U16(0);
                w.U16(0);
                for (const MenuItem& it : m.Items)
                {
                    w.U16(it.Flags);
                    if (it.HasId) w.U16(it.Id);
                    w.WStr(it.Text);
                }
                return w.Data();
            }
            w.U16(1);
            w.U16(m.Offset);
            w.Raw(m.Head);
            for (const MenuItem& it : m.Items)
            {
                w.U32(it.Type);
                w.U32(it.State);
                w.U32(it.Mid);
                w.U16(it.Flags);
                w.WStr(it.Text);
                w.Align4();
                if (it.HasHelp) w.U32(it.Help);
            }
            return w.Data();
        }

        // --- dialogs ----------------------------------------------------------
        //
        // A name that is either none (0), an ordinal (0xFFFF + number) or a
        // string.

        struct SzOrd
        {
            bool None = false;
            bool IsOrd = false;
            uint16_t Ord = 0;
            std::wstring Str;
        };

        SzOrd ReadSzOrd(Reader& r)
        {
            SzOrd v;
            uint16_t w = r.U16();
            if (w == 0)
            {
                v.None = true;
                return v;
            }
            if (w == 0xFFFF)
            {
                v.IsOrd = true;
                v.Ord = r.U16();
                return v;
            }
            r.I -= 2;
            v.Str = r.WStr();
            return v;
        }

        void WriteSzOrd(Writer& w, const SzOrd& v)
        {
            if (v.None)
            {
                w.U16(0);
                return;
            }
            if (v.IsOrd)
            {
                w.U16(0xFFFF);
                w.U16(v.Ord);
                return;
            }
            w.WStr(v.Str);
        }

        struct Control
        {
            uint32_t Help = 0;
            uint32_t Style = 0, ExStyle = 0;
            int16_t X = 0, Y = 0, Cx = 0, Cy = 0;
            uint32_t Id = 0;
            SzOrd Cls;
            SzOrd Text;
            Bytes Extra;
        };

        struct Dialog
        {
            bool Ex = false;
            uint32_t Help = 0, ExStyle = 0, Style = 0;
            int16_t X = 0, Y = 0, Cx = 0, Cy = 0;
            SzOrd Menu;
            SzOrd Cls;
            std::wstring Text;
            bool HasFont = false;
            uint16_t Size = 0, Weight = 0;
            uint8_t Italic = 0, Charset = 0;
            std::wstring Font;
            std::vector<Control> Controls;
        };

        Dialog ReadDialog(const Bytes& data)
        {
            Reader r(data);
            Dialog d;
            // DIALOGEX starts 0x0001 0xFFFF.
            d.Ex = data.size() >= 4 && data[0] == 0x01 && data[1] == 0x00 && data[2] == 0xFF && data[3] == 0xFF;
            int n;
            if (d.Ex)
            {
                r.I = 4;
                d.Help = r.U32();
                d.ExStyle = r.U32();
                d.Style = r.U32();
            }
            else
            {
                d.Style = r.U32();
                d.ExStyle = r.U32();
            }
            n = r.U16();
            d.X = r.S16();
            d.Y = r.S16();
            d.Cx = r.S16();
            d.Cy = r.S16();
            d.Menu = ReadSzOrd(r);
            d.Cls = ReadSzOrd(r);
            d.Text = r.WStr();
            if ((d.Style & 0x40) != 0)  // DS_SETFONT, also part of DS_SHELLFONT
            {
                d.Size = r.U16();
                if (d.Ex)
                {
                    d.Weight = r.U16();
                    d.Italic = r.U8();
                    d.Charset = r.U8();
                }
                d.HasFont = true;
                d.Font = r.WStr();
            }
            for (int k = 0; k < n; k++)
            {
                r.Align4();
                Control c;
                if (d.Ex)
                {
                    c.Help = r.U32();
                    c.ExStyle = r.U32();
                    c.Style = r.U32();
                }
                else
                {
                    c.Style = r.U32();
                    c.ExStyle = r.U32();
                }
                c.X = r.S16();
                c.Y = r.S16();
                c.Cx = r.S16();
                c.Cy = r.S16();
                c.Id = d.Ex ? r.U32() : r.U16();
                c.Cls = ReadSzOrd(r);
                c.Text = ReadSzOrd(r);
                size_t extra = r.U16();
                c.Extra = r.Take(extra);
                d.Controls.push_back(c);
            }
            return d;
        }

        Bytes WriteDialog(const Dialog& d)
        {
            Writer w;
            size_t n = d.Controls.size();
            if (d.Ex)
            {
                w.U16(1);
                w.U16(0xFFFF);
                w.U32(d.Help);
                w.U32(d.ExStyle);
                w.U32(d.Style);
            }
            else
            {
                w.U32(d.Style);
                w.U32(d.ExStyle);
            }
            w.U16((unsigned)n);
            w.U16((uint16_t)d.X);
            w.U16((uint16_t)d.Y);
            w.U16((uint16_t)d.Cx);
            w.U16((uint16_t)d.Cy);
            WriteSzOrd(w, d.Menu);
            WriteSzOrd(w, d.Cls);
            w.WStr(d.Text);
            if (d.HasFont)
            {
                w.U16(d.Size);
                if (d.Ex)
                {
                    w.U16(d.Weight);
                    w.U8(d.Italic);
                    w.U8(d.Charset);
                }
                w.WStr(d.Font);
            }
            for (const Control& c : d.Controls)
            {
                w.Align4();
                if (d.Ex)
                {
                    w.U32(c.Help);
                    w.U32(c.ExStyle);
                    w.U32(c.Style);
                }
                else
                {
                    w.U32(c.Style);
                    w.U32(c.ExStyle);
                }
                w.U16((uint16_t)c.X);
                w.U16((uint16_t)c.Y);
                w.U16((uint16_t)c.Cx);
                w.U16((uint16_t)c.Cy);
                if (d.Ex) w.U32(c.Id);
                else w.U16((uint16_t)c.Id);
                WriteSzOrd(w, c.Cls);
                WriteSzOrd(w, c.Text);
                w.U16((unsigned)c.Extra.size());
                w.Raw(c.Extra);
            }
            return w.Data();
        }

        // The element at a 0-based index the recipe gives.
        template <typename T>
        T& At(std::vector<T>& list, int index)
        {
            if (index < 0 || (size_t)index >= list.size()) NoIndex();
            return list[(size_t)index];
        }
    }

    // --- string tables ----------------------------------------------------------

    std::vector<std::wstring> ReadStrings(const Bytes& data)
    {
        Reader r(data);
        std::vector<std::wstring> out;
        while (out.size() < 16 && r.I + 2 <= data.size())
        {
            size_t n = r.U16();
            out.push_back(r.Chars(n));
        }
        while (out.size() < 16) out.push_back(L"");
        return out;
    }

    Bytes WriteStrings(const std::vector<std::wstring>& texts)
    {
        Writer w;
        for (const std::wstring& t : texts)
        {
            w.U16((unsigned)t.size());
            w.Chars(t);
        }
        return w.Data();
    }

    // --- applying the recipe ----------------------------------------------------

    Bytes TranslateStrings(const Bytes& data, const IndexedTexts& changes)
    {
        std::vector<std::wstring> texts = ReadStrings(data);
        for (const auto& kv : changes) At(texts, kv.first) = kv.second;
        return WriteStrings(texts);
    }

    Bytes TranslateMenu(const Bytes& data, const IndexedTexts& changes)
    {
        Menu m = ReadMenu(data);
        for (const auto& kv : changes) At(m.Items, kv.first).Text = kv.second;
        return WriteMenu(m);
    }

    Bytes TranslateDialog(const Bytes& data, const OptStr& caption, const IndexedTexts* controls,
                          const IndexedWidths* widths)
    {
        Dialog d = ReadDialog(data);
        if (caption) d.Text = *caption;
        if (controls != nullptr)
        {
            for (const auto& kv : *controls)
            {
                Control& c = At(d.Controls, kv.first);
                // A control named by an ordinal (an icon, a bitmap) or not at
                // all keeps that.
                if (!c.Text.None && !c.Text.IsOrd) c.Text.Str = kv.second;
            }
        }
        if (widths != nullptr)
        {
            for (const auto& kv : *widths) At(d.Controls, kv.first).Cx = (int16_t)kv.second;
        }
        return WriteDialog(d);
    }
}
