// See Translation.h.

#include "Translation.h"
#include "IcqResources.h"
#include "../common/Ps.h"

#include <windows.h>

#include <cerrno>
#include <climits>
#include <cmath>
#include <cwchar>

namespace
{
    // --- the recipe as the exe carries it -------------------------------------

    // The recipe, as text. The one place that knows how and where it is
    // stored - an RCDATA resource of the exe, the JSON file as it is (app.rc)
    // - so another way of carrying it only changes this function.
    std::wstring LoadRecipe()
    {
        HMODULE self = GetModuleHandleW(nullptr);
        HRSRC r = FindResourceW(self, L"TRANSLATION", MAKEINTRESOURCEW(10));  // RT_RCDATA
        if (r == nullptr) throw PatchError{ L"The translation is missing from the exe: ICQ-2003b-uk-UA.json" };
        size_t size = SizeofResource(self, r);
        const char* data = (const char*)LockResource(LoadResource(self, r));
        std::wstring text = ps::FromUtf8(std::string(data, size));
        // As StreamReader reads UTF-8: a byte order mark is not text.
        if (!text.empty() && text[0] == 0xFEFF) text.erase(0, 1);
        return text;
    }

    // --- JSON -----------------------------------------------------------------
    //
    // Read the way the C# patch reads it, as PowerShell's ConvertFrom-Json
    // did: an object keeps the order of its members and finds them ignoring
    // case; numbers are whole (long long) where they can be.

    struct JsonMember;

    struct JsonValue
    {
        enum Kind { Null, Bool, Number, String, Array, Object };
        Kind What = Null;
        bool Flag = false;
        bool Whole = false;  // a whole number, in Int; else in Real
        long long Int = 0;
        double Real = 0;
        std::wstring Text;
        std::vector<JsonValue> Items;
        std::vector<JsonMember> Members;

        // A member of an object by name, ignoring case; nothing when this is
        // not an object or has no such member.
        const JsonValue* operator[](const wchar_t* name) const;
    };

    struct JsonMember
    {
        std::wstring Name;
        JsonValue Value;
    };

    const JsonValue* JsonValue::operator[](const wchar_t* name) const
    {
        if (What != Object) return nullptr;
        for (const JsonMember& m : Members)
        {
            if (ps::OrdinalIgnoreCaseEq(m.Name, name)) return &m.Value;
        }
        return nullptr;
    }

    [[noreturn]] void Bad(const std::wstring& what, size_t at)
    {
        throw PatchError{ L"The translation in the exe is damaged - JSON: " + what + L" at " + ps::Num((long long)at) };
    }

    class JsonParser
    {
    public:
        explicit JsonParser(const std::wstring& text) : s_(text) {}

        JsonValue Parse()
        {
            JsonValue v = Value();
            Space();
            if (i_ != s_.size()) Bad(L"text after the value", i_);
            return v;
        }

    private:
        wchar_t At()
        {
            if (i_ >= s_.size()) Bad(L"unexpected end", i_);
            return s_[i_];
        }

        void Space()
        {
            while (i_ < s_.size() && ps::IsWhiteSpace(s_[i_])) i_++;
        }

        bool Word(const wchar_t* w)
        {
            size_t n = wcslen(w);
            if (s_.compare(i_, n, w) != 0) return false;
            i_ += n;
            return true;
        }

        JsonValue Value()
        {
            Space();
            wchar_t c = At();
            JsonValue v;
            if (c == L'{')
            {
                v.What = JsonValue::Object;
                i_++;
                Space();
                if (At() == L'}')
                {
                    i_++;
                    return v;
                }
                while (true)
                {
                    Space();
                    JsonMember m;
                    m.Name = Str();
                    Space();
                    if (At() != L':') Bad(L"':' expected", i_);
                    i_++;
                    m.Value = Value();
                    v.Members.push_back(std::move(m));
                    Space();
                    if (At() == L',')
                    {
                        i_++;
                        continue;
                    }
                    if (At() == L'}')
                    {
                        i_++;
                        return v;
                    }
                    Bad(L"',' or '}' expected", i_);
                }
            }
            if (c == L'[')
            {
                v.What = JsonValue::Array;
                i_++;
                Space();
                if (At() == L']')
                {
                    i_++;
                    return v;
                }
                while (true)
                {
                    v.Items.push_back(Value());
                    Space();
                    if (At() == L',')
                    {
                        i_++;
                        continue;
                    }
                    if (At() == L']')
                    {
                        i_++;
                        return v;
                    }
                    Bad(L"',' or ']' expected", i_);
                }
            }
            if (c == L'"')
            {
                v.What = JsonValue::String;
                v.Text = Str();
                return v;
            }
            if (Word(L"null")) return v;
            if (Word(L"true"))
            {
                v.What = JsonValue::Bool;
                v.Flag = true;
                return v;
            }
            if (Word(L"false"))
            {
                v.What = JsonValue::Bool;
                return v;
            }
            size_t start = i_;
            while (i_ < s_.size() && wcschr(L"+-0123456789.eE", s_[i_]) != nullptr && s_[i_] != 0) i_++;
            std::wstring num = s_.substr(start, i_ - start);
            if (num.empty()) Bad(L"value expected", start);
            v.What = JsonValue::Number;
            wchar_t* end = nullptr;
            errno = 0;
            long long l = _wcstoi64(num.c_str(), &end, 10);
            if (*end == 0 && errno == 0)
            {
                v.Whole = true;
                v.Int = l;
                return v;
            }
            v.Real = wcstod(num.c_str(), &end);
            if (*end != 0) Bad(L"not a number", start);
            return v;
        }

        std::wstring Str()
        {
            if (At() != L'"') Bad(L"string expected", i_);
            i_++;
            std::wstring out;
            while (true)
            {
                wchar_t c = At();
                i_++;
                if (c == L'"') return out;
                if (c != L'\\')
                {
                    out += c;
                    continue;
                }
                wchar_t e = At();
                i_++;
                switch (e)
                {
                case L'"': out += L'"'; break;
                case L'\\': out += L'\\'; break;
                case L'/': out += L'/'; break;
                case L'b': out += L'\b'; break;
                case L'f': out += L'\f'; break;
                case L'n': out += L'\n'; break;
                case L'r': out += L'\r'; break;
                case L't': out += L'\t'; break;
                case L'u':
                {
                    if (i_ + 4 > s_.size()) Bad(L"unexpected end", i_);
                    unsigned code = 0;
                    for (int k = 0; k < 4; k++)
                    {
                        wchar_t h = s_[i_ + k];
                        unsigned d = h >= L'0' && h <= L'9' ? h - L'0'
                                   : h >= L'a' && h <= L'f' ? h - L'a' + 10
                                   : h >= L'A' && h <= L'F' ? h - L'A' + 10 : 16;
                        if (d > 15) Bad(L"bad escape", i_ - 1);
                        code = code * 16 + d;
                    }
                    out += (wchar_t)code;
                    i_ += 4;
                    break;
                }
                default: Bad(L"bad escape", i_ - 1);
                }
            }
        }

        const std::wstring& s_;
        size_t i_ = 0;
    };

    // A list as the C# patch reads one: none as none, an array as it is,
    // anything else as a list of one.
    std::vector<const JsonValue*> ListOf(const JsonValue* v)
    {
        std::vector<const JsonValue*> out;
        if (v == nullptr || v->What == JsonValue::Null) return out;
        if (v->What != JsonValue::Array)
        {
            out.push_back(v);
            return out;
        }
        for (const JsonValue& it : v->Items) out.push_back(&it);
        return out;
    }

    const JsonValue* ObjectOr(const JsonValue* v) { return v != nullptr && v->What == JsonValue::Object ? v : nullptr; }

    // Convert.ToInt64 of what the parser gave: a whole number as it is, a
    // fraction rounded to even, a text read as a number.
    long long AsLong(const JsonValue* v)
    {
        if (v != nullptr && v->What == JsonValue::Number) return v->Whole ? v->Int : (long long)std::nearbyint(v->Real);
        if (v != nullptr && v->What == JsonValue::Bool) return v->Flag ? 1 : 0;
        if (v != nullptr && v->What == JsonValue::String)
        {
            wchar_t* end = nullptr;
            std::wstring t = ps::Trim(v->Text);
            long long n = _wcstoi64(t.c_str(), &end, 10);
            if (!t.empty() && *end == 0) return n;
        }
        if (v == nullptr || v->What == JsonValue::Null) return 0;
        throw PatchError{ L"The translation in the exe is damaged: a number expected." };
    }

    // A text of the recipe; "" where there is none.
    std::wstring AsText(const JsonValue* v)
    {
        if (v == nullptr || v->What == JsonValue::Null) return L"";
        if (v->What != JsonValue::String) throw PatchError{ L"The translation in the exe is damaged: a text expected." };
        return v->Text;
    }

    // "type|name|lang"; a numeric name is written "#123", as the resource
    // reader expects.
    std::wstring KeyOf(const JsonValue* type, const JsonValue* name, const JsonValue* lang)
    {
        std::wstring n = name != nullptr && name->What == JsonValue::String ? name->Text : L"#" + ps::Num(AsLong(name));
        return ps::Num(AsLong(type)) + L"|" + n + L"|" + ps::Num(AsLong(lang));
    }

    int Index(const std::wstring& key)
    {
        wchar_t* end = nullptr;
        std::wstring t = ps::Trim(key);
        long long n = _wcstoi64(t.c_str(), &end, 10);
        if (t.empty() || *end != 0 || n < INT_MIN || n > INT_MAX) throw PatchError{ L"The translation in the exe is damaged: an index expected." };
        return (int)n;
    }

    std::optional<IndexedTexts> MapStr(const JsonValue* v)
    {
        if (ObjectOr(v) == nullptr) return std::nullopt;
        IndexedTexts m;
        for (const JsonMember& kv : v->Members) m.push_back({ Index(kv.Name), AsText(&kv.Value) });
        return m;
    }

    std::optional<IndexedWidths> MapInt(const JsonValue* v)
    {
        if (ObjectOr(v) == nullptr) return std::nullopt;
        IndexedWidths m;
        for (const JsonMember& kv : v->Members) m.push_back({ Index(kv.Name), (int)AsLong(&kv.Value) });
        return m;
    }

    // A text in a Windows code page (Encoding.GetEncoding(cp).GetBytes: a
    // character the page lacks is written as its closest fit, else '?').
    Bytes CodePage(unsigned cp, const std::wstring& text)
    {
        if (text.empty()) return Bytes();
        int n = WideCharToMultiByte(cp, 0, text.c_str(), (int)text.size(), nullptr, 0, nullptr, nullptr);
        Bytes out((size_t)(n > 0 ? n : 0));
        if (n > 0) WideCharToMultiByte(cp, 0, text.c_str(), (int)text.size(), (char*)&out[0], n, nullptr, nullptr);
        return out;
    }

    Bytes Utf16(const std::wstring& text)
    {
        Bytes out;
        for (wchar_t c : text)
        {
            out.push_back((unsigned char)c);
            out.push_back((unsigned char)(c >> 8));
        }
        return out;
    }

    // Shorter than its slot, a text is padded with zeros to fill it.
    Bytes Pad(Bytes b, int slot)
    {
        if (slot > 0 && b.size() < (size_t)slot) b.resize((size_t)slot, 0);
        return b;
    }

    Translation Parse(const std::wstring& text)
    {
        JsonValue doc = JsonParser(text).Parse();
        Translation t;
        if (const JsonValue* sb = ObjectOr(doc[L"sendBy"]))
        {
            t.SendBy.File = AsText((*sb)[L"file"]);
            t.SendBy.Key = KeyOf((*sb)[L"type"], (*sb)[L"name"], (*sb)[L"lang"]);
            t.SendBy.From = AsText((*sb)[L"from"]);
            t.SendBy.Index = (int)AsLong((*sb)[L"index"]);
            t.SendBy.Blank = AsText((*sb)[L"blank"]);
        }
        if (const JsonValue* files = ObjectOr(doc[L"files"]))
        {
            for (const JsonMember& f : files->Members)
            {
                const JsonValue& v = f.Value;
                TrFile file;
                file.Rel = f.Name;
                file.Size = AsLong(v[L"size"]);
                for (const JsonValue* ro : ListOf(v[L"resources"]))
                {
                    ResRecipe r;
                    r.Type = (int)AsLong((*ro)[L"type"]);
                    r.Key = KeyOf((*ro)[L"type"], (*ro)[L"name"], (*ro)[L"lang"]);
                    r.From = AsText((*ro)[L"from"]);
                    r.Strings = MapStr((*ro)[L"strings"]);
                    r.Items = MapStr((*ro)[L"items"]);
                    const JsonValue* caption = (*ro)[L"caption"];
                    if (caption != nullptr && caption->What == JsonValue::String) r.Caption = caption->Text;
                    r.Controls = MapStr((*ro)[L"controls"]);
                    r.Widths = MapInt((*ro)[L"widths"]);
                    file.Resources.push_back(std::move(r));
                }
                for (const JsonValue* p : ListOf(v[L"inplace"]))
                {
                    // ansi: Cyrillic (1251) for the Ukrainian text, Western
                    // (1252) for the English one; anything else UTF-16.
                    bool ansi = AsText((*p)[L"encoding"]) == L"ansi";
                    int slot = (int)AsLong((*p)[L"slot"]);
                    std::wstring uk = AsText((*p)[L"uk"]), en = AsText((*p)[L"en"]);
                    TrPlace pl;
                    pl.Offset = (int)AsLong((*p)[L"offset"]);
                    pl.Data = Pad(ansi ? CodePage(1251, uk) : Utf16(uk), slot);
                    pl.Original = Pad(ansi ? CodePage(1252, en) : Utf16(en), slot);
                    file.Inplace.push_back(std::move(pl));
                }
                if (const JsonValue* whole = ObjectOr(v[L"whole"]))
                {
                    file.HasWhole = true;
                    file.Whole = CodePage(1251, AsText((*whole)[L"text"]));
                    file.WholeFrom = AsText((*whole)[L"from"]);
                }
                t.Files.push_back(std::move(file));
            }
        }
        return t;
    }
}

Bytes ResRecipe::Build(const Bytes& original) const
{
    static const IndexedTexts empty;
    switch (Type)
    {
    case ResourceCodec::RtString: return ResourceCodec::TranslateStrings(original, Strings ? *Strings : empty);
    case ResourceCodec::RtMenu: return ResourceCodec::TranslateMenu(original, Items ? *Items : empty);
    default:
        return ResourceCodec::TranslateDialog(original, Caption, Controls ? &*Controls : nullptr, Widths ? &*Widths : nullptr);
    }
}

const Bytes* MatFile::ByKey(const std::wstring& key) const
{
    for (const MatItem& it : Items)
    {
        if (ps::Eq(it.Key, key)) return &it.Data;
    }
    return nullptr;
}

const TrFile* Translation::File(const std::wstring& rel) const
{
    for (const TrFile& f : Files)
    {
        if (ps::OrdinalIgnoreCaseEq(f.Rel, rel)) return &f;
    }
    return nullptr;
}

MatFile Translation::Materialize(const TrFile& file, const Bytes& originalFileBytes) const
{
    MatFile mat;
    if (!file.Resources.empty())
    {
        std::vector<std::wstring> keys;
        for (const ResRecipe& r : file.Resources) keys.push_back(r.Key);
        std::vector<std::optional<Bytes>> orig = IcqResources::Read(originalFileBytes, keys);
        for (size_t i = 0; i < file.Resources.size(); i++)
        {
            const ResRecipe& r = file.Resources[i];
            if (!orig[i]) continue;
            // A key the recipe lists twice keeps the hash of its first record.
            std::wstring from = r.From;
            for (size_t j = 0; j < i; j++)
            {
                if (file.Resources[j].Key == r.Key)
                {
                    from = file.Resources[j].From;
                    break;
                }
            }
            mat.Items.push_back(MatItem{ r.Key, r.Build(*orig[i]), from });
        }
    }
    if (ps::IsTrue(SendBy.Key) && ps::Eq(file.Rel, SendBy.File))
    {
        std::optional<Bytes> sbOrig = IcqResources::Read(originalFileBytes, { SendBy.Key })[0];
        if (sbOrig)
        {
            std::vector<std::wstring> orig = ResourceCodec::ReadStrings(*sbOrig);
            std::vector<std::wstring> translated = orig;
            for (const ResRecipe& r : file.Resources)
            {
                if (!ps::Eq(r.Key, SendBy.Key)) continue;
                if (r.Strings)
                {
                    for (const auto& kv : *r.Strings)
                    {
                        if (kv.first < 0 || (size_t)kv.first >= translated.size()) throw PatchError{ L"Index was outside the bounds of the array." };
                        translated[(size_t)kv.first] = kv.second;
                    }
                }
                break;
            }
            if (SendBy.Index < 0 || (size_t)SendBy.Index >= orig.size()) throw PatchError{ L"Index was outside the bounds of the array." };
            std::vector<std::wstring> blankEn = orig, blankUk = translated;
            blankEn[(size_t)SendBy.Index] = blankUk[(size_t)SendBy.Index] = SendBy.Blank;
            mat.BlankEn = ResourceCodec::WriteStrings(blankEn);
            mat.BlankUk = ResourceCodec::WriteStrings(blankUk);
        }
    }
    return mat;
}

const Translation& Translation::Get()
{
    static Translation* loaded = nullptr;
    if (loaded == nullptr) loaded = new Translation(Parse(LoadRecipe()));
    return *loaded;
}
