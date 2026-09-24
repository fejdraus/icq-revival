// See Ps.h.

#include "Ps.h"

#include <cmath>

namespace ps
{
    namespace
    {
        // LOCALE_INVARIANT; spelt out, as the older SDK headers guard it.
        const LCID Invariant = MAKELCID(MAKELANGID(LANG_INVARIANT, SUBLANG_NEUTRAL), SORT_DEFAULT);

        bool Compare(LCID lcid, DWORD flags, const std::wstring& a, const std::wstring& b)
        {
            if (a.empty() && b.empty()) return true;
            int r = CompareStringW(lcid, flags, a.c_str(), (int)a.size(), b.c_str(), (int)b.size());
            // Should Windows refuse the comparison, the plain one.
            if (r == 0) return flags & NORM_IGNORECASE ? OrdinalIgnoreCaseEq(a, b) : a == b;
            return r == CSTR_EQUAL;
        }

        // Casing by the culture, as .NET does it for any culture but the
        // invariant one.
        const DWORD LinguisticCasing = 0x01000000;  // LCMAP_LINGUISTIC_CASING
        const DWORD CultureLower = LCMAP_LOWERCASE | LinguisticCasing;
        const DWORD CultureUpper = LCMAP_UPPERCASE | LinguisticCasing;

        // LCMapString, and again without linguistic casing where Windows
        // does not take the flag.
        int MapChars(LCID lcid, DWORD flags, const wchar_t* src, int n, wchar_t* dst, int size)
        {
            int r = LCMapStringW(lcid, flags, src, n, dst, size);
            if (r == 0 && (flags & LinguisticCasing)) r = LCMapStringW(lcid, flags & ~LinguisticCasing, src, n, dst, size);
            return r;
        }

        std::wstring Map(LCID lcid, DWORD flags, const std::wstring& s)
        {
            if (s.empty()) return s;
            int n = MapChars(lcid, flags, s.c_str(), (int)s.size(), nullptr, 0);
            if (n <= 0) return s;
            std::wstring out(n, L'\0');
            MapChars(lcid, flags, s.c_str(), (int)s.size(), &out[0], n);
            return out;
        }

        // Ordinal ignoring case: both sides upper-cased one character at a
        // time by the invariant table.
        wchar_t OrdinalUpper(wchar_t c)
        {
            if (c < 0x80) return (c >= L'a' && c <= L'z') ? (wchar_t)(c - 32) : c;
            wchar_t out = c;
            if (LCMapStringW(Invariant, LCMAP_UPPERCASE, &c, 1, &out, 1) != 1) return c;
            return out;
        }
    }

    bool Eq(const std::wstring& a, const std::wstring& b) { return Compare(Invariant, NORM_IGNORECASE, a, b); }
    bool Ceq(const std::wstring& a, const std::wstring& b) { return Compare(Invariant, 0, a, b); }
    bool KeyEq(const std::wstring& a, const std::wstring& b) { return Compare(LOCALE_USER_DEFAULT, NORM_IGNORECASE, a, b); }

    bool OrdinalIgnoreCaseEq(const std::wstring& a, const std::wstring& b)
    {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); i++)
        {
            if (a[i] != b[i] && OrdinalUpper(a[i]) != OrdinalUpper(b[i])) return false;
        }
        return true;
    }

    bool StartsWithOrdinalIgnoreCase(const std::wstring& s, const std::wstring& prefix)
    {
        return s.size() >= prefix.size() && OrdinalIgnoreCaseEq(s.substr(0, prefix.size()), prefix);
    }

    bool Contains(const std::vector<std::wstring>& list, const std::wstring& value)
    {
        for (const std::wstring& s : list)
        {
            if (Eq(s, value)) return true;
        }
        return false;
    }

    std::vector<std::wstring> Unique(const std::vector<std::wstring>& list)
    {
        std::vector<std::wstring> result;
        for (const std::wstring& s : list)
        {
            bool seen = false;
            for (const std::wstring& r : result)
            {
                if (r == s) { seen = true; break; }
            }
            if (!seen) result.push_back(s);
        }
        return result;
    }

    bool IsTrue(const std::vector<unsigned char>* value)
    {
        if (value == nullptr || value->empty()) return false;
        return value->size() > 1 || (*value)[0] != 0;
    }

    int Int(double value)
    {
        // Convert.ToInt32(double): to the nearest, a half to the even one.
        double r = std::floor(value);
        double diff = value - r;
        if (diff > 0.5 || (diff == 0.5 && std::fmod(r, 2.0) != 0)) r += 1;
        return (int)r;
    }

    bool IsWhiteSpace(wchar_t c)
    {
        if (c == L' ' || (c >= 0x09 && c <= 0x0D) || c == 0x85 || c == 0xA0) return true;
        if (c < 0x1680) return false;
        return c == 0x1680 || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 ||
               c == 0x202F || c == 0x205F || c == 0x3000;
    }

    std::wstring Trim(const std::wstring& s)
    {
        size_t a = 0, b = s.size();
        while (a < b && IsWhiteSpace(s[a])) a++;
        while (b > a && IsWhiteSpace(s[b - 1])) b--;
        return s.substr(a, b - a);
    }

    bool IsNullOrWhiteSpace(const OptStr& s)
    {
        if (!s) return true;
        for (wchar_t c : *s)
        {
            if (!IsWhiteSpace(c)) return false;
        }
        return true;
    }

    std::wstring TrimEnd(const std::wstring& s, const std::wstring& chars)
    {
        size_t b = s.size();
        while (b > 0 && chars.find(s[b - 1]) != std::wstring::npos) b--;
        return s.substr(0, b);
    }

    std::wstring TrimStart(const std::wstring& s, const std::wstring& chars)
    {
        size_t a = 0;
        while (a < s.size() && chars.find(s[a]) != std::wstring::npos) a++;
        return s.substr(a);
    }

    wchar_t Lower(wchar_t c)
    {
        // A table, filled on first use: a regex asks for every character.
        static wchar_t table[65536];
        static bool filled = false;
        if (!filled)
        {
            for (int i = 0; i < 65536; i++) table[i] = (wchar_t)i;
            // Surrogates and the private use area stay as they are.
            static wchar_t src[0xD800];
            for (int i = 0; i < 0xD800; i++) src[i] = (wchar_t)i;
            MapChars(LOCALE_USER_DEFAULT, CultureLower, src, 0xD800, table, 0xD800);
            static wchar_t src2[0x10000 - 0xF900];
            for (int i = 0xF900; i < 0x10000; i++) src2[i - 0xF900] = (wchar_t)i;
            MapChars(LOCALE_USER_DEFAULT, CultureLower, src2, 0x10000 - 0xF900, table + 0xF900, 0x10000 - 0xF900);
            filled = true;
        }
        return table[(unsigned short)c];
    }

    std::wstring ToLower(const std::wstring& s) { return Map(LOCALE_USER_DEFAULT, CultureLower, s); }
    std::wstring ToUpper(const std::wstring& s) { return Map(LOCALE_USER_DEFAULT, CultureUpper, s); }
    std::wstring ToLowerInvariant(const std::wstring& s) { return Map(Invariant, LCMAP_LOWERCASE, s); }

    size_t Find(const std::wstring& s, const std::wstring& needle, size_t from, bool ignoreCase)
    {
        if (!ignoreCase) return s.find(needle, from);
        if (needle.empty()) return from <= s.size() ? from : std::wstring::npos;
        for (size_t i = from; i + needle.size() <= s.size(); i++)
        {
            size_t k = 0;
            while (k < needle.size() && CharEqIgnoreCase(s[i + k], needle[k])) k++;
            if (k == needle.size()) return i;
        }
        return std::wstring::npos;
    }

    bool Has(const std::wstring& s, const std::wstring& needle, bool ignoreCase)
    {
        return Find(s, needle, 0, ignoreCase) != std::wstring::npos;
    }

    bool StartsWithIgnoreCase(const std::wstring& s, const std::wstring& prefix)
    {
        if (s.size() < prefix.size()) return false;
        for (size_t k = 0; k < prefix.size(); k++)
        {
            if (!CharEqIgnoreCase(s[k], prefix[k])) return false;
        }
        return true;
    }

    std::vector<std::wstring> Split(const std::wstring& s, const std::wstring& separator, bool ignoreCase)
    {
        std::vector<std::wstring> parts;
        size_t start = 0;
        for (;;)
        {
            size_t at = Find(s, separator, start, ignoreCase);
            if (at == std::wstring::npos) break;
            parts.push_back(s.substr(start, at - start));
            start = at + separator.size();
        }
        parts.push_back(s.substr(start));
        return parts;
    }

    std::wstring Replace(const std::wstring& s, const std::wstring& from, const std::wstring& to, bool ignoreCase)
    {
        std::wstring out;
        size_t start = 0;
        for (;;)
        {
            size_t at = Find(s, from, start, ignoreCase);
            if (at == std::wstring::npos) break;
            out.append(s, start, at - start);
            out += to;
            start = at + from.size();
        }
        out.append(s, start, std::wstring::npos);
        return out;
    }

    std::wstring Join(const std::vector<std::wstring>& parts, const std::wstring& separator)
    {
        std::wstring out;
        for (size_t i = 0; i < parts.size(); i++)
        {
            if (i > 0) out += separator;
            out += parts[i];
        }
        return out;
    }

    std::wstring Num(long long value)
    {
        wchar_t buf[32];
        swprintf_s(buf, L"%lld", value);
        return buf;
    }

    std::wstring Hex(unsigned long long value)
    {
        wchar_t buf[32];
        swprintf_s(buf, L"%llX", value);
        return buf;
    }

    bool StringSet::Contains(const std::wstring& s) const
    {
        for (const OptStr& slot : slots_)
        {
            if (slot && *slot == s) return true;
        }
        return false;
    }

    bool StringSet::Add(const std::wstring& s)
    {
        if (Contains(s)) return false;
        if (!free_.empty())
        {
            slots_[free_.back()] = s;
            free_.pop_back();
        }
        else
        {
            slots_.push_back(s);
        }
        count_++;
        return true;
    }

    bool StringSet::Remove(const std::wstring& s)
    {
        for (size_t i = 0; i < slots_.size(); i++)
        {
            if (slots_[i] && *slots_[i] == s)
            {
                slots_[i].reset();
                free_.push_back(i);
                count_--;
                // A HashSet that becomes empty starts its slots over.
                if (count_ == 0)
                {
                    slots_.clear();
                    free_.clear();
                }
                return true;
            }
        }
        return false;
    }

    std::vector<std::wstring> StringSet::Items() const
    {
        std::vector<std::wstring> out;
        for (const OptStr& slot : slots_)
        {
            if (slot) out.push_back(*slot);
        }
        return out;
    }

    std::string Utf8(const std::wstring& s)
    {
        if (s.empty()) return std::string();
        int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
        std::string out(n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n, nullptr, nullptr);
        return out;
    }

    std::wstring FromUtf8(const std::string& s)
    {
        if (s.empty()) return std::wstring();
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        std::wstring out(n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
        return out;
    }
}
