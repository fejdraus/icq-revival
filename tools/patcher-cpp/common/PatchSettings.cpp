// See PatchSettings.h.

#include "PatchSettings.h"
#include "PatchFiles.h"
#include "Registry.h"

namespace PatchSettings
{
    OptStr Read(const std::wstring& settingsKey, const std::wstring& name)
    {
        try
        {
            Reg::Key key = Reg::Open(HKEY_CURRENT_USER, settingsKey, false);
            if (!key) return std::nullopt;
            OptStr text = Reg::Text(Reg::GetValue(key, name));
            return text ? *text : std::wstring();
        }
        catch (const PatchError&)
        {
            return std::nullopt;
        }
    }

    void Save(const std::wstring& settingsKey, const std::wstring& name, const std::wstring& value)
    {
        try
        {
            Reg::Key key = Reg::Create(HKEY_CURRENT_USER, settingsKey);
            Reg::SetString(key, name, value, REG_SZ);
        }
        catch (const PatchError&)
        {
        }
    }
}

namespace Domain
{
    namespace
    {
        // A character in a class of a pattern with IgnoreCase: the character
        // is lower-cased by the culture first, as .NET's Regex does.
        bool IsLetter(wchar_t c)
        {
            wchar_t l = ps::Lower(c);
            return (l >= L'a' && l <= L'z') || (l >= L'A' && l <= L'Z');
        }

        bool IsDigit(wchar_t c)
        {
            wchar_t l = ps::Lower(c);
            return l >= L'0' && l <= L'9';
        }

        // ^[A-Za-z][A-Za-z0-9+.-]*://
        size_t SchemeLength(const std::wstring& v)
        {
            if (v.empty() || !IsLetter(v[0])) return 0;
            size_t i = 1;
            while (i < v.size())
            {
                wchar_t l = ps::Lower(v[i]);
                if (IsLetter(v[i]) || IsDigit(v[i]) || l == L'+' || l == L'.' || l == L'-') i++;
                else break;
            }
            if (v.compare(i, 3, L"://") == 0) return i + 3;
            return 0;
        }

        // [a-z0-9]([a-z0-9-]*[a-z0-9])? - one label of a domain.
        bool IsLabel(const std::wstring& s)
        {
            if (s.empty()) return false;
            for (size_t i = 0; i < s.size(); i++)
            {
                bool alnum = IsLetter(s[i]) || IsDigit(s[i]);
                bool hyphen = ps::Lower(s[i]) == L'-';
                if (!alnum && !(hyphen && i > 0 && i + 1 < s.size())) return false;
            }
            return true;
        }
    }

    std::wstring Of(const OptStr& value)
    {
        std::wstring v = ps::Trim(ps::Or(value));
        v = v.substr(SchemeLength(v));
        size_t cut = 0;
        while (cut < v.size())
        {
            wchar_t l = ps::Lower(v[cut]);
            if (l == L'/' || l == L'?' || l == L'#') break;
            cut++;
        }
        v = v.substr(0, cut);
        size_t colon = v.find(L':');
        if (colon != std::wstring::npos) v = v.substr(0, colon);
        return ps::ToLowerInvariant(v);
    }

    bool IsValid(const OptStr& value)
    {
        // ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$
        // with IgnoreCase; $ also matches before a final line feed.
        std::wstring s = ps::Or(value);
        if (!s.empty() && s.back() == L'\n') s.pop_back();
        std::vector<std::wstring> labels = ps::Split(s, L".", false);
        if (labels.size() < 2) return false;
        for (const std::wstring& l : labels)
        {
            if (!IsLabel(l)) return false;
        }
        return true;
    }
}
