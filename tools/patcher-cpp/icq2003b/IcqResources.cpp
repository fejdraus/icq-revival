// See IcqResources.h.

#include "IcqResources.h"

#include <windows.h>

namespace IcqResources
{
    namespace
    {
        // int.Parse / int.TryParse of the invariant culture: blanks around, a sign.
        bool ParseInt(const std::wstring& text, int& out)
        {
            std::wstring s = ps::Trim(text);
            size_t i = 0;
            bool negative = false;
            if (i < s.size() && (s[i] == L'-' || s[i] == L'+')) negative = s[i++] == L'-';
            if (i >= s.size()) return false;
            long long n = 0;
            for (; i < s.size(); i++)
            {
                if (s[i] < L'0' || s[i] > L'9') return false;
                n = n * 10 + (s[i] - L'0');
                if (n > 0x80000000LL) return false;
            }
            if (negative) n = -n;
            if (n > 0x7FFFFFFFLL || n < -0x80000000LL) return false;
            out = (int)n;
            return true;
        }

        bool IsId(const std::wstring& name, int& id)
        {
            id = 0;
            return !name.empty() && name[0] == L'#' && ParseInt(name.substr(1), id);
        }

        LPCWSTR NameOf(const Key& k, int& id)
        {
            return IsId(k.Name, id) ? MAKEINTRESOURCEW(id) : k.Name.c_str();
        }
    }

    Key Key::Parse(const std::wstring& key)
    {
        std::vector<std::wstring> p = ps::Split(key, L"|", false);
        Key k;
        if (p.size() < 3 || !ParseInt(p[0], k.Type) || !ParseInt(p[2], k.Lang)) throw PatchError{ L"Input string was not in a correct format." };
        k.Name = p[1];
        return k;
    }

    std::vector<std::optional<Bytes>> Read(const std::wstring& file, const std::vector<Key>& keys)
    {
        std::vector<std::optional<Bytes>> result(keys.size());
        // As a data file and as an image resource; XP knows only the first.
        HMODULE module = LoadLibraryExW(file.c_str(), nullptr, 0x22);
        if (module == nullptr) module = LoadLibraryExW(file.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
        if (module == nullptr) return result;
        for (size_t i = 0; i < keys.size(); i++)
        {
            int id;
            LPCWSTR name = NameOf(keys[i], id);
            HRSRC res = FindResourceExW(module, MAKEINTRESOURCEW(keys[i].Type), name, (WORD)keys[i].Lang);
            if (res == nullptr) continue;
            DWORD size = SizeofResource(module, res);
            const unsigned char* p = (const unsigned char*)LockResource(LoadResource(module, res));
            result[i] = p != nullptr ? Bytes(p, p + size) : Bytes(size, 0);
        }
        FreeLibrary(module);
        return result;
    }

    bool Same(const Bytes& a, const Bytes& b) { return a == b; }

    bool Same(const std::optional<Bytes>& a, const Bytes& b) { return a && *a == b; }

    void Write(const std::wstring& file, const std::vector<Key>& keys, const std::vector<Bytes>& data)
    {
        HANDLE update = BeginUpdateResourceW(file.c_str(), FALSE);
        if (update == nullptr) throw PatchError{ PatchFiles::SystemMessage(GetLastError()) };
        static unsigned char none = 0;
        for (size_t i = 0; i < keys.size(); i++)
        {
            int id;
            LPCWSTR name = NameOf(keys[i], id);
            void* bytes = data[i].empty() ? (void*)&none : (void*)data[i].data();
            if (!UpdateResourceW(update, MAKEINTRESOURCEW(keys[i].Type), name, (WORD)keys[i].Lang, bytes, (DWORD)data[i].size()))
            {
                DWORD e = GetLastError();
                EndUpdateResourceW(update, TRUE);
                throw PatchError{ PatchFiles::SystemMessage(e) };
            }
        }
        if (!EndUpdateResourceW(update, FALSE)) throw PatchError{ PatchFiles::SystemMessage(GetLastError()) };
    }
}
