// See Registry.h.

#include "Registry.h"
#include "PatchFiles.h"

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif

namespace Reg
{
    bool Is64BitOs()
    {
        // IsWow64Process came with XP SP2; without it Windows is 32-bit.
        typedef BOOL(WINAPI * IsWow64Fn)(HANDLE, PBOOL);
        static int known = -1;
        if (known < 0)
        {
            BOOL wow = FALSE;
            IsWow64Fn fn = (IsWow64Fn)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
            if (fn == nullptr || !fn(GetCurrentProcess(), &wow)) wow = FALSE;
            known = wow ? 1 : 0;
        }
        return known == 1;
    }

    namespace
    {
        REGSAM View(HKEY hive)
        {
            return hive == HKEY_LOCAL_MACHINE && Is64BitOs() ? KEY_WOW64_64KEY : 0;
        }

        [[noreturn]] void Fail(LONG error)
        {
            if (error == ERROR_ACCESS_DENIED) throw PatchError{ L"Requested registry access is not allowed." };
            throw PatchError{ PatchFiles::SystemMessage((DWORD)error) };
        }
    }

    Key::~Key()
    {
        if (h_ != nullptr) RegCloseKey(h_);
    }

    Key& Key::operator=(Key&& o) noexcept
    {
        if (this != &o)
        {
            if (h_ != nullptr) RegCloseKey(h_);
            h_ = o.h_;
            o.h_ = nullptr;
        }
        return *this;
    }

    Key Open(HKEY hive, const std::wstring& path, bool writable)
    {
        return Open(hive, path, writable, hive == HKEY_LOCAL_MACHINE);
    }

    Key Open(HKEY parent, const std::wstring& path, bool writable, bool machine)
    {
        HKEY h = nullptr;
        REGSAM view = machine && Is64BitOs() ? KEY_WOW64_64KEY : 0;
        LONG r = RegOpenKeyExW(parent, path.c_str(), 0, (writable ? KEY_READ | KEY_WRITE : KEY_READ) | view, &h);
        if (r == ERROR_SUCCESS) return Key(h);
        if (r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND) return Key();
        Fail(r);
    }

    Key Create(HKEY hive, const std::wstring& path)
    {
        HKEY h = nullptr;
        LONG r = RegCreateKeyExW(hive, path.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE | View(hive), nullptr, &h, nullptr);
        if (r != ERROR_SUCCESS) Fail(r);
        return Key(h);
    }

    std::optional<Value> GetValue(const Key& key, const std::wstring& name)
    {
        if (!key) return std::nullopt;
        for (int attempt = 0; attempt < 8; attempt++)
        {
            DWORD type = 0, size = 0;
            LONG r = RegQueryValueExW(key.Get(), name.c_str(), nullptr, &type, nullptr, &size);
            if (r == ERROR_FILE_NOT_FOUND) return std::nullopt;
            if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA) return std::nullopt;
            Value v;
            v.Type = type;
            v.Data.resize(size);
            DWORD got = size;
            r = RegQueryValueExW(key.Get(), name.c_str(), nullptr, &type, v.Data.empty() ? nullptr : v.Data.data(), &got);
            if (r == ERROR_MORE_DATA) continue;
            if (r != ERROR_SUCCESS) return std::nullopt;
            v.Type = type;
            v.Data.resize(got);
            return v;
        }
        return std::nullopt;
    }

    std::vector<std::wstring> SubKeyNames(const Key& key)
    {
        std::vector<std::wstring> names;
        if (!key) return names;
        wchar_t buf[256];
        for (DWORD i = 0;; i++)
        {
            DWORD len = 256;
            LONG r = RegEnumKeyExW(key.Get(), i, buf, &len, nullptr, nullptr, nullptr, nullptr);
            if (r != ERROR_SUCCESS) break;
            names.push_back(std::wstring(buf, len));
        }
        return names;
    }

    namespace
    {
        // The UTF-16 units of a value, an odd last byte counted as a unit.
        std::wstring Units(const Value& v)
        {
            size_t n = (v.Data.size() + 1) / 2;
            std::wstring s(n, L'\0');
            if (!v.Data.empty()) memcpy(&s[0], v.Data.data(), v.Data.size());
            return s;
        }

        std::wstring Expand(const std::wstring& s)
        {
            DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
            if (n == 0) return s;
            std::wstring out(n, L'\0');
            n = ExpandEnvironmentStringsW(s.c_str(), &out[0], n);
            if (n == 0) return s;
            out.resize(n - 1);
            return out;
        }

        // What .NET makes of a value: a string, a list of them, or a number.
        struct Read
        {
            bool IsList = false;
            std::wstring Text;
            std::vector<std::wstring> List;
        };

        Read Interpret(const Value& v)
        {
            Read r;
            switch (v.Type)
            {
            case REG_SZ:
            case REG_EXPAND_SZ:
            {
                std::wstring s = Units(v);
                // One terminating null is dropped; one inside stays.
                if (!s.empty() && s.back() == L'\0') s.pop_back();
                r.Text = v.Type == REG_EXPAND_SZ ? Expand(s) : s;
                return r;
            }
            case REG_MULTI_SZ:
            {
                r.IsList = true;
                std::wstring blob = Units(v);
                if (!blob.empty() && blob.back() != L'\0') blob += L'\0';
                size_t cur = 0, len = blob.size();
                while (cur < len)
                {
                    size_t next = cur;
                    while (next < len && blob[next] != L'\0') next++;
                    if (next < len)
                    {
                        if (next - cur > 0) r.List.push_back(blob.substr(cur, next - cur));
                        else if (next != len - 1) r.List.push_back(L"");
                    }
                    else
                    {
                        r.List.push_back(blob.substr(cur, len - cur));
                    }
                    cur = next + 1;
                }
                return r;
            }
            case REG_DWORD:
                if (v.Data.size() >= 4)
                {
                    int n;
                    memcpy(&n, v.Data.data(), 4);
                    r.Text = ps::Num(n);
                    return r;
                }
                break;
            case REG_QWORD:
                if (v.Data.size() >= 8)
                {
                    long long n;
                    memcpy(&n, v.Data.data(), 8);
                    r.Text = ps::Num(n);
                    return r;
                }
                break;
            }
            // Bytes: Convert.ToString gives the name of the type.
            r.Text = L"System.Byte[]";
            return r;
        }
    }

    OptStr Text(const std::optional<Value>& value)
    {
        if (!value) return std::nullopt;
        Read r = Interpret(*value);
        if (r.IsList) return ps::Join(r.List, L" ");
        return r.Text;
    }

    std::vector<std::wstring> Strings(const std::optional<Value>& value)
    {
        if (!value) return {};
        Read r = Interpret(*value);
        if (r.IsList) return r.List;
        return { r.Text };
    }

    namespace
    {
        void Put(const Key& key, const std::wstring& name, DWORD type, const void* data, size_t size)
        {
            LONG r = RegSetValueExW(key.Get(), name.c_str(), 0, type, (const BYTE*)data, (DWORD)size);
            if (r != ERROR_SUCCESS) Fail(r);
        }

        const wchar_t* BadKind = L"The type of the value object did not match the specified RegistryValueKind or the object could not be properly converted.";

        // Convert.ToInt64 of a string, as the invariant culture reads it.
        bool ParseInteger(const std::wstring& text, long long min, long long max, long long& out)
        {
            std::wstring s = ps::Trim(text);
            size_t i = 0;
            bool negative = false;
            if (i < s.size() && (s[i] == L'-' || s[i] == L'+')) negative = s[i++] == L'-';
            if (i >= s.size()) return false;
            unsigned long long n = 0;
            for (; i < s.size(); i++)
            {
                if (s[i] < L'0' || s[i] > L'9') return false;
                n = n * 10 + (s[i] - L'0');
                if (n > 0x8000000000000000ull) return false;
            }
            long long v = negative ? (long long)(0 - n) : (long long)n;
            if ((!negative && n > 0x7FFFFFFFFFFFFFFFull) || v < min || v > max) return false;
            out = v;
            return true;
        }
    }

    void SetString(const Key& key, const std::wstring& name, const std::wstring& value, DWORD type)
    {
        switch (type)
        {
        case REG_SZ:
        case REG_EXPAND_SZ:
            Put(key, name, type, value.c_str(), (value.size() + 1) * sizeof(wchar_t));
            return;
        case REG_MULTI_SZ:
            SetMultiString(key, name, { value });
            return;
        case REG_DWORD:
        {
            long long n;
            if (!ParseInteger(value, INT_MIN, INT_MAX, n)) throw PatchError{ BadKind };
            int v = (int)n;
            Put(key, name, REG_DWORD, &v, 4);
            return;
        }
        case REG_QWORD:
        {
            long long n;
            if (!ParseInteger(value, LLONG_MIN, LLONG_MAX, n)) throw PatchError{ BadKind };
            Put(key, name, REG_QWORD, &n, 8);
            return;
        }
        default:
            throw PatchError{ BadKind };
        }
    }

    void SetMultiString(const Key& key, const std::wstring& name, const std::vector<std::wstring>& values)
    {
        std::wstring blob;
        for (const std::wstring& v : values)
        {
            blob += v;
            blob += L'\0';
        }
        blob += L'\0';
        Put(key, name, REG_MULTI_SZ, blob.c_str(), blob.size() * sizeof(wchar_t));
    }

    void DeleteValue(const Key& key, const std::wstring& name)
    {
        if (key) RegDeleteValueW(key.Get(), name.c_str());
    }
}
