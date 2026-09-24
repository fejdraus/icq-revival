// Registry values with the behaviour of .NET's RegistryKey, which the C#
// patches read and write them with - so a value reads as the same text.
//
// The patches ran as 64-bit processes, where HKLM\SOFTWARE is the 64-bit
// view and SOFTWARE\WOW6432Node the 32-bit one. This exe is 32-bit, so HKLM
// is opened with the 64-bit view wherever Windows is 64-bit; on 32-bit
// Windows there is only the one.

#pragma once

#include "Ps.h"

#include <windows.h>

#include <optional>
#include <string>
#include <vector>

namespace Reg
{
    // A value as it is stored.
    struct Value
    {
        DWORD Type = REG_NONE;
        std::vector<unsigned char> Data;
    };

    // Whether Windows is 64-bit (Environment.Is64BitOperatingSystem).
    bool Is64BitOs();

    // A key, closed when it goes. Empty when it could not be opened.
    class Key
    {
    public:
        Key() = default;
        explicit Key(HKEY h) : h_(h) {}
        ~Key();
        Key(Key&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
        Key& operator=(Key&& o) noexcept;
        Key(const Key&) = delete;
        Key& operator=(const Key&) = delete;
        explicit operator bool() const { return h_ != nullptr; }
        HKEY Get() const { return h_; }

    private:
        HKEY h_ = nullptr;
    };

    // OpenSubKey / CreateSubKey. Machine keys are opened in the 64-bit view.
    // Open gives an empty key when there is none; an error other than "not
    // there" is thrown as a PatchError, as .NET throws it.
    // A key under another is opened in the view of the hive it is under:
    // machine tells.
    Key Open(HKEY hive, const std::wstring& path, bool writable);
    Key Open(HKEY parent, const std::wstring& path, bool writable, bool machine);
    Key Create(HKEY hive, const std::wstring& path);

    // GetValue; nothing when the value is not there.
    std::optional<Value> GetValue(const Key& key, const std::wstring& name);
    // The names of the subkeys, in the order the registry gives them.
    std::vector<std::wstring> SubKeyNames(const Key& key);

    // A value as PowerShell turns it into a string: a multi-string's parts
    // joined by spaces, a number in decimal, an expandable string expanded.
    OptStr Text(const std::optional<Value>& value);
    // A value as a list of strings: a multi-string as it is, any other value
    // as its one string.
    std::vector<std::wstring> Strings(const std::optional<Value>& value);

    // SetValue of a string as a given kind (REG_SZ, REG_EXPAND_SZ,
    // REG_MULTI_SZ as one string, REG_DWORD / REG_QWORD as a number).
    void SetString(const Key& key, const std::wstring& name, const std::wstring& value, DWORD type);
    void SetMultiString(const Key& key, const std::wstring& name, const std::vector<std::wstring>& values);
    // DeleteValue without complaint when it is not there.
    void DeleteValue(const Key& key, const std::wstring& name);
}
