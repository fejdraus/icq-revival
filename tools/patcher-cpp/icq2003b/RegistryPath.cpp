// See RegistryPath.h.

#include "RegistryPath.h"
#include "../common/PatchFiles.h"
#include "../common/Registry.h"

namespace RegistryPath
{
    namespace
    {
        HKEY Hive(const std::wstring& path, std::wstring& sub)
        {
            size_t colon = path.find(L":\\");
            if (colon == std::wstring::npos) throw PatchError{ L"not a registry path: " + path };
            std::wstring hive = path.substr(0, colon);
            sub = path.substr(colon + 2);
            if (ps::OrdinalIgnoreCaseEq(hive, L"HKLM")) return HKEY_LOCAL_MACHINE;
            if (ps::OrdinalIgnoreCaseEq(hive, L"HKCU")) return HKEY_CURRENT_USER;
            throw PatchError{ L"not a registry path: " + path };
        }

        Reg::Key Open(const std::wstring& path, bool writable)
        {
            std::wstring sub;
            HKEY hive = Hive(path, sub);
            return Reg::Open(hive, sub, writable);
        }
    }

    bool Exists(const std::wstring& path)
    {
        try
        {
            return (bool)Open(path, false);
        }
        catch (const PatchError&)
        {
            return false;
        }
    }

    OptStr Get(const std::wstring& path, const std::wstring& name)
    {
        try
        {
            Reg::Key k = Open(path, false);
            if (!k) return std::nullopt;
            return Reg::Text(Reg::GetValue(k, name));
        }
        catch (const PatchError&)
        {
            return std::nullopt;
        }
    }

    void Create(const std::wstring& path)
    {
        std::wstring sub;
        HKEY hive = Hive(path, sub);
        Reg::Create(hive, sub);
    }

    void Set(const std::wstring& path, const std::wstring& name, const std::wstring& value)
    {
        Reg::Key k = Open(path, true);
        if (!k) throw PatchError{ L"Cannot find path '" + path + L"' because it does not exist." };
        DWORD kind = REG_SZ;
        std::optional<Reg::Value> existing = Reg::GetValue(k, name);
        if (existing) kind = existing->Type;
        Reg::SetString(k, name, value, kind);
    }

    void Remove(const std::wstring& path, const std::wstring& name)
    {
        try
        {
            Reg::Key k = Open(path, true);
            Reg::DeleteValue(k, name);
        }
        catch (const PatchError&)
        {
        }
    }
}
