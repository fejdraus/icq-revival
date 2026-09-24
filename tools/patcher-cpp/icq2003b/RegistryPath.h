// Registry values by PowerShell-style paths (HKLM:\..., HKCU:\...) - the
// port of tools\patcher\Icq2003b\RegistryPath.cs, with the behaviour of the
// cmdlets the patch was written with: HKLM as a 64-bit PowerShell sees it,
// and a value that is set again keeps its kind.

#pragma once

#include "../common/Ps.h"

#include <string>

namespace RegistryPath
{
    // Test-Path.
    bool Exists(const std::wstring& path);
    // (Get-ItemProperty path).name, as text; nothing when the key or the
    // value is not there, or cannot be read.
    OptStr Get(const std::wstring& path, const std::wstring& name);
    // New-Item -Force for a key that may be missing. Throws a PatchError.
    void Create(const std::wstring& path);
    // Set-ItemProperty: the key must exist, and a value there keeps its kind.
    // Throws a PatchError.
    void Set(const std::wstring& path, const std::wstring& name, const std::wstring& value);
    // Remove-ItemProperty -ErrorAction SilentlyContinue.
    void Remove(const std::wstring& path, const std::wstring& name);
}
