// See ClientFolder.h.

#include "ClientFolder.h"
#include "PatchFiles.h"
#include "Registry.h"

#include <vector>

namespace ClientFolder
{
    std::wstring Self()
    {
        wchar_t buf[MAX_PATH * 4];
        DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)(sizeof buf / sizeof buf[0]));
        if (n == 0) return L"";
        OptStr dir = PatchFiles::DirectoryName(std::wstring(buf, n));
        return dir ? *dir : L"";
    }

    namespace
    {
        // ^\s*"?(?<exe>[^"]+?\.exe) with IgnoreCase, backtracking included:
        // the program at the start of an uninstall command line, which may
        // be quoted and have arguments after it.
        OptStr ExeOfCommand(const std::wstring& s)
        {
            size_t ws = 0;
            while (ws < s.size() && ps::IsWhiteSpace(s[ws])) ws++;
            auto groupFrom = [&](size_t j) -> OptStr {
                for (size_t k = j + 1; k + 4 <= s.size(); k++)
                {
                    if (s[k - 1] == L'"') return std::nullopt;
                    if (ps::StartsWithIgnoreCase(s.substr(k, 4), L".exe")) return s.substr(j, k + 4 - j);
                }
                return std::nullopt;
            };
            for (size_t start = ws + 1; start-- > 0;)
            {
                if (start == ws && ws < s.size() && s[ws] == L'"')
                {
                    OptStr g = groupFrom(ws + 1);
                    if (g) return g;
                }
                if (start < s.size() && s[start] != L'"')
                {
                    OptStr g = groupFrom(start);
                    if (g) return g;
                }
            }
            return std::nullopt;
        }

        std::wstring Env(const wchar_t* name)
        {
            wchar_t buf[MAX_PATH * 2];
            DWORD n = GetEnvironmentVariableW(name, buf, (DWORD)(sizeof buf / sizeof buf[0]));
            if (n == 0 || n >= sizeof buf / sizeof buf[0]) return L"";
            return std::wstring(buf, n);
        }
    }

    OptStr Find(const ClientSearch& search)
    {
        std::vector<std::wstring> candidates;
        std::wstring self = Self();
        if (!self.empty()) candidates.push_back(self);

        for (const std::wstring& sub : {
                 L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + search.AppPathsExe,
                 L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + search.AppPathsExe })
        {
            try
            {
                Reg::Key key = Reg::Open(HKEY_LOCAL_MACHINE, sub, false);
                if (!key) continue;
                OptStr exe = Reg::Text(Reg::GetValue(key, L""));
                if (ps::IsTrue(exe))
                {
                    std::wstring path = search.TrimQuotes ? ps::TrimStart(ps::TrimEnd(*exe, L"\""), L"\"") : *exe;
                    OptStr dir = PatchFiles::DirectoryName(path);
                    if (!dir) continue;
                    candidates.push_back(*dir);
                }
            }
            catch (const PatchError&)
            {
            }
        }

        struct Place
        {
            HKEY Hive;
            const wchar_t* Path;
        };
        const Place uninstall[] = {
            { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
            { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
            { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        };
        for (const Place& u : uninstall)
        {
            try
            {
                Reg::Key key = Reg::Open(u.Hive, u.Path, false);
                if (!key) continue;
                for (const std::wstring& name : Reg::SubKeyNames(key))
                {
                    try
                    {
                        Reg::Key d = Reg::Open(key.Get(), name, false, u.Hive == HKEY_LOCAL_MACHINE);
                        if (!d) continue;
                        OptStr display = Reg::Text(Reg::GetValue(d, L"DisplayName"));
                        if (!search.IsDisplayName(ps::Or(display))) continue;
                        OptStr location = Reg::Text(Reg::GetValue(d, L"InstallLocation"));
                        if (ps::IsTrue(location)) candidates.push_back(*location);
                        if (search.UseUninstallString)
                        {
                            OptStr exe = ExeOfCommand(ps::Or(Reg::Text(Reg::GetValue(d, L"UninstallString"))));
                            if (exe)
                            {
                                OptStr dir = PatchFiles::DirectoryName(*exe);
                                if (dir) candidates.push_back(*dir);
                            }
                        }
                    }
                    catch (const PatchError&)
                    {
                    }
                }
            }
            catch (const PatchError&)
            {
            }
        }

        // Program Files as a 64-bit process sees it: this one is 32-bit, and
        // its ProgramFiles is the (x86) folder, so the 64-bit one is asked
        // for by the name Windows keeps it under.
        std::wstring programFiles = Env(L"ProgramW6432");
        if (programFiles.empty()) programFiles = Env(L"ProgramFiles");
        for (const std::wstring& b : { Env(L"ProgramFiles(x86)"), programFiles })
        {
            if (!b.empty()) candidates.push_back(PatchFiles::Join(b, search.StandardFolder));
        }

        for (const std::wstring& c : candidates)
        {
            OptStr full = PatchFiles::FullPath(c);
            if (!full) continue;
            if (search.IsClient(*full)) return *full;
        }
        return std::nullopt;
    }
}
