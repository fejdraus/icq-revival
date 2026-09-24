// Patch for ICQ Pro 2003b (build 3916) - a windowed tool, the same kind as
// the one for ICQ 6.5. The port of tools\patcher\Icq2003b\Program.cs to
// plain Win32, so it runs on Windows XP SP3 through 11 with nothing to
// install.
//
// What it changes is in Icq2003bClient.cpp. The folder is found on its own:
// next to this tool first (dropped into the ICQ folder, or a portable copy),
// then from the registry, then the standard path.
//
// Without arguments the window opens. For a scripted run:
//   ICQ-2003b-Patch.exe -Apply   [-Root <folder>] [-Server <domain>] [-Skip <jobs>] [-Include ukrainian] [-NoRegistry]
//   ICQ-2003b-Patch.exe -Restore [-Root <folder>] [-NoRegistry]
// -Skip takes job keys (banners, google bar, send-by, links, sign-in,
// ukrainian), separated by commas; -Include takes the jobs that are off unless
// asked for. The run reports on the standard output ("applied: ...", "did not
// fit: ...", "changes made: N", "files restored: N") and exits with 0, or
// with 1 and the reason on the standard error.
//
// The window is the one all client patches share, ..\common\PatchWindow.cpp.
// Built by ..\Build.ps1.

#include "Icq2003bClient.h"
#include "../common/PatchCli.h"
#include "../common/PatchConsole.h"
#include "../common/PatchSettings.h"
#include "../common/PatchWindow.h"

#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>

#include <algorithm>

namespace
{
    // --- scripted run ---------------------------------------------------------

    int RunHeadless(const CliArgs& a)
    {
        OptStr rootArg = a.Text(L"Root");
        OptStr root;
        if (ps::IsTrue(rootArg))
        {
            root = PatchFiles::FullPath(*rootArg);
            if (!root)
            {
                // Path.GetFullPath threw here, and nothing caught it.
                PatchConsole::ErrorLine(L"Unhandled Exception: System.ArgumentException: Illegal characters in path.");
                return (int)0xE0434352;
            }
        }
        else
        {
            root = Icq2003bClient::FindRoot();
        }
        if (!Icq2003bClient::IsClientFolder(root))
        {
            PatchConsole::ErrorLine(L"ICQ Pro 2003b folder not found: " + ps::Or(root));
            return 1;
        }
        Icq2003bClient client(*root, a.Switch(L"NoRegistry"));
        if (a.Switch(L"Restore"))
        {
            int n;
            try
            {
                n = client.RestoreAll();
            }
            catch (const PatchError& e)
            {
                PatchConsole::ErrorLine(e.Message);
                return (int)0xE0434352;
            }
            PatchConsole::OutLine(L"files restored: " + ps::Num(n));
            return 0;
        }
        OptStr previous = Icq2003bClient::SavedBase();
        OptStr serverArg = a.Text(L"Server");
        OptStr domain = ps::IsTrue(serverArg) ? OptStr(Domain::Of(serverArg)) : previous;
        if (!Domain::IsValid(domain))
        {
            PatchConsole::ErrorLine(L"not a domain: '" + ps::Or(serverArg) + L"' - pass -Server icq.example.org");
            return 1;
        }
        ps::StringSet skip;
        for (const std::wstring& k : a.List(L"Skip")) skip.Add(k);
        std::vector<std::wstring> include = a.List(L"Include");
        const PatchJobs& jobs = Icq2003bClient::Jobs();
        for (const std::wstring& k : jobs.Keys())
        {
            if (jobs[k].Off && !ps::Contains(include, k)) skip.Add(k);
        }
        Icq2003bResult result;
        try
        {
            result = client.ApplyAll(*domain, previous, skip);
        }
        catch (const PatchError& e)
        {
            PatchConsole::ErrorLine(e.Message);
            return 1;
        }
        for (const std::wstring& line : result.Lines) PatchConsole::OutLine(line);
        for (const std::wstring& t : result.TooLong) PatchConsole::OutLine(L"did not fit: " + t);
        PatchConsole::OutLine(L"changes made: " + ps::Num((long long)result.Lines.size()));
        return 0;
    }

    // --- window -------------------------------------------------------------------

    // Process.GetProcessesByName: the name of the program without ".exe",
    // ignoring case.
    bool ProcessRunning(const wchar_t* name)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe = { sizeof pe };
        bool found = false;
        for (BOOL ok = Process32FirstW(snap, &pe); ok && !found; ok = Process32NextW(snap, &pe))
        {
            std::wstring exe = pe.szExeFile;
            if (exe.size() > 4 && ps::OrdinalIgnoreCaseEq(exe.substr(exe.size() - 4), L".exe")) exe = exe.substr(0, exe.size() - 4);
            if (ps::OrdinalIgnoreCaseEq(exe, name)) found = true;
        }
        CloseHandle(snap);
        return found;
    }

    int CALLBACK BrowseCallback(HWND hwnd, UINT msg, LPARAM, LPARAM data)
    {
        if (msg == BFFM_INITIALIZED && data != 0) SendMessageW(hwnd, BFFM_SETSELECTIONW, TRUE, data);
        return 0;
    }

    // FolderBrowserDialog: the folder picked, or nothing.
    OptStr PickFolder(HWND owner, const std::wstring& description, const OptStr& selected)
    {
        BROWSEINFOW bi = {};
        bi.hwndOwner = owner;
        bi.lpszTitle = description.c_str();
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        bi.lpfn = BrowseCallback;
        bi.lParam = ps::IsTrue(selected) ? (LPARAM)selected->c_str() : 0;
        PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
        if (pidl == nullptr) return std::nullopt;
        wchar_t path[MAX_PATH];
        BOOL ok = SHGetPathFromIDListW(pidl, path);
        CoTaskMemFree(pidl);
        if (!ok) return std::nullopt;
        return std::wstring(path);
    }

    std::wstring JoinFirst(const std::vector<std::wstring>& lines, size_t n, const std::wstring& separator)
    {
        std::vector<std::wstring> first(lines.begin(), lines.begin() + (std::min)(n, lines.size()));
        return ps::Join(first, separator);
    }

    class Icq2003bWindow
    {
    public:
        explicit Icq2003bWindow(bool noRegistry)
            : noRegistry_(noRegistry),
              root_(Icq2003bClient::FindRoot()),
              ui_(L"ICQ Pro 2003b Patch",
                  L"Removes the banners, the Google search bar and the empty strip they occupied, and points the menu items that used to open ICQ.com at your own server. The user database and the skin are left untouched.",
                  L"2003b", L"#4FA3E0", L"#1F66B0", L"ICQ Pro 2003b",
                  L"Just the domain, e.g. icq.example.org. The patch fills in the port and path, and new accounts sign in there. Remembered for next time.",
                  { { L"Change", 400 }, { L"Where", 210 } })
        {
            ui_.OnFolderButton = [this]() { SelectFolder(); };
            OptStr saved = Icq2003bClient::SavedBase();
            if (ps::IsTrue(saved)) ui_.SetServerText(*saved);
            ui_.ReadUnchecked(Icq2003bClient::SettingsKey, Icq2003bClient::Jobs().DefaultOff());
            ui_.OnServerLeave = [this]() { UpdateView(); };

            ui_.AddButton(L"Close", [this]() { ui_.Close(); });
            ui_.AddButton(L"Apply", [this]() { Apply(); }, true);
            ui_.AddButton(L"Restore original", [this]() { Restore(); });
            ui_.AddButton(L"Re-check", [this]() { UpdateView(); });
        }

        void Run()
        {
            UpdateView();
            ui_.ShowWindow();
        }

    private:
        bool Ready()
        {
            if (!ps::IsTrue(root_))
            {
                ui_.Message(L"ICQ Pro 2003b folder not found.\n\nPut this tool into the ICQ folder, or pick the folder manually.",
                            L"Client not found", MB_ICONERROR);
                return false;
            }
            if (ProcessRunning(L"Icq"))
            {
                ui_.Message(L"ICQ is running. Close it properly: tray icon -> Exit.\n\n"
                            L"Do not kill the process: the client leaves its contact list cache half-written and then hangs forever on \"Logging in...\"",
                            L"Close ICQ first", MB_ICONWARNING);
                return false;
            }
            return true;
        }

        void Apply()
        {
            if (!Ready()) return;
            // Checked before anything is written.
            std::wstring domain = Domain::Of(ui_.ServerText());
            if (!Domain::IsValid(domain))
            {
                ui_.Message(L"Type your server's domain, nothing else:\n\n  icq.example.org\n\nThe port and path are filled in by the patch.",
                            L"Server", MB_ICONWARNING);
                return;
            }
            ui_.SetServerText(domain);
            ui_.SaveUnchecked(Icq2003bClient::SettingsKey);
            ui_.StartWork(L"Applying...");
            Icq2003bResult result;
            try
            {
                result = Icq2003bClient(*root_, noRegistry_).ApplyAll(domain, Icq2003bClient::SavedBase(), ui_.Unchecked);
            }
            catch (const PatchError& e)
            {
                ui_.StopWork();
                ui_.Message(e.Message, L"Wrong client version", MB_ICONERROR);
                UpdateView();
                return;
            }
            ui_.StopWork();
            Icq2003bClient::SaveBase(domain);
            UpdateView();

            const std::vector<std::wstring>& done = result.Lines;
            std::wstring msg = !done.empty()
                ? L"Changes made: " + ps::Num((long long)done.size()) + L"\n\n  " + JoinFirst(done, 12, L"\n  ")
                : L"The client already matches the selection.";
            if (done.size() > 12) msg += L"\n  ...";
            if (!result.TooLong.empty())
            {
                msg += L"\n\nThese did not fit and were left alone:\n  " + ps::Join(result.TooLong, L"\n  ") +
                       L"\n\nA link stored inside the executable cannot be made longer than the original," +
                       L" so a shorter server address would fix it.";
            }
            if (ui_.IsSelected(L"sign-in") && ps::Eq(ps::Or(Icq2003bClient::SignInServer()), domain))
            {
                OptStr c = Icq2003bClient::ConnectionServer();
                if (ps::IsTrue(c) && !ps::Eq(*c, domain))
                {
                    msg += L"\n\nICQ is set to sign in to " + *c + L" under Preferences -> Connection," +
                           L" which looks like your own choice, so it was left alone. Change it there" +
                           L" to " + domain + L" to sign in to this server.";
                }
                else
                {
                    msg += L"\n\nICQ signs in to " + domain + L".";
                }
            }
            msg += L"\n\nYou can start ICQ now.";
            ui_.Message(msg, L"Done", MB_ICONINFORMATION);
        }

        void Restore()
        {
            if (!Ready()) return;
            ui_.StartWork(L"Restoring...");
            int done;
            try
            {
                done = Icq2003bClient(*root_, noRegistry_).RestoreAll();
            }
            catch (...)
            {
                ui_.StopWork();
                throw;
            }
            ui_.StopWork();
            UpdateView();
            ui_.Message(L"Files restored: " + ps::Num(done) + L".", L"Done", MB_ICONINFORMATION);
        }

        void SelectFolder()
        {
            OptStr picked = PickFolder(ui_.Handle(), L"Select the ICQ Pro 2003b folder (the one with Icq.exe)", root_);
            if (!picked) return;
            if (Icq2003bClient::IsClientFolder(picked))
            {
                root_ = picked;
                UpdateView();
            }
            else
            {
                ui_.Message(L"This folder does not look like ICQ Pro 2003b.\n\nExpected files: " + Icq2003bClient::ExpectedFiles(),
                            L"Wrong folder", MB_ICONWARNING);
            }
        }

        void UpdateView()
        {
            ui_.SetFolder(root_);
            ui_.ClearList();
            if (ps::IsTrue(root_))
            {
                std::vector<std::pair<std::wstring, int>> groups;
                for (const PatchItem& it : Icq2003bClient(*root_, noRegistry_).Items(Domain::Of(ui_.ServerText())))
                {
                    int id = -1;
                    for (const auto& g : groups)
                    {
                        if (ps::KeyEq(g.first, it.Group)) id = g.second;
                    }
                    if (id < 0)
                    {
                        id = ui_.AddGroup(it.Group);
                        groups.push_back({ it.Group, id });
                    }
                    ui_.AddRow(id, { it.What, it.Where }, it.State, it.Key);
                }
            }
            ui_.CompleteList();
        }

        bool noRegistry_;
        OptStr root_;
        PatchWindow ui_;
    };
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    CliArgs a;
    try
    {
        a = PatchCli::Parse(PatchCli::ProcessArgs(), {
            { L"Apply", CliKind::Switch },
            { L"Restore", CliKind::Switch },
            { L"Root", CliKind::Text },
            { L"Server", CliKind::Text },
            // Jobs to leave out - or take out, if in place - by their keys.
            { L"Skip", CliKind::List },
            // Jobs that are off unless asked for, such as ukrainian.
            { L"Include", CliKind::List },
            // Leaves the registry alone - the sign-in server lives there,
            // for the whole machine, not in the folder. For runs on a copy
            // of the client.
            { L"NoRegistry", CliKind::Switch },
        });
    }
    catch (const CliException& e)
    {
        PatchConsole::Attach();
        PatchConsole::ErrorLine(e.Message);
        return 1;
    }

    if (a.Switch(L"Apply") || a.Switch(L"Restore"))
    {
        PatchConsole::Attach();
        try
        {
            return RunHeadless(a);
        }
        catch (const PatchError& e)
        {
            // What the C# patch let through to the runtime.
            PatchConsole::ErrorLine(e.Message);
            return (int)0xE0434352;
        }
    }

    PatchWindow::Init();
    try
    {
        Icq2003bWindow(a.Switch(L"NoRegistry")).Run();
    }
    catch (const PatchError& e)
    {
        PatchConsole::ErrorLine(e.Message);
    }
    return 0;
}
