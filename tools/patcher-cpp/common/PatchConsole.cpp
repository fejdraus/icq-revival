// See PatchConsole.h.

#include "PatchConsole.h"

#include <windows.h>

#include <string>

namespace PatchConsole
{
    namespace
    {
        bool Usable(HANDLE h)
        {
            return h != nullptr && h != INVALID_HANDLE_VALUE && GetFileType(h) != FILE_TYPE_UNKNOWN;
        }

        HANDLE OpenConsoleOutput()
        {
            return CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        }

        // Console.OutputEncoding: the console's code page, or the ANSI one
        // of Windows when the process has no console.
        UINT CodePage()
        {
            UINT cp = GetConsoleOutputCP();
            return cp != 0 ? cp : GetACP();
        }

        void Write(DWORD which, const std::wstring& line)
        {
            HANDLE h = GetStdHandle(which);
            if (!Usable(h)) return;
            std::wstring text = line + L"\r\n";
            UINT cp = CodePage();
            int n = WideCharToMultiByte(cp, 0, text.c_str(), (int)text.size(), nullptr, 0, nullptr, nullptr);
            if (n <= 0) return;
            std::string bytes(n, '\0');
            WideCharToMultiByte(cp, 0, text.c_str(), (int)text.size(), &bytes[0], n, nullptr, nullptr);
            DWORD wrote = 0;
            WriteFile(h, bytes.data(), (DWORD)bytes.size(), &wrote, nullptr);
        }
    }

    void Attach()
    {
        bool outOk = Usable(GetStdHandle(STD_OUTPUT_HANDLE));
        bool errOk = Usable(GetStdHandle(STD_ERROR_HANDLE));
        if (!(outOk && errOk) && AttachConsole(ATTACH_PARENT_PROCESS))
        {
            HANDLE con = nullptr;
            if (!outOk && !Usable(GetStdHandle(STD_OUTPUT_HANDLE))) SetStdHandle(STD_OUTPUT_HANDLE, con = OpenConsoleOutput());
            if (!errOk && !Usable(GetStdHandle(STD_ERROR_HANDLE))) SetStdHandle(STD_ERROR_HANDLE, con != nullptr ? con : OpenConsoleOutput());
        }
    }

    void OutLine(const std::wstring& line) { Write(STD_OUTPUT_HANDLE, line); }
    void ErrorLine(const std::wstring& line) { Write(STD_ERROR_HANDLE, line); }
}
