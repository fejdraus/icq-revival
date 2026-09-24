// See PatchFiles.h.

#include "PatchFiles.h"
#include "PatchConsole.h"

#include <wincrypt.h>

#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | 12)
#endif
#ifndef PROV_RSA_AES
#define PROV_RSA_AES 24
#endif

namespace PatchFiles
{
    std::function<void(const std::wstring&)> Error = [](const std::wstring& message) { PatchConsole::ErrorLine(message); };

    namespace
    {
        const wchar_t* InvalidPathChars = L"\"<>|";

        bool HasInvalidPathChars(const std::wstring& path)
        {
            for (wchar_t c : path)
            {
                if (c < 32 || wcschr(InvalidPathChars, c) != nullptr) return true;
            }
            return false;
        }

        DWORD Attributes(const std::wstring& path)
        {
            if (path.empty() || HasInvalidPathChars(path)) return INVALID_FILE_ATTRIBUTES;
            return GetFileAttributesW(path.c_str());
        }

        struct Handle
        {
            HANDLE h;
            explicit Handle(HANDLE handle) : h(handle) {}
            ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
            Handle(const Handle&) = delete;
            Handle& operator=(const Handle&) = delete;
        };

        HANDLE Open(const std::wstring& path, DWORD access, DWORD share, DWORD disposition)
        {
            if (path.empty() || HasInvalidPathChars(path)) throw PatchError{ L"Illegal characters in path." };
            HANDLE h = CreateFileW(path.c_str(), access, share, nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE)
            {
                DWORD e = GetLastError();
                // A folder opened as a file: .NET says access is denied.
                throw PatchError{ IoMessage(e, path) };
            }
            return h;
        }

        // Copy, Rename and Remove report instead of stopping.
        void Try(const std::function<void()>& action)
        {
            try
            {
                action();
            }
            catch (const PatchError& e)
            {
                Error(e.Message);
            }
        }

        std::wstring Quoted(const std::wstring& path) { return L"'" + path + L"'"; }
    }

    std::wstring SystemMessage(DWORD error)
    {
        wchar_t* buf = nullptr;
        DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 nullptr, error, 0, (LPWSTR)&buf, 0, nullptr);
        std::wstring text;
        if (n > 0 && buf != nullptr)
        {
            text.assign(buf, n);
            while (!text.empty() && (text.back() == L'\n' || text.back() == L'\r')) text.pop_back();
        }
        if (buf != nullptr) LocalFree(buf);
        if (text.empty()) text = L"Unknown error (0x" + ps::Hex(error) + L")";
        return text;
    }

    std::wstring IoMessage(DWORD error, const std::wstring& path)
    {
        switch (error)
        {
        case ERROR_FILE_NOT_FOUND:
            return path.empty() ? L"Unable to find the specified file." : L"Could not find file " + Quoted(path) + L".";
        case ERROR_PATH_NOT_FOUND:
            return path.empty() ? L"Could not find a part of the path." : L"Could not find a part of the path " + Quoted(path) + L".";
        case ERROR_ACCESS_DENIED:
            return path.empty() ? L"Access to the path is denied." : L"Access to the path " + Quoted(path) + L" is denied.";
        case ERROR_ALREADY_EXISTS:
            return L"Cannot create \"" + path + L"\" because a file or directory with the same name already exists.";
        case ERROR_FILENAME_EXCED_RANGE:
            return L"The specified path, file name, or both are too long. The fully qualified file name must be less than 260 characters, and the directory name must be less than 248 characters.";
        case ERROR_INVALID_DRIVE:
            return L"Could not find the drive " + Quoted(path) + L". The drive might not be ready or might not be mapped.";
        case ERROR_INVALID_PARAMETER:
            return SystemMessage(error);
        case ERROR_SHARING_VIOLATION:
            return path.empty() ? L"The process cannot access the file because it is being used by another process."
                                : L"The process cannot access the file " + Quoted(path) + L" because it is being used by another process.";
        case ERROR_FILE_EXISTS:
            return L"The file " + Quoted(path) + L" already exists.";
        case ERROR_OPERATION_ABORTED:
            return L"The I/O operation has been aborted because of either a thread exit or an application request.";
        default:
            return SystemMessage(error);
        }
    }

    bool Exists(const std::wstring& path) { return Attributes(path) != INVALID_FILE_ATTRIBUTES; }

    bool FileExists(const std::wstring& path)
    {
        DWORD a = Attributes(path);
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    bool DirectoryExists(const std::wstring& path)
    {
        DWORD a = Attributes(path);
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    std::wstring Join(const std::wstring& path, const std::wstring& child)
    {
        if (child.empty()) return path;
        if (path.empty()) return child;
        if (child[0] == L'\\' || child[0] == L'/' || (child.size() >= 2 && child[1] == L':')) return child;
        wchar_t last = path.back();
        if (last == L'\\' || last == L'/' || last == L':') return path + child;
        return path + L"\\" + child;
    }

    std::wstring FileName(const std::wstring& path)
    {
        size_t at = path.find_last_of(L"\\/:");
        return at == std::wstring::npos ? path : path.substr(at + 1);
    }

    std::wstring Leaf(const std::wstring& path)
    {
        return FileName(ps::TrimEnd(path, L"\\/"));
    }

    OptStr DirectoryName(const std::wstring& raw)
    {
        if (HasInvalidPathChars(raw)) return std::nullopt;
        std::wstring path = raw;
        for (wchar_t& c : path) { if (c == L'/') c = L'\\'; }
        // The root: "C:\", "C:", "\\server\share\" or "\".
        size_t root = 0;
        if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\')
        {
            size_t n = 2, parts = 2;
            while (n < path.size() && (path[n] != L'\\' || --parts > 0)) n++;
            root = n;
        }
        else
        {
            if (path.size() >= 2 && path[1] == L':') root = 2;
            if (root < path.size() && path[root] == L'\\') root++;
        }
        if (path.size() <= root) return std::nullopt;
        size_t i = path.size();
        while (i > root && path[--i] != L'\\') {}
        return path.substr(0, i);
    }

    OptStr FullPath(const std::wstring& path)
    {
        if (ps::IsNullOrWhiteSpace(path) || HasInvalidPathChars(path)) return std::nullopt;
        // A colon anywhere but after the drive letter is not a path .NET takes.
        size_t colon = path.find(L':', path.size() >= 2 && path[1] == L':' ? 2 : 0);
        if (colon != std::wstring::npos && !(path.compare(0, 4, L"\\\\?\\") == 0)) return std::nullopt;
        DWORD n = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (n == 0) return std::nullopt;
        std::wstring out(n, L'\0');
        n = GetFullPathNameW(path.c_str(), n, &out[0], nullptr);
        if (n == 0) return std::nullopt;
        out.resize(n);
        return out;
    }

    void Copy(const std::wstring& from, const std::wstring& to, bool force)
    {
        Try([&]() {
            if (HasInvalidPathChars(from) || HasInvalidPathChars(to)) throw PatchError{ L"Illegal characters in path." };
            if (force && FileExists(to))
            {
                DWORD a = GetFileAttributesW(to.c_str());
                DWORD clear = a & ~(DWORD)(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN);
                if (clear != a) SetFileAttributesW(to.c_str(), clear);
            }
            if (!CopyFileW(from.c_str(), to.c_str(), FALSE))
            {
                // Which of the two to name, the way File.Copy works it out.
                DWORD e = GetLastError();
                std::wstring name = to;
                if (e != ERROR_FILE_EXISTS)
                {
                    HANDLE h = CreateFileW(from.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                    if (h == INVALID_HANDLE_VALUE) name = from;
                    else CloseHandle(h);
                    if (e == ERROR_ACCESS_DENIED && DirectoryExists(to))
                    {
                        throw PatchError{ L"The target file \"" + to + L"\" is a directory, not a file." };
                    }
                }
                throw PatchError{ IoMessage(e, name) };
            }
        });
    }

    void Rename(const std::wstring& path, const std::wstring& newName)
    {
        Try([&]() {
            OptStr dir = DirectoryName(path);
            if (!dir) throw PatchError{ L"Illegal characters in path." };
            std::wstring to = Join(*dir, newName);
            if (!MoveFileW(path.c_str(), to.c_str()))
            {
                DWORD e = GetLastError();
                throw PatchError{ IoMessage(e, e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND ? path : to) };
            }
        });
    }

    void Remove(const std::wstring& path)
    {
        Try([&]() {
            if (FileExists(path))
            {
                DWORD a = GetFileAttributesW(path.c_str());
                if (a & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(path.c_str(), a & ~(DWORD)FILE_ATTRIBUTE_READONLY);
            }
            if (!DeleteFileW(path.c_str()))
            {
                DWORD e = GetLastError();
                if (e != ERROR_FILE_NOT_FOUND) throw PatchError{ IoMessage(e, path) };
            }
        });
    }

    void BackupOnce(const std::wstring& path, const std::wstring& suffix)
    {
        std::wstring backup = path + suffix;
        if (!Exists(backup)) Copy(path, backup, false);
    }

    Bytes ReadAllBytes(const std::wstring& path)
    {
        Handle f(Open(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING));
        LARGE_INTEGER size;
        if (!GetFileSizeEx(f.h, &size)) throw PatchError{ IoMessage(GetLastError(), path) };
        if (size.QuadPart > 0x7FFFFFFF) throw PatchError{ L"The file is too long. This operation is currently limited to supporting files less than 2 gigabytes in size." };
        Bytes bytes((size_t)size.QuadPart);
        size_t done = 0;
        while (done < bytes.size())
        {
            DWORD got = 0;
            if (!ReadFile(f.h, bytes.data() + done, (DWORD)(bytes.size() - done), &got, nullptr)) throw PatchError{ IoMessage(GetLastError(), path) };
            if (got == 0) throw PatchError{ L"Unable to read beyond the end of the stream." };
            done += got;
        }
        return bytes;
    }

    void WriteAllBytes(const std::wstring& path, const Bytes& bytes)
    {
        Handle f(Open(path, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS));
        size_t done = 0;
        while (done < bytes.size())
        {
            DWORD wrote = 0;
            if (!WriteFile(f.h, bytes.data() + done, (DWORD)(bytes.size() - done), &wrote, nullptr)) throw PatchError{ IoMessage(GetLastError(), path) };
            done += wrote;
        }
    }

    long long Length(const std::wstring& path)
    {
        WIN32_FILE_ATTRIBUTE_DATA d;
        if (HasInvalidPathChars(path) || !GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &d) ||
            (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            throw PatchError{ IoMessage(ERROR_FILE_NOT_FOUND, path) };
        }
        return ((long long)d.nFileSizeHigh << 32) | d.nFileSizeLow;
    }

    Bytes ReadAt(const std::wstring& path, long long offset, size_t len)
    {
        Handle f(Open(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING));
        Bytes buf(len, 0);
        LARGE_INTEGER at;
        at.QuadPart = offset;
        if (!SetFilePointerEx(f.h, at, nullptr, FILE_BEGIN)) throw PatchError{ IoMessage(GetLastError(), path) };
        DWORD got = 0;
        if (!ReadFile(f.h, buf.data(), (DWORD)len, &got, nullptr)) throw PatchError{ IoMessage(GetLastError(), path) };
        return buf;
    }

    namespace
    {
        // UTF-8 as .NET reads it with its default replacement: every byte
        // that does not start or continue a valid sequence is one U+FFFD.
        std::wstring DecodeUtf8(const unsigned char* p, size_t n)
        {
            std::wstring out;
            out.reserve(n);
            size_t i = 0;
            while (i < n)
            {
                unsigned char b = p[i];
                if (b < 0x80) { out += (wchar_t)b; i++; continue; }
                int need = 0;
                unsigned int cp = 0, min = 0;
                if (b >= 0xC2 && b <= 0xDF) { need = 1; cp = b & 0x1F; min = 0x80; }
                else if (b >= 0xE0 && b <= 0xEF) { need = 2; cp = b & 0x0F; min = 0x800; }
                else if (b >= 0xF0 && b <= 0xF4) { need = 3; cp = b & 0x07; min = 0x10000; }
                else { out += (wchar_t)0xFFFD; i++; continue; }
                size_t k = 1;
                bool ok = true;
                for (; k <= (size_t)need; k++)
                {
                    if (i + k >= n || (p[i + k] & 0xC0) != 0x80) { ok = false; break; }
                    cp = (cp << 6) | (p[i + k] & 0x3F);
                    // Overlong, surrogate and out-of-range forms stop at the
                    // second byte, as .NET's decoder does.
                    if (k == 1)
                    {
                        unsigned char c = p[i + 1];
                        if ((b == 0xE0 && c < 0xA0) || (b == 0xED && c > 0x9F) || (b == 0xF0 && c < 0x90) || (b == 0xF4 && c > 0x8F))
                        {
                            ok = false;
                            break;
                        }
                    }
                }
                if (!ok || cp < min)
                {
                    out += (wchar_t)0xFFFD;
                    i += k;
                    continue;
                }
                if (cp >= 0x10000)
                {
                    cp -= 0x10000;
                    out += (wchar_t)(0xD800 + (cp >> 10));
                    out += (wchar_t)(0xDC00 + (cp & 0x3FF));
                }
                else
                {
                    out += (wchar_t)cp;
                }
                i += need + 1;
            }
            return out;
        }

        std::wstring DecodeUtf16(const unsigned char* p, size_t n, bool bigEndian)
        {
            std::wstring out;
            for (size_t i = 0; i + 1 < n; i += 2)
            {
                out += bigEndian ? (wchar_t)((p[i] << 8) | p[i + 1]) : (wchar_t)(p[i] | (p[i + 1] << 8));
            }
            if (n % 2 != 0) out += (wchar_t)0xFFFD;
            return out;
        }

        std::wstring DecodeUtf32(const unsigned char* p, size_t n, bool bigEndian)
        {
            std::wstring out;
            for (size_t i = 0; i + 3 < n; i += 4)
            {
                unsigned int cp = bigEndian ? ((unsigned)p[i] << 24) | (p[i + 1] << 16) | (p[i + 2] << 8) | p[i + 3]
                                            : p[i] | (p[i + 1] << 8) | (p[i + 2] << 16) | ((unsigned)p[i + 3] << 24);
                if (cp >= 0x110000 || (cp >= 0xD800 && cp <= 0xDFFF)) out += (wchar_t)0xFFFD;
                else if (cp >= 0x10000)
                {
                    cp -= 0x10000;
                    out += (wchar_t)(0xD800 + (cp >> 10));
                    out += (wchar_t)(0xDC00 + (cp & 0x3FF));
                }
                else out += (wchar_t)cp;
            }
            if (n % 4 != 0) out += (wchar_t)0xFFFD;
            return out;
        }
    }

    std::wstring ReadAllTextLatin1(const std::wstring& path)
    {
        Bytes b = ReadAllBytes(path);
        const unsigned char* p = b.data();
        size_t n = b.size();
        if (n >= 2 && p[0] == 0xFE && p[1] == 0xFF) return DecodeUtf16(p + 2, n - 2, true);
        if (n >= 2 && p[0] == 0xFF && p[1] == 0xFE)
        {
            if (n >= 4 && p[2] == 0 && p[3] == 0) return DecodeUtf32(p + 4, n - 4, false);
            return DecodeUtf16(p + 2, n - 2, false);
        }
        if (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) return DecodeUtf8(p + 3, n - 3);
        if (n >= 4 && p[0] == 0 && p[1] == 0 && p[2] == 0xFE && p[3] == 0xFF) return DecodeUtf32(p + 4, n - 4, true);
        std::wstring text(n, L'\0');
        for (size_t i = 0; i < n; i++) text[i] = (wchar_t)p[i];
        return text;
    }

    void WriteAllTextLatin1(const std::wstring& path, const std::wstring& text)
    {
        Bytes b(text.size());
        size_t o = 0;
        for (size_t i = 0; i < text.size(); i++)
        {
            wchar_t c = text[i];
            if (c <= 0xFF) { b[o++] = (unsigned char)c; continue; }
            // Outside Latin-1: the nearest Latin-1 character, as .NET's
            // best-fit fallback gives it; a surrogate pair is one character.
            int len = (c >= 0xD800 && c <= 0xDBFF && i + 1 < text.size()) ? 2 : 1;
            char out[4] = { '?' };
            BOOL lossy = FALSE;
            if (WideCharToMultiByte(28591, 0, &text[i], len, out, sizeof out, nullptr, &lossy) < 1) out[0] = '?';
            b[o++] = (unsigned char)out[0];
            i += len - 1;
        }
        b.resize(o);
        WriteAllBytes(path, b);
    }

    namespace
    {
        std::wstring HexOf(const unsigned char* h, size_t n, bool upper)
        {
            const wchar_t* digits = upper ? L"0123456789ABCDEF" : L"0123456789abcdef";
            std::wstring out;
            for (size_t i = 0; i < n; i++)
            {
                out += digits[h[i] >> 4];
                out += digits[h[i] & 15];
            }
            return out;
        }

        // SHA-256 by the AES provider, which XP has from SP3 on.
        class Hasher
        {
        public:
            Hasher()
            {
                if (!CryptAcquireContextW(&prov_, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
                    !CryptCreateHash(prov_, CALG_SHA_256, 0, 0, &hash_))
                {
                    throw PatchError{ SystemMessage(GetLastError()) };
                }
            }
            ~Hasher()
            {
                if (hash_) CryptDestroyHash(hash_);
                if (prov_) CryptReleaseContext(prov_, 0);
            }
            void Add(const unsigned char* p, size_t n)
            {
                if (n > 0 && !CryptHashData(hash_, p, (DWORD)n, 0)) throw PatchError{ SystemMessage(GetLastError()) };
            }
            std::wstring Hex(bool upper)
            {
                unsigned char h[32];
                DWORD len = sizeof h;
                if (!CryptGetHashParam(hash_, HP_HASHVAL, h, &len, 0)) throw PatchError{ SystemMessage(GetLastError()) };
                return HexOf(h, len, upper);
            }

        private:
            HCRYPTPROV prov_ = 0;
            HCRYPTHASH hash_ = 0;
        };
    }

    std::wstring Sha256(const std::wstring& path)
    {
        Handle f(Open(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING));
        Hasher h;
        static unsigned char buf[65536];
        for (;;)
        {
            DWORD got = 0;
            if (!ReadFile(f.h, buf, sizeof buf, &got, nullptr)) throw PatchError{ IoMessage(GetLastError(), path) };
            if (got == 0) break;
            h.Add(buf, got);
        }
        return h.Hex(true);
    }

    std::wstring Sha256Lower(const Bytes& bytes)
    {
        Hasher h;
        h.Add(bytes.data(), bytes.size());
        return h.Hex(false);
    }
}
