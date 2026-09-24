// The file work every client patch does - the port of
// tools\patcher\Common\PatchFiles.cs: backups next to the file, the checksum
// a build is told apart by, and bytes read and written back.
//
// Copying, renaming and removing behave like the PowerShell cmdlets the
// patches were written with: a failure is reported and the run goes on,
// where a failed read or write of a file's bytes stops it (a PatchError).
// The messages are worded like the .NET ones the C# port prints.

#pragma once

#include "Ps.h"

#include <functional>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

// What stops a run: the reason, as it is reported.
struct PatchError
{
    std::wstring Message;
};

namespace PatchFiles
{
    // Where a failed copy, rename or removal is reported. The run goes on.
    extern std::function<void(const std::wstring&)> Error;

    // Test-Path: a file or a folder.
    bool Exists(const std::wstring& path);
    bool FileExists(const std::wstring& path);
    bool DirectoryExists(const std::wstring& path);

    // Join-Path (Path.Combine).
    std::wstring Join(const std::wstring& path, const std::wstring& child);
    // Split-Path -Leaf.
    std::wstring Leaf(const std::wstring& path);
    // Path.GetFileName and Path.GetDirectoryName; the latter gives nothing
    // for a path with characters a path cannot have, where .NET throws.
    std::wstring FileName(const std::wstring& path);
    OptStr DirectoryName(const std::wstring& path);
    // Path.GetFullPath; nothing where .NET throws.
    OptStr FullPath(const std::wstring& path);

    // Copy-Item for a file: an existing one is replaced, and with force
    // also when it is read-only.
    void Copy(const std::wstring& from, const std::wstring& to, bool force);
    // Rename-Item, for a file or a folder.
    void Rename(const std::wstring& path, const std::wstring& newName);
    // Remove-Item -Force for a file.
    void Remove(const std::wstring& path);

    // The file as it was, next to it, before the first change.
    void BackupOnce(const std::wstring& path, const std::wstring& suffix);

    // File.ReadAllBytes / File.WriteAllBytes; throw a PatchError.
    Bytes ReadAllBytes(const std::wstring& path);
    void WriteAllBytes(const std::wstring& path, const Bytes& bytes);
    // FileInfo.Length.
    long long Length(const std::wstring& path);
    // Up to len bytes from offset, the rest zero - one read of a FileStream
    // opened for reading with FileShare.ReadWrite.
    Bytes ReadAt(const std::wstring& path, long long offset, size_t len);

    // File.ReadAllText with an encoding: the byte order mark decides when
    // there is one (UTF-8, UTF-16, UTF-32), Latin-1 otherwise; and
    // File.WriteAllText in Latin-1, with no mark.
    std::wstring ReadAllTextLatin1(const std::wstring& path);
    void WriteAllTextLatin1(const std::wstring& path, const std::wstring& text);

    // The checksum a file is told apart by, as upper-case hex, and the one of
    // some bytes, as lower-case hex.
    std::wstring Sha256(const std::wstring& path);
    std::wstring Sha256Lower(const Bytes& bytes);

    // The message .NET gives for a failed file call, for this path.
    std::wstring IoMessage(DWORD error, const std::wstring& path);
    // The text Windows has for an error code (Win32Exception.Message).
    std::wstring SystemMessage(DWORD error);
}
