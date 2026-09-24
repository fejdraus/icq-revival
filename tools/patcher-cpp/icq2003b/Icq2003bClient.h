// What the patch for ICQ Pro 2003b (build 3916) changes - the port of
// tools\patcher\Icq2003b\Icq2003bClient.cs.
//
// It does two things at once:
//
//   1. Removes the advertising and the Google search bar with a few point
//      changes in the client's code.
//   2. Points the links to the dead ICQ.com services - help, white pages, the
//      web pager, the panel after sign-in, search - at our server. The domain
//      of the server is typed in the window.
//
// It can also give the client a Ukrainian interface, and it sets the server
// the client signs in to, which lives in the registry.
//
// The user's database and the skin's look are left alone: changing the
// database kills the client for good.
//
// Apply makes the client match the selection: what is wanted is put in, what
// is not wanted and in place is taken out again, from the backup of the file.

#pragma once

#include "../common/PatchFiles.h"
#include "../common/PatchItems.h"

#include <string>
#include <vector>

struct Icq2003bResult
{
    std::vector<std::wstring> Lines;
    std::vector<std::wstring> TooLong;
};

class Icq2003bClient
{
public:
    static const wchar_t* BinSuffix;
    static const wchar_t* LinkSuffix;
    // The domain typed is remembered, so it need not be typed on every run.
    static const wchar_t* SettingsKey;

    Icq2003bClient(const std::wstring& root, bool noRegistry) : Root(root), NoRegistry(noRegistry) {}

    const std::wstring Root;
    // Leaves the registry alone - the sign-in server lives there, for the
    // whole machine, not in the folder. For runs on a copy of the client.
    const bool NoRegistry;

    // What a person chooses between: one row per job, whatever number of
    // files and places it takes.
    static const PatchJobs& Jobs();

    // Every change with its current state, in the order the window lists
    // them, the parts of one job folded into one row.
    std::vector<PatchItem> Items(const std::wstring& domain) const;

    // Makes the client match the selection. Gives what changed, one line per
    // change, and the links that did not fit. Throws a PatchError, before
    // anything is written, when a file that would be patched is not from
    // build 3916.
    Icq2003bResult ApplyAll(const std::wstring& domain, const OptStr& previous, const ps::StringSet& skip) const;

    // Puts the originals back from their backups, which stay, and gives how
    // many things were put back.
    int RestoreAll() const;

    static bool IsClientFolder(const OptStr& path);
    static OptStr FindRoot();
    // The files a folder must have to be taken for the client, as the
    // window names them (each change names its file, so some twice).
    static std::wstring ExpectedFiles();

    // Older versions saved the whole address here; only the domain is kept now.
    static OptStr SavedBase();
    static void SaveBase(const std::wstring& value);

    static OptStr SignInServer();
    // The server the client signs in with; nothing before its first run.
    static OptStr ConnectionServer();
};
