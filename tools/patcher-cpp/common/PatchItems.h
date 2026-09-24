// The list of changes a client patch offers, shared by every patch and used
// with and without the window - the port of tools\patcher\Common\PatchItems.cs.
//
// A patch keeps its changes as small as the files need - one byte run, one
// line of markup - but a person chooses what they get: no Xtraz, no
// advertising, links to their own server. So every change belongs to a job,
// and the window shows one row per job, with one tick and one state.
//
// Filled in by the patch: the jobs in the order the window lists them, and
// which job each change belongs to.

#pragma once

#include "Ps.h"

#include <functional>
#include <string>
#include <vector>

// One change, or one job folded out of them. Where is a file, maybe
// "file at offset".
struct PatchItem
{
    std::wstring Group;
    std::wstring Key;
    std::wstring What;
    std::wstring Where;
    std::wstring State;
};

struct PatchJob
{
    std::wstring Group;
    std::wstring What;
    // Off until chosen: cleared the first time the window sees it.
    bool Off = false;
};

class PatchJobs
{
public:
    void Add(const std::wstring& key, const std::wstring& group, const std::wstring& what, bool off = false);

    // Says which job a change belongs to.
    void Assign(const std::wstring& part, const std::wstring& job);

    const std::vector<std::wstring>& Keys() const { return order_; }
    const PatchJob& operator[](const std::wstring& key) const;
    bool Contains(const std::wstring& key) const;

    // The jobs that are off until chosen.
    std::vector<std::wstring> DefaultOff() const;

    // The key a change is chosen by: its job, or the change itself.
    std::wstring KeyOf(const std::wstring& part) const;

    // Whether a change is wanted: all of them, unless its job is in skip -
    // the rows cleared in the window, or -Skip of a scripted run. The keys
    // in skip are matched as they are spelt.
    bool IsWanted(const ps::StringSet& skip, const std::wstring& part) const;

    // One state for a job out of the states of its changes.
    static std::wstring JoinStates(const std::vector<std::wstring>& states);

    // Folds the changes into one row per job, in the order of the jobs.
    // A change no job claims keeps a row of its own at the end.
    std::vector<PatchItem> Merge(const std::vector<PatchItem>& items) const;

private:
    const PatchJob* Find(const std::wstring& key) const;

    std::vector<std::wstring> order_;
    // Keyed ignoring case, like the [ordered] tables of the scripts.
    std::vector<std::pair<std::wstring, PatchJob>> jobs_;
    std::vector<std::pair<std::wstring, std::wstring>> jobOf_;
};

// How far a long run is. The patch says how many steps there are and names
// each as it starts; whoever shows it - the window - sets Show. Without it
// the steps cost nothing.
namespace PatchSteps
{
    extern int Total;
    extern int Done;
    extern std::function<void(int, int, const std::wstring&)> Show;

    void Start(int total);
    void Step(const std::wstring& text);
}
