// See PatchItems.h.

#include "PatchItems.h"

#include <algorithm>
#include <stdexcept>

void PatchJobs::Add(const std::wstring& key, const std::wstring& group, const std::wstring& what, bool off)
{
    order_.push_back(key);
    jobs_.push_back({ key, PatchJob{ group, what, off } });
}

void PatchJobs::Assign(const std::wstring& part, const std::wstring& job)
{
    for (auto& p : jobOf_)
    {
        if (ps::KeyEq(p.first, part))
        {
            p.second = job;
            return;
        }
    }
    jobOf_.push_back({ part, job });
}

const PatchJob* PatchJobs::Find(const std::wstring& key) const
{
    for (const auto& p : jobs_)
    {
        if (ps::KeyEq(p.first, key)) return &p.second;
    }
    return nullptr;
}

const PatchJob& PatchJobs::operator[](const std::wstring& key) const
{
    const PatchJob* j = Find(key);
    if (j == nullptr) throw std::out_of_range("no such job");
    return *j;
}

bool PatchJobs::Contains(const std::wstring& key) const { return Find(key) != nullptr; }

std::vector<std::wstring> PatchJobs::DefaultOff() const
{
    std::vector<std::wstring> result;
    for (const std::wstring& k : order_)
    {
        if ((*this)[k].Off) result.push_back(k);
    }
    return result;
}

std::wstring PatchJobs::KeyOf(const std::wstring& part) const
{
    for (const auto& p : jobOf_)
    {
        if (ps::KeyEq(p.first, part)) return p.second;
    }
    return part;
}

bool PatchJobs::IsWanted(const ps::StringSet& skip, const std::wstring& part) const
{
    return !(skip.Count() > 0 && skip.Contains(KeyOf(part)));
}

std::wstring PatchJobs::JoinStates(const std::vector<std::wstring>& states)
{
    std::vector<std::wstring> s;
    for (const std::wstring& x : states)
    {
        if (!ps::Eq(x, L"missing")) s.push_back(x);
    }
    if (s.empty()) return L"missing";
    for (const wchar_t* bad : { L"other version", L"unknown" })
    {
        if (ps::Contains(s, bad)) return bad;
    }
    std::vector<std::wstring> distinct = ps::Unique(s);
    if (distinct.size() == 1) return distinct[0];
    return L"partly";
}

std::vector<PatchItem> PatchJobs::Merge(const std::vector<PatchItem>& items) const
{
    std::vector<PatchItem> result;
    for (const std::wstring& job : order_)
    {
        std::vector<const PatchItem*> parts;
        for (const PatchItem& i : items)
        {
            if (ps::Eq(KeyOf(i.Key), job)) parts.push_back(&i);
        }
        if (parts.empty()) continue;
        std::vector<std::wstring> wheres, states;
        for (const PatchItem* p : parts)
        {
            wheres.push_back(ps::Split(p->Where, L" at ", true)[0]);
            states.push_back(p->State);
        }
        std::vector<std::wstring> files = ps::Unique(wheres);
        std::wstring where = files.size() <= 2
            ? ps::Join(files, L", ")
            : ps::Num((long long)parts.size()) + L" changes in " + ps::Num((long long)files.size()) + L" files";
        const PatchJob& j = (*this)[job];
        result.push_back(PatchItem{ j.Group, job, j.What, where, JoinStates(states) });
    }
    for (const PatchItem& it : items)
    {
        if (!Contains(KeyOf(it.Key))) result.push_back(it);
    }
    return result;
}

namespace PatchSteps
{
    int Total = 0;
    int Done = 0;
    std::function<void(int, int, const std::wstring&)> Show;

    void Start(int total)
    {
        Total = (std::max)(1, total);
        Done = 0;
    }

    void Step(const std::wstring& text)
    {
        Done++;
        if (Show) Show(Done, Total, text);
    }
}
