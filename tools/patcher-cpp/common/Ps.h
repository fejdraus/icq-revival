// The comparisons of the PowerShell originals, spelt out - the port of
// tools\patcher\Common\Ps.cs.
//
// The patches were first written in PowerShell, where most comparisons ignore
// case without saying so: -eq, -ne, -contains, the keys of @{} and [ordered]
// tables, -match, -split and -replace. A few do not: a .NET method called
// directly ([regex]::Match, String.Contains, IndexOf), and a HashSet[string].
// Each place in the port says which one it is by the helper it calls, so the
// behaviour stays the one the scripts had.
//
// .NET Framework 4.5 and later compare and case strings through Windows
// itself (CompareStringEx, LCMapStringEx) on Windows 8 and later, so the same
// calls here give the same answers; on XP the older forms of the same calls
// are used.

#pragma once

#include <windows.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

// A string that may be missing, where the C# code tells null from "".
using OptStr = std::optional<std::wstring>;

namespace ps
{
    // The text of an OptStr, "" for none - how PowerShell reads $null as text.
    inline const std::wstring& Or(const OptStr& s)
    {
        static const std::wstring empty;
        return s ? *s : empty;
    }

    // -eq / -ne on two strings: the invariant culture, ignoring case.
    bool Eq(const std::wstring& a, const std::wstring& b);
    // -ceq / -cne: the invariant culture, minding case.
    bool Ceq(const std::wstring& a, const std::wstring& b);
    // The keys of @{} and [ordered] tables: the current culture, ignoring case.
    bool KeyEq(const std::wstring& a, const std::wstring& b);
    // StringComparer.OrdinalIgnoreCase.
    bool OrdinalIgnoreCaseEq(const std::wstring& a, const std::wstring& b);
    bool StartsWithOrdinalIgnoreCase(const std::wstring& s, const std::wstring& prefix);

    // -contains / -notcontains.
    bool Contains(const std::vector<std::wstring>& list, const std::wstring& value);

    // Select-Object -Unique: minds case, keeps the first of each.
    std::vector<std::wstring> Unique(const std::vector<std::wstring>& list);

    // A string in an if: false when null or empty.
    inline bool IsTrue(const OptStr& s) { return s && !s->empty(); }
    inline bool IsTrue(const std::wstring& s) { return !s.empty(); }
    // A byte array in an if: empty is false, one byte is that byte, more are true.
    bool IsTrue(const std::vector<unsigned char>* value);

    // [int] of a number: rounded half to even, not cut off.
    int Int(double value);

    // char.IsWhiteSpace, and String.Trim / IsNullOrWhiteSpace built on it.
    bool IsWhiteSpace(wchar_t c);
    std::wstring Trim(const std::wstring& s);
    bool IsNullOrWhiteSpace(const OptStr& s);
    std::wstring TrimEnd(const std::wstring& s, const std::wstring& chars);
    std::wstring TrimStart(const std::wstring& s, const std::wstring& chars);

    // One character cased by the current culture (what Regex with IgnoreCase
    // and String.ToLower use), and whole strings.
    wchar_t Lower(wchar_t c);
    std::wstring ToLower(const std::wstring& s);
    std::wstring ToUpper(const std::wstring& s);
    std::wstring ToLowerInvariant(const std::wstring& s);

    // Whether two characters are the same to a regex with IgnoreCase.
    inline bool CharEqIgnoreCase(wchar_t a, wchar_t b) { return a == b || Lower(a) == Lower(b); }

    // The patterns the patches use that are plain text, not patterns: an
    // escaped literal under -match, -split and -replace, or a String method.
    size_t Find(const std::wstring& s, const std::wstring& needle, size_t from, bool ignoreCase);
    bool Has(const std::wstring& s, const std::wstring& needle, bool ignoreCase);
    bool StartsWithIgnoreCase(const std::wstring& s, const std::wstring& prefix);
    std::vector<std::wstring> Split(const std::wstring& s, const std::wstring& separator, bool ignoreCase);
    std::wstring Replace(const std::wstring& s, const std::wstring& from, const std::wstring& to, bool ignoreCase);
    std::wstring Join(const std::vector<std::wstring>& parts, const std::wstring& separator);

    // Numbers as the invariant culture writes them.
    std::wstring Num(long long value);
    std::wstring Hex(unsigned long long value);  // upper case, like {0:X}

    // An ordered set of strings compared by ordinal: a HashSet<string>, kept
    // with the slot order a HashSet has, since the registry gets its items in
    // that order - a removed item's slot is taken by the next one added.
    class StringSet
    {
    public:
        bool Contains(const std::wstring& s) const;
        bool Add(const std::wstring& s);
        bool Remove(const std::wstring& s);
        size_t Count() const { return count_; }
        std::vector<std::wstring> Items() const;

    private:
        std::vector<OptStr> slots_;
        std::vector<size_t> free_;
        size_t count_ = 0;
    };

    // UTF-16 to UTF-8 and back.
    std::string Utf8(const std::wstring& s);
    std::wstring FromUtf8(const std::string& s);
}
