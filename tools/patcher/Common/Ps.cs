// The comparisons of the PowerShell originals, spelt out.
//
// The patches were first written in PowerShell, where most comparisons ignore
// case without saying so: -eq, -ne, -contains, the keys of @{} and [ordered]
// tables, -match, -split and -replace. A few do not: a .NET method called
// directly ([regex]::Match, String.Contains, IndexOf), and a HashSet[string].
// Each place in the port says which one it is by the helper it calls, so the
// behaviour stays the one the scripts had.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace IcqRevival.Patch
{
    internal static class Ps
    {
        // The keys of @{} and [ordered] tables.
        public static readonly StringComparer Keys = StringComparer.CurrentCultureIgnoreCase;

        // -eq / -ne on two strings: the invariant culture, ignoring case.
        public static bool Eq(string a, string b)
        {
            return CultureInfo.InvariantCulture.CompareInfo.Compare(a ?? "", b ?? "", CompareOptions.IgnoreCase) == 0;
        }

        // -ceq / -cne: the invariant culture, minding case.
        public static bool Ceq(string a, string b)
        {
            return CultureInfo.InvariantCulture.CompareInfo.Compare(a ?? "", b ?? "", CompareOptions.None) == 0;
        }

        // -contains / -notcontains.
        public static bool Contains(IEnumerable<string> list, string value)
        {
            if (list == null) return false;
            foreach (string s in list) { if (Eq(s, value)) return true; }
            return false;
        }

        // -match.
        public static bool Match(string input, string pattern)
        {
            return Regex.IsMatch(input ?? "", pattern, RegexOptions.IgnoreCase);
        }

        // -split with a pattern.
        public static string[] Split(string input, string pattern)
        {
            return Regex.Split(input ?? "", pattern, RegexOptions.IgnoreCase);
        }

        // -replace.
        public static string Replace(string input, string pattern, string replacement)
        {
            return Regex.Replace(input ?? "", pattern, replacement, RegexOptions.IgnoreCase);
        }

        // A byte array in an if: empty is false, one byte is that byte, more
        // are true.
        public static bool IsTrue(byte[] value)
        {
            if (value == null || value.Length == 0) return false;
            return value.Length > 1 || value[0] != 0;
        }

        // A string in an if: false when null or empty.
        public static bool IsTrue(string value)
        {
            return !string.IsNullOrEmpty(value);
        }

        // [int] of a number: rounded half to even, not cut off.
        public static int Int(double value)
        {
            return Convert.ToInt32(value);
        }

        // Select-Object -Unique: minds case, keeps the first of each.
        public static List<string> Unique(IEnumerable<string> list)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var result = new List<string>();
            foreach (string s in list) { if (seen.Add(s)) result.Add(s); }
            return result;
        }
    }
}
