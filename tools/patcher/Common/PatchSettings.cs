// What a patch remembers between runs, under its own key in HKCU, and the
// server domain every patch asks for.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

namespace IcqRevival.Patch
{
    internal static class PatchSettings
    {
        // A registry value as a list of strings: a multi-string as it is, any
        // other value as its one string.
        public static List<string> Strings(object value)
        {
            if (value == null) return new List<string>();
            var many = value as string[];
            if (many != null) return many.ToList();
            return new List<string> { Text(value) };
        }

        // A registry value as PowerShell turns it into a string: the parts of a
        // multi-string joined by spaces.
        public static string Text(object value)
        {
            if (value == null) return null;
            var many = value as string[];
            if (many != null) return string.Join(" ", many);
            return Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
        }

        // One value of the patch's key: null when the key is not there, an
        // empty string when only the value is not.
        public static string Read(string settingsKey, string name)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(settingsKey))
                {
                    if (key == null) return null;
                    return Text(key.GetValue(name)) ?? "";
                }
            }
            catch { return null; }
        }

        public static void Save(string settingsKey, string name, string value)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(settingsKey))
                {
                    key.SetValue(name, value ?? "", RegistryValueKind.String);
                }
            }
            catch { }
        }
    }

    internal static class Domain
    {
        // The domain out of whatever was typed: a scheme, a port or a path after
        // it - habits from older versions of the patches - are dropped.
        public static string Of(string value)
        {
            string v = (value ?? "").Trim();
            v = Ps.Replace(v, "^[A-Za-z][A-Za-z0-9+.-]*://", "");
            v = Ps.Split(v, "[/?#]")[0];
            v = Ps.Split(v, ":")[0];
            return v.ToLowerInvariant();
        }

        public static bool IsValid(string value)
        {
            return Ps.Match(value ?? "", "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$");
        }
    }
}
