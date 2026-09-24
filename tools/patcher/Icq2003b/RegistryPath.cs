// Registry values by PowerShell-style paths (HKLM:\..., HKCU:\...), with the
// behaviour of the cmdlets the patch was written with: HKLM as a 64-bit
// PowerShell sees it, and a value that is set again keeps its kind.

using System;
using Microsoft.Win32;

namespace IcqRevival.Patch
{
    internal static class RegistryPath
    {
        static RegistryKey Hive(string path, out string sub)
        {
            int colon = path.IndexOf(":\\", StringComparison.Ordinal);
            string hive = path.Substring(0, colon);
            sub = path.Substring(colon + 2);
            if (hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase))
            {
                return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
                    Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
            }
            if (hive.Equals("HKCU", StringComparison.OrdinalIgnoreCase))
            {
                return RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            }
            throw new ArgumentException("not a registry path: " + path);
        }

        static RegistryKey Open(string path, bool writable)
        {
            string sub;
            using (RegistryKey hive = Hive(path, out sub))
            {
                return hive.OpenSubKey(sub, writable);
            }
        }

        // Test-Path.
        public static bool Exists(string path)
        {
            try
            {
                using (RegistryKey k = Open(path, false)) return k != null;
            }
            catch { return false; }
        }

        // (Get-ItemProperty path).name, as text; null when the key or the value
        // is not there, or cannot be read.
        public static string Get(string path, string name)
        {
            try
            {
                using (RegistryKey k = Open(path, false))
                {
                    if (k == null) return null;
                    return PatchSettings.Text(k.GetValue(name));
                }
            }
            catch { return null; }
        }

        // New-Item -Force for a key that may be missing.
        public static void Create(string path)
        {
            string sub;
            using (RegistryKey hive = Hive(path, out sub))
            using (hive.CreateSubKey(sub)) { }
        }

        // Set-ItemProperty: the key must exist, and a value there keeps its kind.
        public static void Set(string path, string name, string value)
        {
            using (RegistryKey k = Open(path, true))
            {
                if (k == null) throw new InvalidOperationException("Cannot find path '" + path + "' because it does not exist.");
                RegistryValueKind kind = RegistryValueKind.String;
                if (Array.IndexOf(k.GetValueNames(), name) >= 0 || (name == "" && k.GetValue("") != null))
                {
                    kind = k.GetValueKind(name);
                }
                if (kind == RegistryValueKind.MultiString) k.SetValue(name, new[] { value }, kind);
                else k.SetValue(name, value, kind);
            }
        }

        // Remove-ItemProperty -ErrorAction SilentlyContinue.
        public static void Remove(string path, string name)
        {
            try
            {
                using (RegistryKey k = Open(path, true))
                {
                    if (k != null) k.DeleteValue(name, false);
                }
            }
            catch { }
        }
    }
}
