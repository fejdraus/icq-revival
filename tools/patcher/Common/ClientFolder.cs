// Finding the client's folder on its own: next to the patch first (dropped
// into the client's folder), then from the registry, then the standard path.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace IcqRevival.Patch
{
    internal sealed class ClientSearch
    {
        // The name of the client's exe under App Paths, e.g. ICQ.exe.
        public string AppPathsExe;
        // Whether the App Paths value is taken out of its quotes first.
        public bool TrimQuotes;
        // What the uninstall entry's DisplayName starts with, as a pattern.
        public string DisplayName;
        // Whether the folder of the exe in UninstallString counts too.
        public bool UseUninstallString;
        // The folder under Program Files the installer picks, e.g. ICQ6.5.
        public string StandardFolder;
        // Whether a folder is the client's.
        public Func<string, bool> IsClient;
    }

    internal static class ClientFolder
    {
        // The folder the patch itself runs from.
        public static string Self()
        {
            try
            {
                return Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
            }
            catch
            {
                return AppDomain.CurrentDomain.BaseDirectory;
            }
        }

        // HKLM as a 64-bit PowerShell sees it: SOFTWARE is the 64-bit view,
        // SOFTWARE\WOW6432Node the 32-bit one.
        static RegistryKey Machine()
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
                Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
        }

        public static string Find(ClientSearch search)
        {
            var candidates = new List<string>();
            string self = Self();
            if (!string.IsNullOrEmpty(self)) candidates.Add(self);

            foreach (string sub in new[] {
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\" + search.AppPathsExe,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + search.AppPathsExe })
            {
                try
                {
                    using (RegistryKey hklm = Machine())
                    using (RegistryKey key = hklm.OpenSubKey(sub))
                    {
                        if (key == null) continue;
                        string exe = PatchSettings.Text(key.GetValue(""));
                        if (!string.IsNullOrEmpty(exe))
                        {
                            if (search.TrimQuotes) exe = exe.Trim('"');
                            candidates.Add(Path.GetDirectoryName(exe));
                        }
                    }
                }
                catch { }
            }

            var uninstall = new[] {
                new KeyValuePair<bool, string>(true, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                new KeyValuePair<bool, string>(true, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                new KeyValuePair<bool, string>(false, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            };
            foreach (KeyValuePair<bool, string> u in uninstall)
            {
                try
                {
                    using (RegistryKey hive = u.Key ? Machine() : Registry.CurrentUser)
                    using (RegistryKey key = hive.OpenSubKey(u.Value))
                    {
                        if (key == null) continue;
                        foreach (string name in key.GetSubKeyNames())
                        {
                            try
                            {
                                using (RegistryKey d = key.OpenSubKey(name))
                                {
                                    if (d == null) continue;
                                    string display = PatchSettings.Text(d.GetValue("DisplayName"));
                                    if (!Ps.Match(display ?? "", search.DisplayName)) continue;
                                    string location = PatchSettings.Text(d.GetValue("InstallLocation"));
                                    if (!string.IsNullOrEmpty(location)) candidates.Add(location);
                                    if (search.UseUninstallString)
                                    {
                                        // The command line may quote the program and add arguments after it.
                                        Match m = Regex.Match(PatchSettings.Text(d.GetValue("UninstallString")) ?? "",
                                            "^\\s*\"?(?<exe>[^\"]+?\\.exe)", RegexOptions.IgnoreCase);
                                        if (m.Success)
                                        {
                                            try { candidates.Add(Path.GetDirectoryName(m.Groups["exe"].Value)); } catch { }
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }

            foreach (string b in new[] { Environment.GetEnvironmentVariable("ProgramFiles(x86)"), Environment.GetEnvironmentVariable("ProgramFiles") })
            {
                if (!string.IsNullOrEmpty(b)) candidates.Add(Path.Combine(b, search.StandardFolder));
            }

            foreach (string c in candidates)
            {
                string full;
                try { full = Path.GetFullPath(c); } catch { continue; }
                if (search.IsClient(full)) return full;
            }
            return null;
        }
    }
}
