// The E2E add-on DLLs this patch was built with, by SHA-256 (fourth review of
// 2026-10, finding I).
//
// The version resource (ProductName, InternalName) says a DLL claims to be
// ours; anyone can write that. tools\common\Build-Patches.ps1 builds the
// add-on first, hashes the DLL this patch hands out and embeds the list in
// the exe as the resource "e2e-manifest.txt": one line per DLL,
// "<SHA-256 in hex> <file name>". Before a DLL is copied into the client -
// and before one already there counts as ours - its hash must be on that
// list. A patch built without the add-on has no list and accepts no DLL.
// (Authenticode signing may come later; this needs no certificate.)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace IcqRevival.Patch
{
    internal static class E2eManifest
    {
        public const string Resource = "e2e-manifest.txt";

        static string[] hashes;

        // The hashes on the list, upper case; empty without a list.
        public static string[] Hashes
        {
            get
            {
                if (hashes != null) return hashes;
                var list = new List<string>();
                using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(Resource))
                {
                    if (s != null)
                    {
                        using (var r = new StreamReader(s))
                        {
                            string line;
                            while ((line = r.ReadLine()) != null)
                            {
                                string[] parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 1 && parts[0].Length == 64 && parts[0].All(Uri.IsHexDigit)) list.Add(parts[0].ToUpperInvariant());
                            }
                        }
                    }
                }
                hashes = list.ToArray();
                return hashes;
            }
        }

        // Whether path is a DLL on the list.
        public static bool Knows(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            string h = PatchFiles.Sha256(path);
            return h != null && Hashes.Contains(h.ToUpperInvariant());
        }

        // Why path is not taken, for the row and the report.
        public static string Why(string path)
        {
            if (Hashes.Length == 0) return "this patch was built without the E2E add-on (no manifest of its DLLs)";
            return Path.GetFileName(path) + " is not the E2E add-on this patch was built with (its SHA-256 is not in the patch's manifest)";
        }
    }
}
