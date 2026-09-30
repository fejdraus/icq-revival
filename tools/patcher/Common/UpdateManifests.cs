// The update manifests of the Boxely clients, ICQ 6.5 and ICQ 7.2.
//
// Each folder the client updates on its own - itself, its configuration
// files, every add-on package - keeps an "updates" folder with a manifest in
// it: the files of that folder, each with the MD5 and size it should have.
// The client fetches the manifests again from update.icq.com, which still
// answers - http://update.icq.com/cb/icq6/<distribution>/ConfigFiles/updates.xml
// for the configuration files, <package>/manifest.xml for the packages - and
// puts every file that no longer matches back from there: configfiles.zip,
// the package's zip. It skips that check only for its own files, when the
// manifest is for the build it is. A file the manifest does not list is left
// alone. The fetch asks for the manifest If-Modified-Since the time of the
// one it has, and the one it has is kept on "304 Not Modified".
//
// So a file the patch changes has to be listed as it is now, or the client
// takes the change back: its entry gets the file's MD5 and size, the entry of
// a file taken out of the way is dropped, the first line - the MD5 of the
// rest - is worked out again, and the manifest keeps its time, so the client
// goes on using it. The manifest is backed up once like any other file, and
// "Restore original" puts it back with the rest.
//
// A manifest is its first line, "<!--md5-->", and <manifest> after it with
// <file id path hash size> for each file; an entry of the client's own
// manifest also lists where to fetch the file from, inside it.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace IcqRevival.Patch
{
    internal static class UpdateManifests
    {
        const string Folder = "updates";
        const string Name = "manifest";

        // Byte for byte: the paths in the manifests are plain ASCII.
        static readonly Encoding Bytes = Encoding.GetEncoding(28591);

        static readonly Regex Entry = new Regex(
            "<file\\s+id=\"[^\"]*\"\\s+path=\"(?<path>[^\"]*)\"\\s+hash=\"(?<hash>[0-9A-Fa-f]*)\"\\s+size=\"(?<size>\\d*)\"\\s*(?:/>|>.*?</file>)",
            RegexOptions.Singleline);

        // One manifest as read: the folder it covers, its first line with the
        // line break after it, and the rest, which the first line is the MD5 of.
        sealed class Manifest
        {
            public string Path;
            public string Covers;
            public string Head;
            public string Body;
            // The MD5 of each file by its path, once asked for.
            public Dictionary<string, string> Hashes;
        }

        static string Md5(string text)
        {
            using (var md5 = MD5.Create())
            {
                return BitConverter.ToString(md5.ComputeHash(Bytes.GetBytes(text))).Replace("-", "").ToLowerInvariant();
            }
        }

        // The manifest at this path, or null when there is none or it is not
        // one: a fetch that went wrong leaves whatever page came back.
        static Manifest Read(string path)
        {
            if (!File.Exists(path)) return null;
            // The states are worked out many times over: a manifest is taken
            // apart again only when its bytes have changed.
            string text = Bytes.GetString(File.ReadAllBytes(path));
            KeyValuePair<string, Manifest> seen;
            if (cache.TryGetValue(path, out seen) && seen.Key == text) return seen.Value;
            Manifest m = Parse(path, text);
            cache[path] = new KeyValuePair<string, Manifest>(text, m);
            return m;
        }

        static readonly Dictionary<string, KeyValuePair<string, Manifest>> cache =
            new Dictionary<string, KeyValuePair<string, Manifest>>(StringComparer.OrdinalIgnoreCase);

        static Manifest Parse(string path, string text)
        {
            int end = text.IndexOf('\n');
            if (end < 0) return null;
            string head = text.Substring(0, end + 1);
            string body = text.Substring(end + 1);
            Match sum = Regex.Match(head, "^<!--([0-9a-f]{32})-->\\r?\\n$");
            if (!sum.Success || sum.Groups[1].Value != Md5(body) || !body.Contains("<manifest")) return null;
            return new Manifest
            {
                Path = path,
                Covers = System.IO.Path.GetDirectoryName(System.IO.Path.GetDirectoryName(path)),
                Head = head,
                Body = body,
            };
        }

        // Every manifest in the client's folder.
        static List<Manifest> All(string root)
        {
            return PatchFiles.Tree(root)
                .Where(i => i is FileInfo && Ps.Eq(i.Name, Name) && Ps.Eq(((FileInfo)i).Directory.Name, Folder))
                .Select(i => Read(i.FullName))
                .Where(m => m != null)
                .ToList();
        }

        // Whether the patch has changed a file or taken it away: there is a
        // backup next to it, or next to a folder it is in.
        static bool Touched(string file, string covers, IEnumerable<string> suffixes)
        {
            if (suffixes.Any(s => PatchFiles.Exists(file + s))) return true;
            string dir = System.IO.Path.GetDirectoryName(file);
            while (dir != null && dir.Length > covers.Length)
            {
                if (suffixes.Any(s => PatchFiles.Exists(dir + s))) return true;
                dir = System.IO.Path.GetDirectoryName(dir);
            }
            return false;
        }

        // Lists every file the patch has touched as it is now, in every
        // manifest of the client, and gives the manifests changed. A manifest
        // is backed up with the suffix before its first change.
        public static List<string> Sync(string root, ICollection<string> suffixes, string suffix)
        {
            var changed = new List<string>();
            foreach (Manifest m in All(root))
            {
                string body = Entry.Replace(m.Body, e =>
                {
                    string file = System.IO.Path.Combine(m.Covers, e.Groups["path"].Value);
                    if (!Touched(file, m.Covers, suffixes)) return e.Value;
                    if (!File.Exists(file)) return "";
                    string hash = PatchFiles.Md5(file);
                    string size = new FileInfo(file).Length.ToString();
                    Group h = e.Groups["hash"], s = e.Groups["size"];
                    // The hash comes before the size: the size first, so the
                    // hash keeps its place.
                    string value = e.Value;
                    value = value.Substring(0, s.Index - e.Index) + size + value.Substring(s.Index - e.Index + s.Length);
                    value = value.Substring(0, h.Index - e.Index) + hash + value.Substring(h.Index - e.Index + h.Length);
                    return value;
                });
                if (body == m.Body) continue;
                // The time the client asks the server about: kept, so it keeps
                // this manifest rather than fetching the original again.
                DateTime time = File.GetLastWriteTimeUtc(m.Path);
                PatchFiles.BackupOnce(m.Path, suffix);
                string head = Regex.Replace(m.Head, "[0-9a-f]{32}", Md5(body));
                // The client keeps its manifests hidden, and a hidden file
                // can't be overwritten: the attributes go and come back.
                FileAttributes a = File.GetAttributes(m.Path);
                FileAttributes clear = a & ~(FileAttributes.ReadOnly | FileAttributes.Hidden);
                if (clear != a) File.SetAttributes(m.Path, clear);
                File.WriteAllBytes(m.Path, Bytes.GetBytes(head + body));
                File.SetLastWriteTimeUtc(m.Path, time);
                if (clear != a) File.SetAttributes(m.Path, a);
                changed.Add(m.Path);
            }
            return changed;
        }

        // The MD5 the client's own manifests list for a file, as they came
        // from its update server - the backup of a manifest the patch has
        // changed - or null when none lists it. The nearest manifest first.
        public static string Listed(string root, string file, string suffix)
        {
            string full = System.IO.Path.GetFullPath(System.IO.Path.Combine(root, file));
            string top = System.IO.Path.GetFullPath(root).TrimEnd('\\');
            for (string dir = System.IO.Path.GetDirectoryName(full); dir != null && dir.Length >= top.Length; dir = System.IO.Path.GetDirectoryName(dir))
            {
                string path = System.IO.Path.Combine(dir, Folder, Name);
                Manifest m = Read(File.Exists(path + suffix) ? path + suffix : path);
                if (m == null) continue;
                if (m.Hashes == null)
                {
                    m.Hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (Match e in Entry.Matches(m.Body))
                    {
                        m.Hashes[e.Groups["path"].Value.Replace('/', '\\')] = e.Groups["hash"].Value.ToLowerInvariant();
                    }
                }
                string hash;
                if (m.Hashes.TryGetValue(full.Substring(dir.Length).TrimStart('\\'), out hash)) return hash;
            }
            return null;
        }
    }
}
