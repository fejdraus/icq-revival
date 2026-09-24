// The file work every client patch does: backups next to the file, the
// checksum a build is told apart by, and text read and written back as bytes.
//
// Copying, renaming and removing behave like the PowerShell cmdlets the
// patches were written with: a failure is reported and the run goes on,
// where a failed read or write of a file's bytes stops it.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IcqRevival.Patch
{
    // A text file as it was read: its text, and how to write it back.
    internal sealed class TextFile
    {
        public string Text;
        public bool Utf8;
        public bool Bom;
    }

    internal static class PatchFiles
    {
        // Where a failed copy, rename or removal is reported. The run goes on.
        public static Action<string> Error = message => Console.Error.WriteLine(message);

        static readonly Encoding Utf8Strict = new UTF8Encoding(false, true);
        static readonly Encoding Cp1251 = Encoding.GetEncoding(1251);

        // Test-Path: a file or a folder.
        public static bool Exists(string path)
        {
            return !string.IsNullOrEmpty(path) && (File.Exists(path) || Directory.Exists(path));
        }

        // Join-Path.
        public static string Join(string path, string child)
        {
            return Path.Combine(path, child);
        }

        // Split-Path -Leaf.
        public static string Leaf(string path)
        {
            return Path.GetFileName(path.TrimEnd('\\', '/'));
        }

        static void Try(Action action)
        {
            try { action(); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException || e is NotSupportedException)
            {
                Error(e.Message);
            }
        }

        // Copy-Item for a file: an existing one is replaced, and with force
        // also when it is read-only.
        public static void Copy(string from, string to, bool force)
        {
            Try(() =>
            {
                if (force && File.Exists(to))
                {
                    FileAttributes a = File.GetAttributes(to);
                    FileAttributes clear = a & ~(FileAttributes.ReadOnly | FileAttributes.Hidden);
                    if (clear != a) File.SetAttributes(to, clear);
                }
                File.Copy(from, to, true);
            });
        }

        // Rename-Item, for a file or a folder.
        public static void Rename(string path, string newName)
        {
            Try(() =>
            {
                string to = Path.Combine(Path.GetDirectoryName(path), newName);
                if (Directory.Exists(path)) Directory.Move(path, to);
                else File.Move(path, to);
            });
        }

        // Remove-Item -Force for a file.
        public static void Remove(string path)
        {
            Try(() =>
            {
                if (File.Exists(path))
                {
                    FileAttributes a = File.GetAttributes(path);
                    if ((a & FileAttributes.ReadOnly) != 0) File.SetAttributes(path, a & ~FileAttributes.ReadOnly);
                }
                File.Delete(path);
            });
        }

        // The file as it was, next to it, before the first change.
        public static void BackupOnce(string path, string suffix)
        {
            string backup = path + suffix;
            if (!Exists(backup)) Copy(path, backup, false);
        }

        // Get-ChildItem -Filter *.<ext> -File: the files of one folder with
        // that extension, hidden ones left out, in the order the folder
        // lists them. The extension is matched whole: "*.xml" is not "*.xmlx".
        public static List<string> FilesWithExtension(string dir, string extension)
        {
            var result = new List<string>();
            if (!Directory.Exists(dir))
            {
                Error("Cannot find path '" + dir + "' because it does not exist.");
                return result;
            }
            foreach (string f in Directory.GetFiles(dir, "*"))
            {
                if (!f.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) continue;
                if ((File.GetAttributes(f) & FileAttributes.Hidden) != 0) continue;
                result.Add(f);
            }
            return result;
        }

        // Get-ChildItem -Recurse -Force: everything under a folder, hidden or
        // not. Each folder lists its folders and then its files, and then the
        // ones inside its folders follow; links to folders are not followed.
        public static List<FileSystemInfo> Tree(string root)
        {
            var result = new List<FileSystemInfo>();
            Walk(new DirectoryInfo(root), result);
            return result;
        }

        static void Walk(DirectoryInfo dir, List<FileSystemInfo> result)
        {
            DirectoryInfo[] dirs;
            FileInfo[] files;
            try
            {
                dirs = dir.GetDirectories();
                files = dir.GetFiles();
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                Error(e.Message);
                return;
            }
            result.AddRange(dirs);
            result.AddRange(files);
            foreach (DirectoryInfo d in dirs)
            {
                if ((d.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                Walk(d, result);
            }
        }

        // The checksum a file is told apart by, as upper-case hex.
        public static string Sha256(string path)
        {
            using (var sha = SHA256.Create())
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "");
            }
        }

        // Read and written as bytes so nothing changes but the edit itself: the
        // line endings stay, and a byte order mark stays where there was one.
        // UTF-8 when the bytes are that, Windows-1251 otherwise.
        public static TextFile ReadText(string path)
        {
            byte[] bytes = File.ReadAllBytes(path);
            bool bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
            int start = bom ? 3 : 0;
            try
            {
                return new TextFile { Text = Utf8Strict.GetString(bytes, start, bytes.Length - start), Utf8 = true, Bom = bom };
            }
            catch (DecoderFallbackException)
            {
                return new TextFile { Text = Cp1251.GetString(bytes), Utf8 = false, Bom = false };
            }
        }

        public static void WriteText(string path, TextFile file)
        {
            byte[] body = file.Utf8 ? Utf8Strict.GetBytes(file.Text) : Cp1251.GetBytes(file.Text);
            if (file.Bom)
            {
                var withBom = new byte[body.Length + 3];
                withBom[0] = 0xEF; withBom[1] = 0xBB; withBom[2] = 0xBF;
                Buffer.BlockCopy(body, 0, withBom, 3, body.Length);
                body = withBom;
            }
            File.WriteAllBytes(path, body);
        }
    }
}
