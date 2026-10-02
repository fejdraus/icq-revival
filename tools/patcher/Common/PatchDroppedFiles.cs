// Files an earlier build of a patch added to the client - files the client
// never had - that the patch no longer puts in: the E2E lock button of the
// message window (ICQ 6.5 and 7.2), tried and dropped. They have no original
// to back up, so "Restore original" alone would leave them behind; Apply and
// Restore take them out wherever they are found.
//
// Should a file of that name have been there before the earlier build put its
// own - which the client never ships - that build kept it under the backup
// suffix, and it comes back in its place.

using System.Collections.Generic;
using System.IO;

namespace IcqRevival.Patch
{
    internal static class DroppedFiles
    {
        // Takes out one file (relative to the client's folder): what was there
        // before comes back from its backup, or, with none, the file is
        // removed. True when something was done.
        public static bool Take(string root, string relative, IEnumerable<string> suffixes)
        {
            string path = PatchFiles.Join(root, relative);
            foreach (string suffix in suffixes)
            {
                if (!File.Exists(path + suffix)) continue;
                PatchFiles.Copy(path + suffix, path, true);
                PatchFiles.Remove(path + suffix);
                return true;
            }
            if (!File.Exists(path)) return false;
            PatchFiles.Remove(path);
            return true;
        }

        // Takes out every one of them; how many were taken.
        public static int TakeAll(string root, IEnumerable<string> relatives, IEnumerable<string> suffixes)
        {
            int count = 0;
            foreach (string relative in relatives)
            {
                if (Take(root, relative, suffixes)) count++;
            }
            return count;
        }
    }
}
