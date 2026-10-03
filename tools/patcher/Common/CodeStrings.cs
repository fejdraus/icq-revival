// Addresses built into a client's DLLs and programs, written over in place.
//
// Some of the old hosts a client contacts are not in any file it reads but
// in its code, as the default of a setting or as the address itself: the
// crash and statistics reporter, the update and package lists, the SIP
// voice-quality server of calls, the NAT lookup, the HTTP tunnel. Each is
// written over where it is, in its own encoding (ASCII or UTF-16), with a
// replacement no longer than the original and zeros after it, so nothing in
// the file moves. The replacements go to the client's own machine
// (127.0.0.1, port 9 for a URL, where nothing listens): the connection is
// refused at once, as on a dead host, and nothing leaves the machine.
//
// A string is found by its content, not by its offset, aligned as its
// encoding is, and has to be there once - or not at all, when that build of
// the client does not have it. Found more than once, the file is taken for
// another version and left alone. The file itself is recognised by the
// checksum of its original before a byte is written, and it is always built
// again from that original, so taking a change out leaves exactly the
// original behind.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IcqRevival.Patch
{
    internal sealed class CodeString
    {
        public string File;    // relative to the client's folder
        public bool Wide;      // UTF-16, or ASCII
        public string From;
        public string To;      // no longer than From
        public string Part;    // the line of the report it is chosen by
        public bool Infix;     // a host inside a longer string: matched without
                               // a terminator, so the tail (a path) stays but is
                               // cut off by the zeros after the replacement.
    }

    internal static class CodeStrings
    {
        // Where nothing listens, on the client's own machine.
        public const string Nowhere = "http://127.0.0.1:9";
        public const string NoHost = "127.0.0.1";

        // The bytes of the string as it is in the file: the text, then zeros
        // to the length of the original with its terminator.
        public static byte[] Block(CodeString s, string text)
        {
            Encoding e = s.Wide ? Encoding.Unicode : Encoding.ASCII;
            int width = s.Infix ? 0 : (s.Wide ? 2 : 1);
            byte[] block = new byte[e.GetByteCount(s.From) + width];
            byte[] t = e.GetBytes(text);
            if (t.Length > block.Length - width) throw new InvalidOperationException("\"" + s.To + "\" is longer than \"" + s.From + "\"");
            Array.Copy(t, block, t.Length);
            return block;
        }

        // Where the block is, at an offset of its alignment.
        public static List<int> Find(byte[] bytes, byte[] block, int align)
        {
            var found = new List<int>();
            for (int i = 0; i + block.Length <= bytes.Length; i += align)
            {
                if (bytes[i] != block[0]) continue;
                int k = 1;
                while (k < block.Length && bytes[i + k] == block[k]) k++;
                if (k == block.Length) found.Add(i);
            }
            return found;
        }

        // How many of the strings have an occurrence still as it came (from)
        // and how many are fully written over (to). A string may be there more
        // than once - a host named in two places - and every occurrence is
        // counted together: one such string is "original" while any occurrence
        // is unchanged. The file itself is checksum-gated before this is
        // trusted, so a stray partial match is not mistaken for another build.
        public static void Count(byte[] bytes, IEnumerable<CodeString> strings, out int original, out int changed)
        {
            original = 0; changed = 0;
            foreach (CodeString s in strings)
            {
                int align = s.Wide ? 2 : 1;
                int from = Find(bytes, Block(s, s.From), align).Count;
                if (from > 0) { original++; continue; }
                // Two hosts of one length written over with the same
                // replacement look alike afterwards, so a replacement counts
                // once however often it is there.
                if (Find(bytes, Block(s, s.To), align).Count > 0) changed++;
            }
        }

        // patched / original / partly / missing (none of them in this build).
        // Of the bytes of the file as it is now.
        public static string State(byte[] bytes, IEnumerable<CodeString> strings)
        {
            int original, changed;
            Count(bytes, strings, out original, out changed);
            if (original == 0 && changed == 0) return "missing";
            if (original == 0) return "patched";
            if (changed == 0) return "original";
            return "partly";
        }

        // Writes every occurrence of each string over in the bytes of the
        // original.
        public static bool Apply(byte[] bytes, IEnumerable<CodeString> strings)
        {
            foreach (CodeString s in strings)
            {
                byte[] to = Block(s, s.To);
                foreach (int at in Find(bytes, Block(s, s.From), s.Wide ? 2 : 1))
                {
                    Array.Copy(to, 0, bytes, at, to.Length);
                }
            }
            return true;
        }

        public static IEnumerable<string> Files(IEnumerable<CodeString> strings)
        {
            return strings.Select(s => s.File).Distinct(StringComparer.OrdinalIgnoreCase);
        }

        public static CodeString A(string file, string part, string from, string to)
        {
            return new CodeString { File = file, Part = part, Wide = false, From = from, To = to };
        }

        public static CodeString W(string file, string part, string from, string to)
        {
            return new CodeString { File = file, Part = part, Wide = true, From = from, To = to };
        }

        // A host inside a longer UTF-16 string (a URL): matched with no
        // terminator, so the path after it stays but is cut off by the zeros.
        public static CodeString Wi(string file, string part, string from, string to)
        {
            return new CodeString { File = file, Part = part, Wide = true, Infix = true, From = from, To = to };
        }
    }
}
