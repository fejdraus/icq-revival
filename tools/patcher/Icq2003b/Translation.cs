// The Ukrainian interface the patch carries: every translated resource of the
// client's programs, the texts that live in a program's data or in the skin,
// and the blank "Send By:" in both languages.
//
// The source is ..\..\icq2003b\patch\ICQ-2003b-uk-UA.txt, written by the
// translation tools. It is decoded at build time (build\ConvertTranslation.cs)
// into two files the exe carries as they are: translation.dat, the raw bytes
// of every item one after another, and translation.idx, a UTF-8 index into
// them. Here the index is only read; nothing is unpacked or decoded.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IcqRevival.Patch
{
    internal sealed class TrItem
    {
        public string Key;      // "type|name|lang"
        public byte[] Bytes;    // the translated data
        public string From;     // SHA-256 of the English data
    }

    internal sealed class TrPlace
    {
        public int Offset;
        public byte[] Bytes;
        public byte[] Original;
    }

    internal sealed class TrFile
    {
        public string Rel;
        public long Size;
        public List<TrItem> Items = new List<TrItem>();
        public List<TrPlace> Inplace = new List<TrPlace>();
        // A text file written whole, and the SHA-256 of the English one.
        public byte[] Whole;
        public string WholeFrom;
    }

    internal sealed class TrSendBy
    {
        public string File;
        public string Key;
        public string From;
        public byte[] BlankEn;
        public byte[] BlankUk;
    }

    internal sealed class Translation
    {
        // In the order of the source; looked up ignoring case, the first of a name.
        public readonly List<TrFile> Files = new List<TrFile>();
        public TrSendBy SendBy;

        public TrFile File(string rel)
        {
            if (rel == null) return null;
            foreach (TrFile f in Files)
            {
                if (string.Equals(f.Rel, rel, StringComparison.OrdinalIgnoreCase)) return f;
            }
            return null;
        }

        static Translation loaded;

        public static Translation Get()
        {
            if (loaded == null) loaded = Parse(Resource("translation.idx"), Resource("translation.dat"));
            return loaded;
        }

        static byte[] Resource(string name)
        {
            using (Stream s = typeof(Translation).Assembly.GetManifestResourceStream(name))
            {
                if (s == null) throw new InvalidOperationException("The translation is missing from the exe: " + name);
                var ms = new MemoryStream();
                s.CopyTo(ms);
                return ms.ToArray();
            }
        }

        // The index: one record per line, fields split by tabs.
        //   language <name>
        //   file     <rel> <size>
        //   item     <type|name|lang> <sha256 of the English data> <offset> <length>
        //   place    <file offset> <offset> <length> <offset of the original> <its length>
        //   whole    <sha256 of the English file> <offset> <length>
        //   sendby   <file> <type|name|lang> <sha256> <offset> <length> <offset> <length>
        // A line starting with # is a comment. Offsets and lengths are into the
        // data.
        static Translation Parse(byte[] index, byte[] data)
        {
            Func<string, string, byte[]> slice = (offset, length) =>
            {
                long o = long.Parse(offset, CultureInfo.InvariantCulture), n = long.Parse(length, CultureInfo.InvariantCulture);
                if (o < 0 || n < 0 || o + n > data.Length) throw new InvalidDataException("The translation in the exe is damaged.");
                var b = new byte[n];
                Buffer.BlockCopy(data, (int)o, b, 0, (int)n);
                return b;
            };
            var t = new Translation();
            TrFile file = null;
            foreach (string raw in new UTF8Encoding(false).GetString(index).Split('\n'))
            {
                string line = raw.TrimEnd('\r');
                if (line.Length == 0 || line[0] == '#') continue;
                string[] f = line.Split('\t');
                switch (f[0])
                {
                    case "file":
                        if (f.Length < 3) break;
                        file = new TrFile { Rel = f[1], Size = long.Parse(f[2], CultureInfo.InvariantCulture) };
                        t.Files.Add(file);
                        break;
                    case "item":
                        if (f.Length < 5 || file == null) break;
                        file.Items.Add(new TrItem { Key = f[1], From = f[2], Bytes = slice(f[3], f[4]) });
                        break;
                    case "place":
                        if (f.Length < 6 || file == null) break;
                        file.Inplace.Add(new TrPlace
                        {
                            Offset = int.Parse(f[1], CultureInfo.InvariantCulture),
                            Bytes = slice(f[2], f[3]),
                            Original = slice(f[4], f[5]),
                        });
                        break;
                    case "whole":
                        if (f.Length < 4 || file == null) break;
                        file.WholeFrom = f[1];
                        file.Whole = slice(f[2], f[3]);
                        break;
                    case "sendby":
                        if (f.Length < 8) break;
                        t.SendBy = new TrSendBy
                        {
                            File = f[1], Key = f[2], From = f[3],
                            BlankEn = slice(f[4], f[5]), BlankUk = slice(f[6], f[7]),
                        };
                        break;
                }
            }
            return t;
        }

        // SHA-256 of some bytes, as lower-case hex.
        public static string Sha(byte[] bytes)
        {
            using (var sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
