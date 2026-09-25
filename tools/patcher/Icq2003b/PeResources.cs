// Reading and writing the resources of a Windows program over its bytes, so
// the patch never asks Windows to do it - no loading another program as a
// data file, no BeginUpdateResource. The port of
// tools\patcher-cpp\common\PeResources.cpp, with the same layout rules, so the
// two builds write the same bytes.
//
// The layout follows what Windows itself does to these files (checked against
// the output of UpdateResource): the .rsrc section is rebuilt where it is, at
// its own address, and only its size changes. The raw data of the sections
// after it slides by the change in its aligned size - their addresses do not
// move, so nothing else in the file has to be fixed up but the file offsets
// that point past it - and any bytes after the last section (an overlay) are
// kept. Reference: tools\icq2003b\translate\icqres.py, which parses the same
// tree.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace IcqRevival.Patch
{
    internal static class PeResources
    {
        // A type, name or language: a number, or a name, upper-cased as the
        // resource directory keeps it.
        internal struct Id
        {
            public bool IsName;
            public uint Number;
            public string Name;

            public static Id Of(uint n) { return new Id { Number = n, Name = "" }; }
            public static Id OfName(string s) { return new Id { IsName = true, Name = s.ToUpperInvariant() }; }

            public bool Same(Id o)
            {
                if (IsName != o.IsName) return false;
                return IsName ? string.Equals(Name, o.Name, StringComparison.Ordinal) : Number == o.Number;
            }
        }

        internal struct Key
        {
            public Id Type;
            public Id Name;
            public uint Lang;
        }

        // A file the reader cannot make sense of.
        internal sealed class BadFileException : Exception
        {
            public BadFileException(string message) : base(message) { }
        }

        static ushort U16(byte[] b, long at)
        {
            if (at < 0 || at + 2 > b.Length) throw new BadFileException("The file is not a valid program (truncated).");
            return (ushort)(b[at] | (b[at + 1] << 8));
        }

        static uint U32(byte[] b, long at)
        {
            if (at < 0 || at + 4 > b.Length) throw new BadFileException("The file is not a valid program (truncated).");
            return (uint)(b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24));
        }

        static void PutU16(byte[] b, long at, ushort v)
        {
            b[at] = (byte)v;
            b[at + 1] = (byte)(v >> 8);
        }

        static void PutU32(byte[] b, long at, uint v)
        {
            b[at] = (byte)v;
            b[at + 1] = (byte)(v >> 8);
            b[at + 2] = (byte)(v >> 16);
            b[at + 3] = (byte)(v >> 24);
        }

        static uint Align(uint v, uint a) { return a == 0 ? v : (v + a - 1) / a * a; }

        // The pieces of the PE headers the resource work needs.
        sealed class Section
        {
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public long HeaderAt;  // where this section header sits in the file
        }

        sealed class Pe
        {
            public long OptionalAt;
            public bool Plus;
            public uint FileAlignment;
            public uint SectionAlignment;
            public long SizeOfImageAt;
            public long CheckSumAt;
            public long ResourceDirAt;
            public uint ResourceVA;
            public uint ResourceSize;
            public List<Section> Sections = new List<Section>();
        }

        static Pe ParseHeaders(byte[] f)
        {
            if (f.Length < 0x40 || f[0] != 'M' || f[1] != 'Z') throw new BadFileException("The file is not a valid program (no MZ).");
            uint peAt = U32(f, 0x3C);
            if ((long)peAt + 24 > f.Length || U32(f, peAt) != 0x00004550) throw new BadFileException("The file is not a valid program (no PE).");
            var pe = new Pe();
            ushort numSections = U16(f, peAt + 6);
            ushort optSize = U16(f, peAt + 20);
            pe.OptionalAt = peAt + 24;
            ushort magic = U16(f, pe.OptionalAt);
            pe.Plus = magic == 0x20B;
            if (magic != 0x10B && magic != 0x20B) throw new BadFileException("The file is not a valid program (optional header).");
            pe.FileAlignment = U32(f, pe.OptionalAt + 36);
            pe.SectionAlignment = U32(f, pe.OptionalAt + 32);
            pe.SizeOfImageAt = pe.OptionalAt + 56;
            pe.CheckSumAt = pe.OptionalAt + 64;
            // The data directory begins after the fixed part: 96 bytes for PE32,
            // 112 for PE32+. Entry 2 is the resource table.
            long dirAt = pe.OptionalAt + (pe.Plus ? 112 : 96);
            pe.ResourceDirAt = dirAt + 2 * 8;
            pe.ResourceVA = U32(f, pe.ResourceDirAt);
            pe.ResourceSize = U32(f, pe.ResourceDirAt + 4);
            long secAt = pe.OptionalAt + optSize;
            for (int i = 0; i < numSections; i++)
            {
                long at = secAt + i * 40;
                if (at + 40 > f.Length) throw new BadFileException("The file is not a valid program (section table).");
                pe.Sections.Add(new Section
                {
                    VirtualSize = U32(f, at + 8),
                    VirtualAddress = U32(f, at + 12),
                    SizeOfRawData = U32(f, at + 16),
                    PointerToRawData = U32(f, at + 20),
                    HeaderAt = at,
                });
            }
            return pe;
        }

        // The section that holds a virtual address.
        static Section SectionOf(Pe pe, uint rva)
        {
            foreach (Section s in pe.Sections)
            {
                uint size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size) return s;
            }
            return null;
        }

        // --- the resource tree -------------------------------------------------------
        //
        // Three levels: type, then name, then language; each language points at one
        // run of bytes. Every offset in a directory is measured from the start of
        // the resource section; a data entry's address is a virtual address in the
        // image.

        sealed class Leaf
        {
            public uint Lang;
            public uint CodePage;
            public byte[] Data;
        }

        sealed class NameNode
        {
            public Id Name;
            public List<Leaf> Langs = new List<Leaf>();
        }

        sealed class TypeNode
        {
            public Id Type;
            public List<NameNode> Names = new List<NameNode>();
        }

        static string ReadDirString(byte[] f, long b, uint offset)
        {
            long at = b + offset;
            ushort len = U16(f, at);
            var chars = new char[len];
            for (int i = 0; i < len; i++) chars[i] = (char)U16(f, at + 2 + 2 * i);
            return new string(chars);
        }

        static Id ReadId(byte[] f, long b, uint nameField)
        {
            if ((nameField & 0x80000000u) != 0) return Id.OfName(ReadDirString(f, b, nameField & 0x7FFFFFFFu));
            return Id.Of(nameField);
        }

        static List<KeyValuePair<uint, uint>> Entries(byte[] f, long b, uint dirOffset)
        {
            var result = new List<KeyValuePair<uint, uint>>();
            long at = b + dirOffset;
            ushort named = U16(f, at + 12);
            ushort ids = U16(f, at + 14);
            long e = at + 16;
            for (int i = 0; i < named + ids; i++)
            {
                result.Add(new KeyValuePair<uint, uint>(U32(f, e), U32(f, e + 4)));
                e += 8;
            }
            return result;
        }

        static List<TypeNode> ParseTree(byte[] f, Pe pe)
        {
            var tree = new List<TypeNode>();
            if (pe.ResourceVA == 0) return tree;
            Section sec = SectionOf(pe, pe.ResourceVA);
            if (sec == null) throw new BadFileException("The file's resources are not in any section.");
            long b = sec.PointerToRawData + (long)(pe.ResourceVA - sec.VirtualAddress);

            foreach (KeyValuePair<uint, uint> t in Entries(f, b, 0))
            {
                var tn = new TypeNode { Type = ReadId(f, b, t.Key) };
                if ((t.Value & 0x80000000u) == 0) continue;  // a type must be a subdirectory
                foreach (KeyValuePair<uint, uint> n in Entries(f, b, t.Value & 0x7FFFFFFFu))
                {
                    var nn = new NameNode { Name = ReadId(f, b, n.Key) };
                    if ((n.Value & 0x80000000u) == 0) continue;
                    foreach (KeyValuePair<uint, uint> l in Entries(f, b, n.Value & 0x7FFFFFFFu))
                    {
                        if ((l.Value & 0x80000000u) != 0) continue;  // a language points at data, not a subdirectory
                        long de = b + l.Value;
                        uint rva = U32(f, de);
                        uint size = U32(f, de + 4);
                        uint codePage = U32(f, de + 8);
                        Section ds = SectionOf(pe, rva);
                        if (ds == null) throw new BadFileException("A resource points outside the file.");
                        long off = ds.PointerToRawData + (long)(rva - ds.VirtualAddress);
                        if (off + size > f.Length) throw new BadFileException("A resource runs past the end of the file.");
                        var data = new byte[size];
                        Buffer.BlockCopy(f, (int)off, data, 0, (int)size);
                        nn.Langs.Add(new Leaf { Lang = l.Key & 0x7FFFFFFFu, CodePage = codePage, Data = data });
                    }
                    tn.Names.Add(nn);
                }
                tree.Add(tn);
            }
            return tree;
        }

        static uint DirSize(int count) { return (uint)(16 + 8 * count); }

        // Named entries come before numbered ones in each directory.
        static IEnumerable<int> NamedFirst(IList<bool> named)
        {
            return Enumerable.Range(0, named.Count).OrderBy(i => named[i] ? 0 : 1);
        }

        // Lays the tree out again into one run of bytes, addressed from a given
        // virtual address: the directories in tree order, then the name strings,
        // then the data descriptors, then the data.
        static byte[] BuildTree(List<TypeNode> tree, uint baseVA)
        {
            uint cursor = 0;

            // Pass 1: directory offsets, depth first, and the strings and leaves
            // in the order they are met.
            uint typeDirOffset = cursor;
            cursor += DirSize(tree.Count);
            var nameDirOffset = new uint[tree.Count];
            var langDirOffset = new uint[tree.Count][];
            for (int ti = 0; ti < tree.Count; ti++)
            {
                nameDirOffset[ti] = cursor;
                cursor += DirSize(tree[ti].Names.Count);
                langDirOffset[ti] = new uint[tree[ti].Names.Count];
                for (int ni = 0; ni < tree[ti].Names.Count; ni++)
                {
                    langDirOffset[ti][ni] = cursor;
                    cursor += DirSize(tree[ti].Names[ni].Langs.Count);
                }
            }

            // Strings for named types and names, gathered in tree order.
            var stringAt = new Dictionary<string, uint>(StringComparer.Ordinal);
            Action<Id> placeString = id =>
            {
                if (!id.IsName || stringAt.ContainsKey(id.Name)) return;
                stringAt[id.Name] = cursor;
                cursor += (uint)(2 + 2 * id.Name.Length);
                cursor = Align(cursor, 4);
            };
            foreach (TypeNode t in tree) placeString(t.Type);
            foreach (TypeNode t in tree) { foreach (NameNode n in t.Names) placeString(n.Name); }

            // The data descriptors, 16 bytes each, then the data itself.
            cursor = Align(cursor, 4);
            var leaves = new List<Leaf>();
            var leafDescAt = new List<uint>();
            foreach (TypeNode t in tree)
            {
                foreach (NameNode n in t.Names)
                {
                    foreach (Leaf l in n.Langs)
                    {
                        leaves.Add(l);
                        leafDescAt.Add(cursor);
                        cursor += 16;
                    }
                }
            }
            var leafDataAt = new List<uint>();
            foreach (Leaf l in leaves)
            {
                cursor = Align(cursor, 8);
                leafDataAt.Add(cursor);
                cursor += (uint)l.Data.Length;
            }

            var result = new byte[cursor];

            // Pass 2: write it.
            Action<uint, ushort, ushort> writeDir = (offset, named, ids) =>
            {
                PutU32(result, offset, 0);       // Characteristics
                PutU32(result, offset + 4, 0);   // TimeDateStamp
                PutU16(result, offset + 8, 0);   // MajorVersion
                PutU16(result, offset + 10, 0);  // MinorVersion
                PutU16(result, offset + 12, named);
                PutU16(result, offset + 14, ids);
            };
            Func<Id, uint> entryName = id => id.IsName ? (0x80000000u | stringAt[id.Name]) : id.Number;

            // type directory
            {
                List<bool> named = tree.Select(t => t.Type.IsName).ToList();
                ushort nn = (ushort)named.Count(x => x);
                writeDir(typeDirOffset, nn, (ushort)(tree.Count - nn));
                long e = typeDirOffset + 16;
                foreach (int ti in NamedFirst(named))
                {
                    PutU32(result, e, entryName(tree[ti].Type));
                    PutU32(result, e + 4, 0x80000000u | nameDirOffset[ti]);
                    e += 8;
                }
            }
            for (int ti = 0; ti < tree.Count; ti++)
            {
                TypeNode t = tree[ti];
                List<bool> named = t.Names.Select(n => n.Name.IsName).ToList();
                ushort nn = (ushort)named.Count(x => x);
                writeDir(nameDirOffset[ti], nn, (ushort)(t.Names.Count - nn));
                long e = nameDirOffset[ti] + 16;
                foreach (int ni in NamedFirst(named))
                {
                    PutU32(result, e, entryName(t.Names[ni].Name));
                    PutU32(result, e + 4, 0x80000000u | langDirOffset[ti][ni]);
                    e += 8;
                }
            }
            // language directories and their data descriptors
            int leafIndex = 0;
            for (int ti = 0; ti < tree.Count; ti++)
            {
                TypeNode t = tree[ti];
                for (int ni = 0; ni < t.Names.Count; ni++)
                {
                    NameNode n = t.Names[ni];
                    // Languages are always numbered.
                    writeDir(langDirOffset[ti][ni], 0, (ushort)n.Langs.Count);
                    // In language id order, as the directory keeps them sorted.
                    long e = langDirOffset[ti][ni] + 16;
                    foreach (int li in Enumerable.Range(0, n.Langs.Count).OrderBy(i => n.Langs[i].Lang))
                    {
                        PutU32(result, e, n.Langs[li].Lang);
                        PutU32(result, e + 4, leafDescAt[leafIndex + li]);  // a data descriptor, high bit clear
                        e += 8;
                    }
                    leafIndex += n.Langs.Count;
                }
            }
            // the name strings
            foreach (KeyValuePair<string, uint> kv in stringAt)
            {
                PutU16(result, kv.Value, (ushort)kv.Key.Length);
                for (int i = 0; i < kv.Key.Length; i++) PutU16(result, kv.Value + 2 + 2 * i, kv.Key[i]);
            }
            // the data descriptors and the data
            for (int i = 0; i < leaves.Count; i++)
            {
                uint desc = leafDescAt[i];
                uint dataAt = leafDataAt[i];
                PutU32(result, desc, baseVA + dataAt);
                PutU32(result, desc + 4, (uint)leaves[i].Data.Length);
                PutU32(result, desc + 8, leaves[i].CodePage);
                PutU32(result, desc + 12, 0);
                Buffer.BlockCopy(leaves[i].Data, 0, result, (int)dataAt, leaves[i].Data.Length);
            }
            return result;
        }

        // The PE checksum: the file as 16-bit words summed with end-around carry,
        // its own checksum field taken as zero, plus the file's length.
        static uint CheckSum(byte[] f, long checksumAt)
        {
            uint sum = 0;
            long len = f.Length;
            for (long i = 0; i + 1 < len; i += 2)
            {
                if (i == checksumAt || i == checksumAt + 2) continue;  // its own four bytes count as zero
                uint w = (uint)(f[i] | (f[i + 1] << 8));
                sum += w;
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            if ((len & 1) != 0)
            {
                sum += f[len - 1];
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            sum = (sum & 0xFFFF) + (sum >> 16);
            sum = (sum & 0xFFFF) + (sum >> 16);
            return sum + (uint)len;
        }

        // The data of each key, null where the file has none. Throws
        // BadFileException on a malformed file.
        public static byte[][] Read(byte[] file, Key[] keys)
        {
            Pe pe = ParseHeaders(file);
            List<TypeNode> tree = ParseTree(file, pe);
            var result = new byte[keys.Length][];
            for (int i = 0; i < keys.Length; i++)
            {
                foreach (TypeNode t in tree)
                {
                    if (result[i] != null) break;
                    if (!t.Type.Same(keys[i].Type)) continue;
                    foreach (NameNode n in t.Names)
                    {
                        if (result[i] != null) break;
                        if (!n.Name.Same(keys[i].Name)) continue;
                        foreach (Leaf l in n.Langs)
                        {
                            if (l.Lang == keys[i].Lang) { result[i] = l.Data; break; }
                        }
                    }
                }
            }
            return result;
        }

        // The file with those resources' data replaced (a key the file does not
        // have is ignored; here they only ever replace). The bytes before the
        // resource section are the ones passed in. Throws BadFileException if the
        // file is malformed or the new resources do not fit where the section
        // lives.
        public static byte[] Write(byte[] file, Key[] keys, byte[][] data)
        {
            Pe pe = ParseHeaders(file);
            if (pe.Plus) throw new BadFileException("A 64-bit program's resources are not handled.");
            List<TypeNode> tree = ParseTree(file, pe);

            // Replace the data of every key the file has.
            for (int k = 0; k < keys.Length; k++)
            {
                foreach (TypeNode t in tree)
                {
                    if (!t.Type.Same(keys[k].Type)) continue;
                    foreach (NameNode n in t.Names)
                    {
                        if (!n.Name.Same(keys[k].Name)) continue;
                        foreach (Leaf l in n.Langs)
                        {
                            if (l.Lang == keys[k].Lang) l.Data = data[k];
                        }
                    }
                }
            }

            Section rsrc = SectionOf(pe, pe.ResourceVA);
            if (rsrc == null) throw new BadFileException("The file has no resource section to rewrite.");
            int rsrcIndex = pe.Sections.IndexOf(rsrc);

            byte[] blob = BuildTree(tree, rsrc.VirtualAddress);
            uint newRaw = Align((uint)blob.Length, pe.FileAlignment);
            uint oldRaw = rsrc.SizeOfRawData;

            // The rebuilt section keeps its address; it must still end before the
            // next section begins, so nothing that points into the image moves.
            uint roomVA = 0xFFFFFFFFu;
            foreach (Section s in pe.Sections)
            {
                if (s.VirtualAddress > rsrc.VirtualAddress) roomVA = Math.Min(roomVA, s.VirtualAddress - rsrc.VirtualAddress);
            }
            if ((uint)blob.Length > roomVA)
            {
                throw new BadFileException("The translated resources are too large for the space the file keeps for them.");
            }

            var edited = (byte[])file.Clone();  // the bytes passed in, with the earlier edits

            // The section's own header.
            PutU32(edited, rsrc.HeaderAt + 8, (uint)blob.Length);  // VirtualSize
            PutU32(edited, rsrc.HeaderAt + 16, newRaw);             // SizeOfRawData
            // The sections whose raw data comes after it slide by the change.
            int delta = (int)newRaw - (int)oldRaw;
            if (delta != 0)
            {
                foreach (Section s in pe.Sections)
                {
                    if (s.PointerToRawData > rsrc.PointerToRawData)
                    {
                        PutU32(edited, s.HeaderAt + 20, (uint)((int)s.PointerToRawData + delta));
                    }
                }
            }
            // File offsets that point past the section move with it. Two kinds:
            //   - the debug directory names its data by a file offset as well as
            //     an address, and here that data sits in the tail after .rsrc
            //     (Windows moves it and fixes the offset - so must this);
            //   - the certificate table is named by a file offset only.
            if (delta != 0)
            {
                long dirBase = pe.OptionalAt + (pe.Plus ? 112 : 96);
                uint debugVA = U32(edited, dirBase + 6 * 8);
                uint debugSize = U32(edited, dirBase + 6 * 8 + 4);
                Section ds = debugVA != 0 ? SectionOf(pe, debugVA) : null;
                if (ds != null)
                {
                    long at = ds.PointerToRawData + (long)(debugVA - ds.VirtualAddress);
                    for (uint off = 0; off + 28 <= debugSize; off += 28)
                    {
                        long ptrAt = at + off + 24;  // PointerToRawData of this entry
                        uint ptr = U32(edited, ptrAt);
                        if (ptr > rsrc.PointerToRawData) PutU32(edited, ptrAt, (uint)((int)ptr + delta));
                    }
                }
                uint certAt = U32(edited, dirBase + 4 * 8);  // a file offset, not an address
                if (certAt > rsrc.PointerToRawData) PutU32(edited, dirBase + 4 * 8, (uint)((int)certAt + delta));
            }

            // The resource directory of the data directory: address the same, size
            // the tree's own size.
            PutU32(edited, pe.ResourceDirAt + 4, (uint)blob.Length);
            // If the section is the last one, the image may end further out.
            if (rsrcIndex + 1 == pe.Sections.Count)
            {
                uint image = Align(rsrc.VirtualAddress + (uint)blob.Length, pe.SectionAlignment);
                uint was = U32(edited, pe.SizeOfImageAt);
                PutU32(edited, pe.SizeOfImageAt, Math.Max(was, image));
            }

            // Splice: the bytes before the section, the new section padded to its
            // raw size, then everything that was after the old section - the later
            // sections and any overlay - unchanged, only shifted.
            long tailAt = (long)rsrc.PointerToRawData + oldRaw;
            long tail = Math.Max(0, edited.Length - tailAt);
            var result = new byte[rsrc.PointerToRawData + newRaw + tail];
            Buffer.BlockCopy(edited, 0, result, 0, (int)rsrc.PointerToRawData);
            Buffer.BlockCopy(blob, 0, result, (int)rsrc.PointerToRawData, blob.Length);
            if (tail > 0) Buffer.BlockCopy(edited, (int)tailAt, result, (int)(rsrc.PointerToRawData + newRaw), (int)tail);

            // The checksum, if the file carried one (these do not).
            uint stored = U32(result, pe.CheckSumAt);
            if (stored != 0) PutU32(result, pe.CheckSumAt, CheckSum(result, pe.CheckSumAt));
            return result;
        }
    }
}
