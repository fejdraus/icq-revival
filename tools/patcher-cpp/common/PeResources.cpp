// See PeResources.h.

#include "PeResources.h"

#include <algorithm>
#include <cstring>
#include <map>

namespace PeResources
{
    namespace
    {
        // Little-endian reads and writes over a byte vector, bounds checked.
        uint16_t U16(const Bytes& b, size_t at)
        {
            if (at + 2 > b.size()) throw PatchError{ L"The file is not a valid program (truncated)." };
            return (uint16_t)(b[at] | (b[at + 1] << 8));
        }
        uint32_t U32(const Bytes& b, size_t at)
        {
            if (at + 4 > b.size()) throw PatchError{ L"The file is not a valid program (truncated)." };
            return (uint32_t)(b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | ((uint32_t)b[at + 3] << 24));
        }
        void PutU16(Bytes& b, size_t at, uint16_t v)
        {
            b[at] = (uint8_t)v;
            b[at + 1] = (uint8_t)(v >> 8);
        }
        void PutU32(Bytes& b, size_t at, uint32_t v)
        {
            b[at] = (uint8_t)v;
            b[at + 1] = (uint8_t)(v >> 8);
            b[at + 2] = (uint8_t)(v >> 16);
            b[at + 3] = (uint8_t)(v >> 24);
        }
        uint32_t Align(uint32_t v, uint32_t a) { return a == 0 ? v : (v + a - 1) / a * a; }

        // The pieces of the PE headers the resource work needs.
        struct Section
        {
            char Name[8];
            uint32_t VirtualSize;
            uint32_t VirtualAddress;
            uint32_t SizeOfRawData;
            uint32_t PointerToRawData;
            uint32_t Characteristics;
            size_t HeaderAt;  // where this section header sits in the file
        };

        struct Pe
        {
            size_t OptionalAt;      // start of the optional header
            bool Plus;              // PE32+ (64-bit) - not expected here
            uint32_t FileAlignment;
            uint32_t SectionAlignment;
            size_t SizeOfImageAt;
            size_t CheckSumAt;
            size_t ResourceDirAt;   // the resource entry of the data directory
            uint32_t ResourceVA;
            uint32_t ResourceSize;
            std::vector<Section> Sections;
        };

        Pe ParseHeaders(const Bytes& f)
        {
            if (f.size() < 0x40 || f[0] != 'M' || f[1] != 'Z') throw PatchError{ L"The file is not a valid program (no MZ)." };
            uint32_t peAt = U32(f, 0x3C);
            if (peAt + 24 > f.size() || U32(f, peAt) != 0x00004550) throw PatchError{ L"The file is not a valid program (no PE)." };
            Pe pe;
            uint16_t numSections = U16(f, peAt + 6);
            uint16_t optSize = U16(f, peAt + 20);
            pe.OptionalAt = peAt + 24;
            uint16_t magic = U16(f, pe.OptionalAt);
            pe.Plus = magic == 0x20B;
            if (magic != 0x10B && magic != 0x20B) throw PatchError{ L"The file is not a valid program (optional header)." };
            pe.FileAlignment = U32(f, pe.OptionalAt + 36);
            pe.SectionAlignment = U32(f, pe.OptionalAt + 32);
            pe.SizeOfImageAt = pe.OptionalAt + 56;
            pe.CheckSumAt = pe.OptionalAt + 64;
            // The data directory begins after the fixed part: 96 bytes for
            // PE32, 112 for PE32+. Entry 2 is the resource table.
            size_t dirAt = pe.OptionalAt + (pe.Plus ? 112 : 96);
            pe.ResourceDirAt = dirAt + 2 * 8;
            pe.ResourceVA = U32(f, pe.ResourceDirAt);
            pe.ResourceSize = U32(f, pe.ResourceDirAt + 4);
            size_t secAt = pe.OptionalAt + optSize;
            for (uint16_t i = 0; i < numSections; i++)
            {
                size_t at = secAt + i * 40;
                if (at + 40 > f.size()) throw PatchError{ L"The file is not a valid program (section table)." };
                Section s;
                memcpy(s.Name, &f[at], 8);
                s.VirtualSize = U32(f, at + 8);
                s.VirtualAddress = U32(f, at + 12);
                s.SizeOfRawData = U32(f, at + 16);
                s.PointerToRawData = U32(f, at + 20);
                s.Characteristics = U32(f, at + 36);
                s.HeaderAt = at;
                pe.Sections.push_back(s);
            }
            return pe;
        }

        // The section that holds a virtual address.
        const Section* SectionOf(const Pe& pe, uint32_t rva)
        {
            for (const Section& s : pe.Sections)
            {
                uint32_t size = (std::max)(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size) return &s;
            }
            return nullptr;
        }

        // --- the resource tree ---------------------------------------------------
        //
        // Three levels: type, then name, then language; each language points at
        // one run of bytes. Every offset in a directory is measured from the
        // start of the resource section; a data entry's address is a virtual
        // address in the image.

        struct Leaf
        {
            uint32_t Lang;
            uint32_t CodePage;
            Bytes Data;
        };
        struct NameNode
        {
            Id Name;
            std::vector<Leaf> Langs;
        };
        struct TypeNode
        {
            Id Type;
            std::vector<NameNode> Names;
        };
        using Tree = std::vector<TypeNode>;

        std::wstring ReadDirString(const Bytes& f, size_t base, uint32_t offset)
        {
            size_t at = base + offset;
            uint16_t len = U16(f, at);
            std::wstring s;
            for (uint16_t i = 0; i < len; i++) s += (wchar_t)U16(f, at + 2 + 2 * i);
            return s;
        }

        Id ReadId(const Bytes& f, size_t base, uint32_t nameField)
        {
            if (nameField & 0x80000000u) return Id::OfName(ReadDirString(f, base, nameField & 0x7FFFFFFFu));
            return Id::Of(nameField);
        }

        Tree ParseTree(const Bytes& f, const Pe& pe)
        {
            Tree tree;
            if (pe.ResourceVA == 0) return tree;
            const Section* sec = SectionOf(pe, pe.ResourceVA);
            if (sec == nullptr) throw PatchError{ L"The file's resources are not in any section." };
            size_t base = sec->PointerToRawData + (pe.ResourceVA - sec->VirtualAddress);

            auto entriesOf = [&](uint32_t dirOffset, std::vector<std::pair<uint32_t, uint32_t>>& out) {
                size_t at = base + dirOffset;
                uint16_t named = U16(f, at + 12);
                uint16_t ids = U16(f, at + 14);
                size_t e = at + 16;
                for (int i = 0; i < named + ids; i++)
                {
                    out.push_back({ U32(f, e), U32(f, e + 4) });
                    e += 8;
                }
            };

            std::vector<std::pair<uint32_t, uint32_t>> types;
            entriesOf(0, types);
            for (auto& t : types)
            {
                TypeNode tn;
                tn.Type = ReadId(f, base, t.first);
                if (!(t.second & 0x80000000u)) continue;  // a type must be a subdirectory
                std::vector<std::pair<uint32_t, uint32_t>> names;
                entriesOf(t.second & 0x7FFFFFFFu, names);
                for (auto& n : names)
                {
                    NameNode nn;
                    nn.Name = ReadId(f, base, n.first);
                    if (!(n.second & 0x80000000u)) continue;
                    std::vector<std::pair<uint32_t, uint32_t>> langs;
                    entriesOf(n.second & 0x7FFFFFFFu, langs);
                    for (auto& l : langs)
                    {
                        if (l.second & 0x80000000u) continue;  // a language points at data, not a subdirectory
                        size_t de = base + l.second;
                        uint32_t rva = U32(f, de);
                        uint32_t size = U32(f, de + 4);
                        uint32_t codePage = U32(f, de + 8);
                        const Section* ds = SectionOf(pe, rva);
                        if (ds == nullptr) throw PatchError{ L"A resource points outside the file." };
                        size_t off = ds->PointerToRawData + (rva - ds->VirtualAddress);
                        if (off + size > f.size()) throw PatchError{ L"A resource runs past the end of the file." };
                        Leaf leaf;
                        leaf.Lang = (l.first & 0x7FFFFFFFu);
                        leaf.CodePage = codePage;
                        leaf.Data.assign(f.begin() + off, f.begin() + off + size);
                        nn.Langs.push_back(leaf);
                    }
                    tn.Names.push_back(nn);
                }
                tree.push_back(tn);
            }
            return tree;
        }

        // Lays the tree out again into one run of bytes, addressed from a given
        // virtual address: the directories in tree order, then the name
        // strings, then the data descriptors, then the data. The order is the
        // patch's own; Windows lays it out likewise, but nothing depends on it.
        Bytes BuildTree(const Tree& tree, uint32_t baseVA)
        {
            // The size of every directory, and where each will sit.
            struct Dir
            {
                uint32_t Offset;
                uint16_t Named;
                uint16_t Ids;
            };
            uint32_t cursor = 0;
            auto dirSize = [](size_t count) { return (uint32_t)(16 + 8 * count); };

            // Pass 1: directory offsets, depth first, and the strings and
            // leaves in the order they are met.
            std::vector<const Id*> strings;   // named entries needing a string
            std::vector<const Leaf*> leaves;  // data descriptors and data

            uint32_t typeDirOffset = cursor;
            cursor += dirSize(tree.size());
            std::vector<uint32_t> nameDirOffset(tree.size());
            std::vector<std::vector<uint32_t>> langDirOffset(tree.size());
            for (size_t ti = 0; ti < tree.size(); ti++)
            {
                nameDirOffset[ti] = cursor;
                cursor += dirSize(tree[ti].Names.size());
                langDirOffset[ti].resize(tree[ti].Names.size());
                for (size_t ni = 0; ni < tree[ti].Names.size(); ni++)
                {
                    langDirOffset[ti][ni] = cursor;
                    cursor += dirSize(tree[ti].Names[ni].Langs.size());
                }
            }

            // Strings for named types and names, gathered in tree order.
            std::map<std::wstring, uint32_t> stringAt;
            auto placeString = [&](const Id& id) {
                if (!id.IsName) return;
                if (stringAt.count(id.Name)) return;
                stringAt[id.Name] = cursor;
                cursor += (uint32_t)(2 + 2 * id.Name.size());
                cursor = Align(cursor, 4);
            };
            for (const TypeNode& t : tree) placeString(t.Type);
            for (const TypeNode& t : tree)
            {
                for (const NameNode& n : t.Names) placeString(n.Name);
            }

            // The data descriptors, 16 bytes each, then the data itself.
            cursor = Align(cursor, 4);
            std::vector<uint32_t> leafDescAt;
            for (const TypeNode& t : tree)
            {
                for (const NameNode& n : t.Names)
                {
                    for (const Leaf& l : n.Langs)
                    {
                        leaves.push_back(&l);
                        leafDescAt.push_back(cursor);
                        cursor += 16;
                    }
                }
            }
            std::vector<uint32_t> leafDataAt;
            for (const Leaf* l : leaves)
            {
                cursor = Align(cursor, 8);
                leafDataAt.push_back(cursor);
                cursor += (uint32_t)l->Data.size();
            }

            Bytes out(cursor, 0);

            // Pass 2: write it.
            auto writeDir = [&](uint32_t offset, uint16_t named, uint16_t ids) {
                PutU32(out, offset, 0);      // Characteristics
                PutU32(out, offset + 4, 0);  // TimeDateStamp
                PutU16(out, offset + 8, 0);  // MajorVersion
                PutU16(out, offset + 10, 0); // MinorVersion
                PutU16(out, offset + 12, named);
                PutU16(out, offset + 14, ids);
            };
            auto entryName = [&](const Id& id) -> uint32_t {
                return id.IsName ? (0x80000000u | stringAt[id.Name]) : id.Number;
            };

            // Named entries come before numbered ones in each directory.
            auto ordered = [](std::vector<size_t> idx, const std::vector<bool>& named) {
                std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return named[a] && !named[b]; });
                return idx;
            };

            // type directory
            {
                std::vector<bool> named;
                for (const TypeNode& t : tree) named.push_back(t.Type.IsName);
                uint16_t nn = (uint16_t)std::count(named.begin(), named.end(), true);
                writeDir(typeDirOffset, nn, (uint16_t)(tree.size() - nn));
                std::vector<size_t> idx(tree.size());
                for (size_t i = 0; i < tree.size(); i++) idx[i] = i;
                idx = ordered(idx, named);
                size_t e = typeDirOffset + 16;
                for (size_t ti : idx)
                {
                    PutU32(out, e, entryName(tree[ti].Type));
                    PutU32(out, e + 4, 0x80000000u | nameDirOffset[ti]);
                    e += 8;
                }
            }
            for (size_t ti = 0; ti < tree.size(); ti++)
            {
                const TypeNode& t = tree[ti];
                std::vector<bool> named;
                for (const NameNode& n : t.Names) named.push_back(n.Name.IsName);
                uint16_t nn = (uint16_t)std::count(named.begin(), named.end(), true);
                writeDir(nameDirOffset[ti], nn, (uint16_t)(t.Names.size() - nn));
                std::vector<size_t> idx(t.Names.size());
                for (size_t i = 0; i < t.Names.size(); i++) idx[i] = i;
                idx = ordered(idx, named);
                size_t e = nameDirOffset[ti] + 16;
                for (size_t ni : idx)
                {
                    PutU32(out, e, entryName(t.Names[ni].Name));
                    PutU32(out, e + 4, 0x80000000u | langDirOffset[ti][ni]);
                    e += 8;
                }
            }
            // language directories and their data descriptors
            size_t leafIndex = 0;
            for (size_t ti = 0; ti < tree.size(); ti++)
            {
                const TypeNode& t = tree[ti];
                for (size_t ni = 0; ni < t.Names.size(); ni++)
                {
                    const NameNode& n = t.Names[ni];
                    // Languages are always numbered.
                    writeDir(langDirOffset[ti][ni], 0, (uint16_t)n.Langs.size());
                    // In language id order, as the directory keeps them sorted.
                    std::vector<size_t> idx(n.Langs.size());
                    for (size_t i = 0; i < n.Langs.size(); i++) idx[i] = i;
                    std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return n.Langs[a].Lang < n.Langs[b].Lang; });
                    size_t e = langDirOffset[ti][ni] + 16;
                    for (size_t li : idx)
                    {
                        PutU32(out, e, n.Langs[li].Lang);
                        PutU32(out, e + 4, leafDescAt[leafIndex + li]);  // points at a data descriptor, high bit clear
                        e += 8;
                    }
                    leafIndex += n.Langs.size();
                }
            }
            // the name strings
            for (const auto& kv : stringAt)
            {
                uint32_t at = kv.second;
                PutU16(out, at, (uint16_t)kv.first.size());
                for (size_t i = 0; i < kv.first.size(); i++) PutU16(out, at + 2 + 2 * i, (uint16_t)kv.first[i]);
            }
            // the data descriptors and the data
            for (size_t i = 0; i < leaves.size(); i++)
            {
                uint32_t desc = leafDescAt[i];
                uint32_t dataAt = leafDataAt[i];
                PutU32(out, desc, baseVA + dataAt);
                PutU32(out, desc + 4, (uint32_t)leaves[i]->Data.size());
                PutU32(out, desc + 8, leaves[i]->CodePage);
                PutU32(out, desc + 12, 0);
                std::copy(leaves[i]->Data.begin(), leaves[i]->Data.end(), out.begin() + dataAt);
            }
            return out;
        }

        // The PE checksum: the file as 16-bit words summed with end-around
        // carry, its own checksum field taken as zero, plus the file's length.
        uint32_t CheckSum(const Bytes& f, size_t checksumAt)
        {
            uint32_t sum = 0;
            size_t len = f.size();
            for (size_t i = 0; i + 1 < len; i += 2)
            {
                if (i == checksumAt || i == checksumAt + 2) continue;  // its own four bytes count as zero
                uint32_t w = f[i] | (f[i + 1] << 8);
                sum += w;
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            if (len & 1)
            {
                sum += f[len - 1];
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            sum = (sum & 0xFFFF) + (sum >> 16);
            sum = (sum & 0xFFFF) + (sum >> 16);
            return sum + (uint32_t)len;
        }
    }

    Id Id::OfName(const std::wstring& s)
    {
        Id id;
        id.IsName = true;
        id.Name = ps::ToUpper(s);
        return id;
    }

    bool Id::operator==(const Id& o) const
    {
        if (IsName != o.IsName) return false;
        return IsName ? Name == o.Name : Number == o.Number;
    }

    std::vector<Entry> Read(const Bytes& file)
    {
        Pe pe = ParseHeaders(file);
        Tree tree = ParseTree(file, pe);
        std::vector<Entry> out;
        for (const TypeNode& t : tree)
        {
            for (const NameNode& n : t.Names)
            {
                for (const Leaf& l : n.Langs)
                {
                    out.push_back(Entry{ t.Type, n.Name, l.Lang, l.CodePage, l.Data });
                }
            }
        }
        return out;
    }

    std::vector<std::optional<Bytes>> Read(const Bytes& file, const std::vector<Key>& keys)
    {
        std::vector<Entry> all = Read(file);
        std::vector<std::optional<Bytes>> out(keys.size());
        for (size_t i = 0; i < keys.size(); i++)
        {
            for (const Entry& e : all)
            {
                if (e.Type == keys[i].Type && e.Name == keys[i].Name && e.Lang == keys[i].Lang)
                {
                    out[i] = e.Data;
                    break;
                }
            }
        }
        return out;
    }

    Bytes Write(const Bytes& file, const std::vector<Key>& keys, const std::vector<Bytes>& data)
    {
        Pe pe = ParseHeaders(file);
        if (pe.Plus) throw PatchError{ L"A 64-bit program's resources are not handled." };
        Tree tree = ParseTree(file, pe);

        // Replace the data of every key the file has.
        for (size_t k = 0; k < keys.size(); k++)
        {
            for (TypeNode& t : tree)
            {
                if (!(t.Type == keys[k].Type)) continue;
                for (NameNode& n : t.Names)
                {
                    if (!(n.Name == keys[k].Name)) continue;
                    for (Leaf& l : n.Langs)
                    {
                        if (l.Lang == keys[k].Lang) l.Data = data[k];
                    }
                }
            }
        }

        const Section* rsrcConst = SectionOf(pe, pe.ResourceVA);
        if (rsrcConst == nullptr) throw PatchError{ L"The file has no resource section to rewrite." };
        size_t rsrcIndex = rsrcConst - &pe.Sections[0];
        Section rsrc = *rsrcConst;

        Bytes blob = BuildTree(tree, rsrc.VirtualAddress);
        uint32_t newRaw = Align((uint32_t)blob.size(), pe.FileAlignment);
        uint32_t oldRaw = rsrc.SizeOfRawData;

        // The rebuilt section keeps its address; it must still end before the
        // next section begins, so nothing that points into the image moves.
        uint32_t roomVA = 0xFFFFFFFFu;
        for (const Section& s : pe.Sections)
        {
            if (s.VirtualAddress > rsrc.VirtualAddress) roomVA = (std::min)(roomVA, s.VirtualAddress - rsrc.VirtualAddress);
        }
        if ((uint32_t)blob.size() > roomVA)
        {
            throw PatchError{ L"The translated resources are too large for the space the file keeps for them." };
        }

        Bytes out = file;  // the bytes passed in, with the earlier edits

        // The section's own header.
        PutU32(out, rsrc.HeaderAt + 8, (uint32_t)blob.size());  // VirtualSize
        PutU32(out, rsrc.HeaderAt + 16, newRaw);                 // SizeOfRawData
        // The sections whose raw data comes after it slide by the change.
        int32_t delta = (int32_t)newRaw - (int32_t)oldRaw;
        if (delta != 0)
        {
            for (const Section& s : pe.Sections)
            {
                if (s.PointerToRawData > rsrc.PointerToRawData)
                {
                    PutU32(out, s.HeaderAt + 20, (uint32_t)((int32_t)s.PointerToRawData + delta));
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
            size_t dirBase = pe.OptionalAt + (pe.Plus ? 112 : 96);
            uint32_t debugVA = U32(out, dirBase + 6 * 8);
            uint32_t debugSize = U32(out, dirBase + 6 * 8 + 4);
            const Section* ds = debugVA != 0 ? SectionOf(pe, debugVA) : nullptr;
            if (ds != nullptr)
            {
                size_t at = ds->PointerToRawData + (debugVA - ds->VirtualAddress);
                for (uint32_t off = 0; off + 28 <= debugSize; off += 28)
                {
                    size_t ptrAt = at + off + 24;  // PointerToRawData of this entry
                    uint32_t ptr = U32(out, ptrAt);
                    if (ptr > rsrc.PointerToRawData) PutU32(out, ptrAt, (uint32_t)((int32_t)ptr + delta));
                }
            }
            uint32_t certAt = U32(out, dirBase + 4 * 8);  // a file offset, not an address
            if (certAt > rsrc.PointerToRawData) PutU32(out, dirBase + 4 * 8, (uint32_t)((int32_t)certAt + delta));
        }

        // The resource directory of the data directory: address the same, size
        // the tree's own size.
        PutU32(out, pe.ResourceDirAt + 4, (uint32_t)blob.size());
        // If the section is the last one, the image may end further out.
        bool last = rsrcIndex + 1 == pe.Sections.size();
        if (last)
        {
            uint32_t image = Align(rsrc.VirtualAddress + (uint32_t)blob.size(), pe.SectionAlignment);
            uint32_t was = U32(out, pe.SizeOfImageAt);
            PutU32(out, pe.SizeOfImageAt, (std::max)(was, image));
        }

        // Splice: the bytes before the section, the new section padded to its
        // raw size, then everything that was after the old section - the later
        // sections and any overlay - unchanged, only shifted.
        Bytes result;
        result.reserve(rsrc.PointerToRawData + newRaw + (out.size() - (rsrc.PointerToRawData + oldRaw)));
        result.insert(result.end(), out.begin(), out.begin() + rsrc.PointerToRawData);
        result.insert(result.end(), blob.begin(), blob.end());
        result.insert(result.end(), newRaw - blob.size(), 0);
        result.insert(result.end(), out.begin() + rsrc.PointerToRawData + oldRaw, out.end());

        // The checksum, if the file carried one (these do not).
        uint32_t stored = U32(result, pe.CheckSumAt);
        if (stored != 0)
        {
            PutU32(result, pe.CheckSumAt, CheckSum(result, pe.CheckSumAt));
        }
        return result;
    }
}
