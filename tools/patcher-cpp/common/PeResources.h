// Reading and writing the resources of a Windows program over its bytes, so
// the patch never asks Windows to do it. The scanners that took the C# patch
// for something that unpacks itself flagged the resource-editing calls
// (BeginUpdateResource and the rest) as much as the packed payload; a reader
// and writer of our own drop those calls.
//
// The layout follows what Windows itself does to these files (checked against
// the C# patch's output, which went through UpdateResource): the .rsrc
// section is rebuilt where it is, at its own address, and only its size
// changes. The raw data of the sections after it slides by the change in its
// aligned size - their addresses do not move, so nothing else in the file has
// to be fixed up - and any bytes after the last section (an overlay) are kept.
// Reference: tools\icq2003b\translate\icqres.py, which parses the same tree.

#pragma once

#include "PatchFiles.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace PeResources
{
    // A type, name or language: a number, or a name (types and languages are
    // always numbers in these files, a name may be either).
    struct Id
    {
        bool IsName = false;
        uint32_t Number = 0;
        std::wstring Name;  // upper-cased, as the resource directory keeps it

        static Id Of(uint32_t n) { return Id{ false, n, L"" }; }
        static Id OfName(const std::wstring& s);
        bool operator==(const Id& o) const;
    };

    // One resource: where it sits in the tree and its bytes.
    struct Entry
    {
        Id Type;
        Id Name;
        uint32_t Lang = 0;
        uint32_t CodePage = 0;
        Bytes Data;
    };

    // What a caller asks for or replaces.
    struct Key
    {
        Id Type;
        Id Name;
        uint32_t Lang = 0;
    };

    // Every resource of the file, in the order the tree lists them; empty when
    // the file has no resources. Throws a PatchError on a malformed file.
    std::vector<Entry> Read(const Bytes& file);

    // The data of each key, or nothing where the file has none.
    std::vector<std::optional<Bytes>> Read(const Bytes& file, const std::vector<Key>& keys);

    // The file with those resources' data replaced (a key the file does not
    // have is ignored, as UpdateResource added would; here they only ever
    // replace). The bytes before the resource section - code, data, the
    // headers' own fields other than the ones a resized .rsrc needs - are the
    // ones passed in. Throws a PatchError if the file is malformed or the new
    // resources do not fit where the section lives.
    Bytes Write(const Bytes& file, const std::vector<Key>& keys, const std::vector<Bytes>& data);
}
