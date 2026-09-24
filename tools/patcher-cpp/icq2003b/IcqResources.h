// Reading and writing the resources of the client's programs - the port of
// tools\patcher\Icq2003b\IcqResources.cs.
//
// Resources are written by Windows itself (UpdateResource). It rebuilds the
// resource section and nothing before it - code and data stay where they are,
// so the offsets of the code patches hold in a translated file as well.

#pragma once

#include "../common/PatchFiles.h"

#include <optional>
#include <string>
#include <vector>

namespace IcqResources
{
    // A resource by its key "type|name|lang"; the name is "#123" for a
    // number, anything else for a name.
    struct Key
    {
        int Type = 0;
        std::wstring Name;
        int Lang = 0;

        static Key Parse(const std::wstring& key);
    };

    // The data of each resource, nothing where the file has none.
    std::vector<std::optional<Bytes>> Read(const std::wstring& file, const std::vector<Key>& keys);

    bool Same(const std::optional<Bytes>& a, const Bytes& b);
    bool Same(const Bytes& a, const Bytes& b);

    // Throws a PatchError with the reason Windows gives.
    void Write(const std::wstring& file, const std::vector<Key>& keys, const std::vector<Bytes>& data);
}
