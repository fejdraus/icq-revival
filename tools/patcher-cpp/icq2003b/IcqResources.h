// Reading and replacing the resources of the client's programs, over their
// bytes - the port of tools\patcher\Icq2003b\IcqResources.cs, no longer
// through Windows.
//
// The C# patch called BeginUpdateResource / UpdateResource; those calls, and
// the ones that read another file's resources, are what scanners took the
// patch's resource work for something worse. The work is done here in plain
// C++ instead (PeResources), so the exe imports none of them. The resources
// the exe carries for itself are still read the ordinary way, from its own
// module (Translation.cpp).

#pragma once

#include "../common/PatchFiles.h"
#include "../common/PeResources.h"

#include <optional>
#include <string>
#include <vector>

namespace IcqResources
{
    // A resource by its key "type|name|lang"; the name is "#123" for a
    // number, anything else for a name.
    PeResources::Key ParseKey(const std::wstring& key);

    // The data of each key in the file bytes, nothing where the file has none.
    std::vector<std::optional<Bytes>> Read(const Bytes& file, const std::vector<std::wstring>& keys);

    bool Same(const std::optional<Bytes>& a, const Bytes& b);

    // The file with those keys' data replaced.
    Bytes Write(const Bytes& file, const std::vector<std::wstring>& keys, const std::vector<Bytes>& data);
}
