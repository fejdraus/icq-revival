// Finding the client's folder on its own - the port of
// tools\patcher\Common\ClientFolder.cs: next to the patch first (dropped into
// the client's folder), then from the registry, then the standard path.

#pragma once

#include "Ps.h"

#include <functional>
#include <string>

struct ClientSearch
{
    // The name of the client's exe under App Paths, e.g. ICQ.exe.
    std::wstring AppPathsExe;
    // Whether the App Paths value is taken out of its quotes first.
    bool TrimQuotes = false;
    // Whether an uninstall entry's DisplayName is the client's (the pattern
    // the C# patch matches it with).
    std::function<bool(const std::wstring&)> IsDisplayName;
    // Whether the folder of the exe in UninstallString counts too.
    bool UseUninstallString = false;
    // The folder under Program Files the installer picks, e.g. ICQ6.5.
    std::wstring StandardFolder;
    // Whether a folder is the client's.
    std::function<bool(const std::wstring&)> IsClient;
};

namespace ClientFolder
{
    // The folder the patch itself runs from.
    std::wstring Self();

    OptStr Find(const ClientSearch& search);
}
