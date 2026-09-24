// What a patch remembers between runs, under its own key in HKCU, and the
// server domain every patch asks for - the port of
// tools\patcher\Common\PatchSettings.cs.

#pragma once

#include "Ps.h"

#include <string>

namespace PatchSettings
{
    // One value of the patch's key: nothing when the key is not there, an
    // empty string when only the value is not.
    OptStr Read(const std::wstring& settingsKey, const std::wstring& name);

    void Save(const std::wstring& settingsKey, const std::wstring& name, const std::wstring& value);
}

namespace Domain
{
    // The domain out of whatever was typed: a scheme, a port or a path after
    // it - habits from older versions of the patches - are dropped.
    std::wstring Of(const OptStr& value);

    bool IsValid(const OptStr& value);
}
