// The icon every client patch carries, in the window and on its exe - the
// port of tools\patcher\Common\PatchIcon.cs.
//
// The icon is drawn, not stored: the same picture is drawn into the window's
// header, and the app.ico each exe is built with was written from it once
// (by New-PatchIconFile of tools\common\PatchWindow.ps1). This exe carries
// that same app.ico for its title bar and for Explorer.

#pragma once

#include <windows.h>

#include <string>

namespace Gdiplus
{
    class Bitmap;
}

namespace PatchIcon
{
    // #RRGGBB as a GDI colour.
    COLORREF ColorOf(const std::wstring& hex);

    // A flower of eight petals on a rounded tile in the colour of the client
    // version. From 48 pixels up the version is written under the flower, so
    // the exe of each patch can be told apart at a glance in Explorer.
    // The caller deletes the bitmap; GDI+ must be started.
    Gdiplus::Bitmap* Draw(int size, const std::wstring& badge, const std::wstring& top, const std::wstring& bottom);

    // The face a font is asked for by, or where Windows does not have it -
    // XP has no Segoe UI - the nearest one it has: Tahoma, XP's own.
    std::wstring Face(const std::wstring& wanted);
}
