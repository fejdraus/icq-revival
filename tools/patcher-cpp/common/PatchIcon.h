// The icon every client patch carries, in the window and on its exe - the
// port of tools\patcher\Common\PatchIcon.cs.
//
// The picture is the flower of the ICQ Revival logo, drawn from a PNG the exe
// carries (tools\patcher\Common\flower.png, the RCDATA resource FLOWER of
// app.rc), with the client version on a pill under it from 48 pixels up. It
// is drawn into the window's header; the app.ico each exe is built with was
// written from the same picture once (by PatchIcon.WriteFile of
// tools\patcher\Common\PatchIcon.cs), and this exe carries that same app.ico
// for its title bar and for Explorer.

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

    // The flower of the ICQ Revival logo, filling the icon. From 48 pixels up
    // the flower moves up and the version is written under it, white on a
    // pill in the colour of the client version, so the exe of each patch can
    // be told apart at a glance in Explorer.
    // The caller deletes the bitmap; GDI+ must be started.
    Gdiplus::Bitmap* Draw(int size, const std::wstring& badge, const std::wstring& top, const std::wstring& bottom);

    // The face a font is asked for by, or where Windows does not have it -
    // XP has no Segoe UI - the nearest one it has: Tahoma, XP's own.
    std::wstring Face(const std::wstring& wanted);
}
