// Reading and writing the text resources of ICQ Pro 2003b - string tables,
// menus and dialogs - so the patch builds each translated resource from the
// client's own English one, following the recipe. The port of
// tools\patcher\Icq2003b\ResourceCodec.cs, itself the port of
// tools\icq2003b\translate\icqres.py; the bytes it writes are the ones that
// tool's build.py recorded the recipe from, so a translated resource comes out
// exactly as before.
//
// Only what the translation needs: a resource is parsed into its texts plus
// everything else kept as it was, and written back with other texts. The
// layout of a dialog - positions, sizes, styles - stays as it is unless the
// recipe gives a control another width.

#pragma once

#include "../common/PatchFiles.h"
#include "../common/Ps.h"

#include <string>
#include <utility>
#include <vector>

// Texts or widths by a 0-based index, in the order the recipe lists them; a
// later one for the same index wins.
using IndexedTexts = std::vector<std::pair<int, std::wstring>>;
using IndexedWidths = std::vector<std::pair<int, int>>;

namespace ResourceCodec
{
    const int RtMenu = 4, RtDialog = 5, RtString = 6;

    // The 16 strings of a string table, "" for the ones it leaves out.
    std::vector<std::wstring> ReadStrings(const Bytes& data);
    Bytes WriteStrings(const std::vector<std::wstring>& texts);

    // A string table with the given strings replaced by index.
    Bytes TranslateStrings(const Bytes& data, const IndexedTexts& changes);

    // A menu (MENU or MENUEX) with the given item texts replaced by index.
    Bytes TranslateMenu(const Bytes& data, const IndexedTexts& changes);

    // A dialog (DIALOG or DIALOGEX) with its caption, some control captions
    // and some control widths replaced. A control index is 0-based; the
    // caption is separate. Nothing given leaves that part as it is.
    Bytes TranslateDialog(const Bytes& data, const OptStr& caption, const IndexedTexts* controls,
                          const IndexedWidths* widths);
}
