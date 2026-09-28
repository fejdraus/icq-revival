// The Ukrainian interface the patch carries - the port of
// tools\patcher\Icq2003b\Translation.cs: a recipe of what to change in the
// client's menus, dialogs and string tables, the texts that live in a
// program's data or in the skin, the text files written whole, and where the
// "Send By:" words sit.
//
// The recipe is tools\icq2003b\patch\ICQ-2003b-uk-UA.json, written by the
// translation tools (translate\build.py) from the translator's uk-UA.json. It
// is embedded in the exe as it is - one RCDATA resource of readable UTF-8
// text, nothing packed or encoded. The patch rebuilds each translated
// resource itself, from the client's own English resource, following the
// recipe (ResourceCodec), so a resource comes out exactly as before. How the
// recipe is stored is known to one function only, LoadRecipe in
// Translation.cpp.
//
// A resource is only translated when the client's original matches the one the
// recipe was built from: each record carries the SHA-256 of that original.

#pragma once

#include "ResourceCodec.h"
#include "../common/PatchFiles.h"

#include <optional>
#include <string>
#include <vector>

// One resource to translate: its key and the SHA-256 of the English
// original, and the change - replaced strings, menu items or the dialog's
// caption, control captions and control widths, by index.
struct ResRecipe
{
    int Type = 0;
    std::wstring Key;  // "type|name|lang", a numeric name written "#123"
    std::wstring From;
    std::optional<IndexedTexts> Strings;
    std::optional<IndexedTexts> Items;
    OptStr Caption;
    std::optional<IndexedTexts> Controls;
    std::optional<IndexedWidths> Widths;

    // The translated resource, built from the English original's bytes.
    Bytes Build(const Bytes& original) const;
};

// A text in a program's data or in the skin, written over the English one:
// the bytes to write, and the original bytes, for telling the state.
struct TrPlace
{
    int Offset = 0;
    Bytes Data;
    Bytes Original;
};

struct TrFile
{
    std::wstring Rel;
    long long Size = 0;
    std::vector<ResRecipe> Resources;
    std::vector<TrPlace> Inplace;
    // A text file written whole (a datafile), and the SHA-256 of the English one.
    bool HasWhole = false;
    Bytes Whole;
    std::wstring WholeFrom;
};

// Where the "Send By:" words live, and how to blank them.
struct TrSendBy
{
    std::wstring File;
    std::wstring Key;
    std::wstring From;
    int Index = 0;
    std::wstring Blank;
};

// One translated resource on a given client: its key, the bytes built from
// the client's original, and the SHA-256 of the English original the recipe
// was made from.
struct MatItem
{
    std::wstring Key;
    Bytes Data;
    std::wstring From;
};

// What one file's resources come to on a given client: the translated bytes
// by key, and the send-by table blanked in either language (for Icq.exe).
struct MatFile
{
    std::vector<MatItem> Items;
    std::optional<Bytes> BlankEn;
    std::optional<Bytes> BlankUk;

    // The first item of the key (ignoring case), or nothing.
    const Bytes* ByKey(const std::wstring& key) const;
};

class Translation
{
public:
    // In the order of the file; looked up ignoring case.
    std::vector<TrFile> Files;
    TrSendBy SendBy;

    // The file's entry, or nothing; the first one of a name wins.
    const TrFile* File(const std::wstring& rel) const;

    // Everything one file's resources come to on this client, built from the
    // English original's bytes.
    MatFile Materialize(const TrFile& file, const Bytes& originalFileBytes) const;

    // Loaded once, on first use.
    static const Translation& Get();

    // SHA-256 of some bytes, as lower-case hex.
    static std::wstring Sha(const Bytes& bytes) { return PatchFiles::Sha256Lower(bytes); }
};
