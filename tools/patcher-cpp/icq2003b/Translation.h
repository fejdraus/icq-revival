// The Ukrainian interface the patch carries - the port of
// tools\patcher\Icq2003b\Translation.cs: every translated resource of the
// client's programs, the texts that live in a program's data or in the skin,
// and the blank "Send By:" in both languages.
//
// The source is tools\icq2003b\patch\ICQ-2003b-uk-UA.txt (JSON, gzip,
// base64, as icq2003b\translate\build.py writes it). The C# exe carried that
// file as it is; this one carries it decoded at build time
// (Convert-Translation.ps1) into two plain resources - the raw bytes of every
// item one after another, and a UTF-8 text index of them - so nothing packed
// or encoded sits in the exe. How the payload is stored is known to one
// function only, LoadPayload in Translation.cpp.

#pragma once

#include "../common/PatchFiles.h"

#include <string>
#include <vector>

struct TrItem
{
    std::wstring Key;  // "type|name|lang"
    Bytes Data;        // the translated data
    std::wstring From; // SHA-256 of the English data
};

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
    std::vector<TrItem> Items;
    std::vector<TrPlace> Inplace;
    // A text file written whole, and the SHA-256 of the English one.
    bool HasWhole = false;
    Bytes Whole;
    std::wstring WholeFrom;
};

struct TrSendBy
{
    std::wstring File;
    std::wstring Key;
    std::wstring From;
    Bytes BlankEn;
    Bytes BlankUk;
};

class Translation
{
public:
    // In the order of the file; looked up ignoring case.
    std::vector<TrFile> Files;
    TrSendBy SendBy;

    // The file's entry, or nothing; the first one of a name wins.
    const TrFile* File(const std::wstring& rel) const;

    // Loaded once, on first use.
    static const Translation& Get();

    // SHA-256 of some bytes, as lower-case hex.
    static std::wstring Sha(const Bytes& bytes) { return PatchFiles::Sha256Lower(bytes); }
};
