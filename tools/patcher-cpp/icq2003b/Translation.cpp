// See Translation.h.

#include "Translation.h"

#include <windows.h>

#include <stdexcept>

namespace
{
    // The translation as the exe carries it: the index, as UTF-8 text, and
    // the bytes the index points into. The one place that knows how and
    // where it is stored - two RCDATA resources of the exe, written by
    // Convert-Translation.ps1 at build time - so another way of carrying it
    // only changes this function.
    struct Payload
    {
        std::string Index;
        const unsigned char* Data = nullptr;
        size_t Size = 0;
    };

    Payload LoadPayload()
    {
        auto resource = [](const wchar_t* name, const unsigned char*& data, size_t& size) {
            HMODULE self = GetModuleHandleW(nullptr);
            HRSRC r = FindResourceW(self, name, MAKEINTRESOURCEW(10));  // RT_RCDATA
            if (r == nullptr) throw PatchError{ std::wstring(L"The translation is missing from the exe: ") + name };
            size = SizeofResource(self, r);
            data = (const unsigned char*)LockResource(LoadResource(self, r));
        };
        Payload p;
        const unsigned char* index = nullptr;
        size_t indexSize = 0;
        resource(L"TRINDEX", index, indexSize);
        p.Index.assign((const char*)index, indexSize);
        resource(L"TRDATA", p.Data, p.Size);
        return p;
    }

    // The index: one record per line, fields split by tabs.
    //   file    <rel> <size>
    //   item    <type|name|lang> <sha256 of the English data> <offset> <length>
    //   place   <file offset> <offset> <length> <offset of the original> <its length>
    //   whole   <sha256 of the English file> <offset> <length>
    //   sendby  <file> <type|name|lang> <sha256> <offset> <length> <offset> <length>
    // A line starting with # is a comment. Offsets and lengths are into the
    // data resource.
    std::vector<std::wstring> Fields(const std::wstring& line)
    {
        return ps::Split(line, L"\t", false);
    }

    long long Number(const std::wstring& s)
    {
        return _wcstoi64(s.c_str(), nullptr, 10);
    }

    Translation Parse(const Payload& p)
    {
        auto slice = [&](const std::wstring& offset, const std::wstring& length) {
            long long o = Number(offset), n = Number(length);
            if (o < 0 || n < 0 || (size_t)(o + n) > p.Size) throw PatchError{ L"The translation in the exe is damaged." };
            return Bytes(p.Data + o, p.Data + o + n);
        };
        Translation t;
        TrFile* file = nullptr;
        for (const std::wstring& raw : ps::Split(ps::FromUtf8(p.Index), L"\n", false))
        {
            std::wstring line = ps::TrimEnd(raw, L"\r");
            if (line.empty() || line[0] == L'#') continue;
            std::vector<std::wstring> f = Fields(line);
            const std::wstring& kind = f[0];
            if (kind == L"file" && f.size() >= 3)
            {
                t.Files.push_back(TrFile());
                file = &t.Files.back();
                file->Rel = f[1];
                file->Size = Number(f[2]);
            }
            else if (kind == L"item" && f.size() >= 5 && file != nullptr)
            {
                file->Items.push_back(TrItem{ f[1], slice(f[3], f[4]), f[2] });
            }
            else if (kind == L"place" && f.size() >= 6 && file != nullptr)
            {
                file->Inplace.push_back(TrPlace{ (int)Number(f[1]), slice(f[2], f[3]), slice(f[4], f[5]) });
            }
            else if (kind == L"whole" && f.size() >= 4 && file != nullptr)
            {
                file->HasWhole = true;
                file->WholeFrom = f[1];
                file->Whole = slice(f[2], f[3]);
            }
            else if (kind == L"sendby" && f.size() >= 8)
            {
                t.SendBy = TrSendBy{ f[1], f[2], f[3], slice(f[4], f[5]), slice(f[6], f[7]) };
            }
        }
        return t;
    }
}

const TrFile* Translation::File(const std::wstring& rel) const
{
    for (const TrFile& f : Files)
    {
        if (ps::OrdinalIgnoreCaseEq(f.Rel, rel)) return &f;
    }
    return nullptr;
}

const Translation& Translation::Get()
{
    static Translation* loaded = nullptr;
    if (loaded == nullptr) loaded = new Translation(Parse(LoadPayload()));
    return *loaded;
}
