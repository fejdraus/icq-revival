// See Icq2003bClient.h.

#include "Icq2003bClient.h"
#include "IcqResources.h"
#include "RegistryPath.h"
#include "Translation.h"
#include "../common/ClientFolder.h"
#include "../common/PatchSettings.h"

#include <windows.h>

#include <algorithm>

const wchar_t* Icq2003bClient::BinSuffix = L".antibanner-backup";
const wchar_t* Icq2003bClient::LinkSuffix = L".icq-links-backup";
const wchar_t* Icq2003bClient::SettingsKey = L"Software\\OpenOSCAR\\IcqPatch";

namespace
{
    // --- code patches -----------------------------------------------------------
    //
    // The names of the functions come from the export tables of the modules
    // themselves: they export decorated C++ names, so the places were found by
    // name, not by guessing.

    struct CodePatch
    {
        std::wstring File;
        int Offset;
        std::wstring Resource;
        Bytes From;
        Bytes To;
        long long Size;
        std::wstring What;
        std::wstring Job;
    };

    Bytes Utf16(const wchar_t* s)
    {
        Bytes b;
        for (; *s; s++)
        {
            b.push_back((unsigned char)(*s & 0xFF));
            b.push_back((unsigned char)(*s >> 8));
        }
        return b;
    }

    const std::vector<CodePatch>& Patches()
    {
        static const std::vector<CodePatch> patches = {
            { L"icqmutl.dll", 0x20626, L"", { 0xB8, 0x96, 0x9B, 0x22, 0x20 }, { 0x31, 0xC0, 0xC2, 0x04, 0x00 }, 270421,
              L"contact list banner is never created", L"banners" },
            { L"ICQProLib.dll", 0x1217B, L"", { 0xB8, 0xBA, 0x7D, 0x89, 0x24 }, { 0x31, 0xC0, 0xC3 }, 198739,
              L"message window banner is never shown", L"banners" },
            { L"ICQTicker.dll", 0x750, L"", { 0x53, 0x55, 0x8B, 0x6C, 0x24, 0x14, 0x56 }, { 0xB8, 0x11, 0x01, 0x04, 0x80, 0xC2, 0x0C, 0x00 }, 37977,
              L"Google search bar and its button are gone", L"google bar" },
            // The 22 px the layout keeps for the bar above: one job with it.
            { L"Icq.exe", 0x39AA2, L"", { 0x74, 0x41 }, { 0xEB, 0x41 }, 1880639,
              L"no empty strip reserved for them", L"google bar" },
            // The "Send By: ICQ / SMS / Email" strip in the message window. SMS and
            // Email went through gateways on ICQ.com and there is nothing behind
            // them any more, so the strip only offers ways to fail.
            //
            // The strip is made of three layers that know nothing about each
            // other, and each needed its own change:
            //
            //   1. the three tick boxes - controls of the plugin's dialog;
            //   2. the words "Send By:"  - a string in Icq.exe, painted by the skin;
            //   3. the frame around them - an object in Skin\IcqPro.skn.
            //
            // This is the first layer. The dialog template is not where visibility
            // is decided: a layout routine calls ShowWindow itself and works out
            // the argument as 5 (SW_SHOW) or 0 (SW_HIDE):
            //
            //   neg eax ; sbb eax, eax ; and al, 0xFB ; add eax, 5
            //
            // Zeroing the result makes the client hide the boxes with its own
            // call. They stay in the dialog and the ICQ box stays ticked, so the
            // code still reads it and Send keeps working. Two places: eax for the
            // group, edi for the three boxes pushed after it.
            { L"ICQMessagePlugin.dll", 0x7B63, L"", { 0x83, 0xC0, 0x05 }, { 0x31, 0xC0, 0x90 }, 236144,
              L"tick boxes ICQ / SMS / Email are hidden", L"send-by" },
            { L"ICQMessagePlugin.dll", 0x7B84, L"", { 0x83, 0xC7, 0x05 }, { 0x31, 0xFF, 0x90 }, 236144,
              L"the same for the group around them", L"send-by" },
            // Second layer: the words. There is no control behind them - a walk
            // of the open window shows none - the skin paints them from this
            // string, string 8727 of Icq.exe, so only the string itself can be
            // changed. It is written as a resource, blank, in English or in
            // Ukrainian - see "the binaries" below; the offset is where it sits
            // in the original. The three layers of the strip only make sense
            // together.
            { L"Icq.exe", 0x1C489C, L"sendBy", Utf16(L"Send By:"), Utf16(L"        "), 1880639,
              L"the words \"Send By:\" are gone", L"send-by" },
            // Third layer: the frame. An object named RgnFrame in the skin, 334x32
            // from x=136 to x=470 - it used to hold the tick boxes, and with them
            // hidden its left half was empty. Its position is worked out from
            // anchors and offsets, not from the rectangle, so the offset is what
            // actually moves it; the rectangle is kept in step so the file stays
            // consistent with itself.
            //
            // 344 is as close to the Send button as the skin can draw: the curve
            // of the left end is part of a stretched image, and below this width
            // it visibly flattens. Hiding the object outright is not an option -
            // it shapes the window, and without it the right edge clips the
            // indicator.
            { L"Skin\\IcqPro.skn", 0x41750, L"", { 0xAB, 0xFE, 0xFF, 0xFF }, { 0x7B, 0xFF, 0xFF, 0xFF }, 423358,
              L"the frame is pulled up to the Send button", L"send-by" },
            { L"Skin\\IcqPro.skn", 0x41782, L"", { 0x88, 0x00, 0x00, 0x00 }, { 0x58, 0x01, 0x00, 0x00 }, 423358,
              L"its rectangle follows the offset", L"send-by" },
        };
        return patches;
    }

    // --- addresses built into the code ---------------------------------------------
    //
    // These links sit in Icq.exe as strings; there is no file with them. A
    // string can only be replaced by one no longer than it: the tail is
    // filled with zeros, and nothing can be moved. So the server has the
    // short paths /p, /u, /e, /m at the root of the address, which only
    // redirect to the full pages.

    struct StringPatch
    {
        std::wstring File;
        int Offset;
        std::wstring Path;
        std::wstring Original;
        std::wstring What;
    };

    const std::vector<StringPatch>& StringPatches()
    {
        static const std::vector<StringPatch> patches = {
            { L"Icq.exe", 0x14269C, L"/p", L"http://cf.icq.com/cf/2003b/password.html",
              L"\"Forgot your ICQ#/Password?\" on the login window" },
            { L"Icq.exe", 0x14283C, L"/e", L"http://cf.icq.com/cf/2003b/email_login.html",
              L"\"ICQ#/Email\" help on the login window" },
            { L"Icq.exe", 0x140448, L"/u", L"http://cf.icq.com/cf/2003b/unregister.html",
              L"help on deleting your number" },
            { L"Icq.exe", 0x142804, L"/m", L"http://cf.icq.com/cf/2003b/public_private_modes.html",
              L"help on public and private mode" },
        };
        return patches;
    }

    // --- links ----------------------------------------------------------------------

    const std::vector<std::wstring> LinkFiles = {
        L"DataFiles\\icqlinks.xml",
        L"DataFiles\\channels.xml",
        L"DataFiles\\atelink.xml",
        L"DataFiles\\icqacc.xml",
        L"DataFiles\\psearch.xml",
        L"DataFiles\\WebSearch.fld",
    };

    const std::vector<std::wstring> DeadHosts = {
        L"cb.icq.com", L"cf.icq.com", L"cgi.icq.com", L"google.icq.com", L"mail.icqmail.com",
        L"members.icq.com", L"news.icqit.com", L"public.icq.com", L"search.icq.com",
        L"web.icq.com", L"www.icq.com", L"www.icqit.com", L"wwp.icq.com",
    };

    // Links with a known name in icqlinks.xml go to their own pages.
    const std::vector<std::pair<std::wstring, std::wstring>> NamedRoutes = {
        { L"StartPage", L"{base}/today?uin=%icquin%" },
        { L"WWP", L"{base}/center?uin=%d" },
        { L"HowTo", L"{base}/howto?uin=%icquin%" },
        { L"Main Page", L"{base}/howto?uin=%icquin%" },
        { L"Password", L"{base}/password" },
        { L"PasswordR", L"{base}/password" },
        { L"Registration", L"{base}/register" },
        { L"Fail Register", L"{base}/register" },
        { L"Delete User", L"{base}/account" },
        { L"Whitepages", L"{base}/whitepages" },
        { L"White Pages Update", L"{base}/whitepages" },
        { L"Users Lists", L"{base}/whitepages" },
        { L"OtherDirectories", L"{base}/whitepages" },
        { L"Homepage Directory", L"{base}/whitepages" },
        { L"Map", L"{base}/map" },  // Google Maps at the address the client appends
    };

    // Links without a name are recognised by the address itself. The order
    // matters: the particular before the general, or the general rule would
    // catch the search request and lose the word. (The patterns of the C#
    // patch are plain text, matched anywhere, ignoring case.)
    //
    // About "=REPLACEME": the client puts the typed word in place of this
    // sequence together with the equals sign, hence the two signs - the
    // first one stays in the address.
    const std::vector<std::pair<std::wstring, std::wstring>> UrlRoutes = {
        { L"google.icq.com/search", L"https://www.google.com/search?q==REPLACEME" },
        { L"search.icq.com", L"{base}/whitepages" },
        { L"google.icq.com", L"https://www.google.com/" },
        { L"/welcome/", L"{base}/welcome?uin=%icquin%" },
    };

    // Only the server's domain is asked for. The port and path of the pages
    // are the same on every ICQ Revival server (deploy/VM-SPEC.md, section 3),
    // so the patch fills them in: 2003b opens these links in the browser,
    // which wants HTTPS.
    const int PagesPortHttps = 8102;
    const wchar_t* PagesPath = L"/icq";

    std::wstring PagesRoot(const std::wstring& domain) { return L"https://" + domain + L":" + ps::Num(PagesPortHttps); }

    const wchar_t* SettingsPath = L"HKCU:\\Software\\OpenOSCAR\\IcqPatch";

    // --- sign-in server -----------------------------------------------------------
    //
    // ICQ 2003b keeps the server in two places. Default Server Host under
    // HKLM is what a new install starts from - and what "Get an ICQ Number"
    // connects to: out of the box it is login.icq.com, which is gone, so
    // registering failed with "Info Number 117". On its first run the client
    // copies it into the connection settings under HKCU, and from then on
    // signs in with those; the default is not read again. So both are set.
    //
    // The connection settings are only taken over while they still hold the
    // dead default, or a server this patch put there before: a server the
    // user typed under Preferences -> Connection stays theirs. The port stays
    // 5190, as it is there already. What each held first is saved once, for
    // Restore original.

    const std::vector<std::wstring> DefaultPrefsKeys = {
        L"HKLM:\\SOFTWARE\\WOW6432Node\\Mirabilis\\ICQ\\ICQPro\\DefaultPrefs",  // 64-bit Windows
        L"HKLM:\\SOFTWARE\\Mirabilis\\ICQ\\ICQPro\\DefaultPrefs",              // 32-bit Windows
    };
    const wchar_t* SignInValue = L"Default Server Host";
    const wchar_t* ConnectionKey = L"HKCU:\\Software\\Mirabilis\\ICQ\\CommonPrefs\\Connection";
    const wchar_t* ConnectionValue = L"ServerHostName";
    const wchar_t* DeadSignIn = L"login.icq.com";

    OptStr DefaultPrefsKey()
    {
        for (const std::wstring& k : DefaultPrefsKeys)
        {
            if (RegistryPath::Exists(k)) return k;
        }
        return std::nullopt;
    }

    // Whether the connection settings are the patch's to change: the dead
    // default, or the server of an earlier apply.
    bool ConnectionOurs(const OptStr& current, const OptStr& previous)
    {
        return ps::Eq(ps::Or(current), DeadSignIn) || (ps::IsTrue(previous) && ps::Eq(ps::Or(current), *previous));
    }

    // Saves what a value held first - once, so a second apply does not save
    // our own domain as the "original".
    void SaveOriginal(const std::wstring& name, const OptStr& value)
    {
        try
        {
            if (!RegistryPath::Exists(SettingsPath)) RegistryPath::Create(SettingsPath);
        }
        catch (const PatchError& e)
        {
            PatchFiles::Error(e.Message);
        }
        if (!ps::IsTrue(RegistryPath::Get(SettingsPath, name)))
        {
            try
            {
                RegistryPath::Set(SettingsPath, name, ps::Or(value));
            }
            catch (const PatchError& e)
            {
                PatchFiles::Error(e.Message);
            }
        }
    }

    // original / patched / missing, for the domain.
    std::wstring SignInState(const std::wstring& domain, const OptStr& previous)
    {
        if (!DefaultPrefsKey()) return L"missing";
        if (!ps::IsTrue(domain) || !ps::Eq(ps::Or(Icq2003bClient::SignInServer()), domain)) return L"original";
        OptStr c = Icq2003bClient::ConnectionServer();
        if (ps::IsTrue(c) && !ps::Eq(*c, domain) && ConnectionOurs(c, previous)) return L"original";
        return L"patched";
    }

    bool SetSignInServer(const std::wstring& domain, const OptStr& previous)
    {
        OptStr k = DefaultPrefsKey();
        if (!k) return false;
        bool changed = false;
        try
        {
            OptStr current = Icq2003bClient::SignInServer();
            if (!ps::Eq(ps::Or(current), domain))
            {
                SaveOriginal(L"OriginalServerHost", current);
                RegistryPath::Set(*k, SignInValue, domain);
                changed = true;
            }
            OptStr c = Icq2003bClient::ConnectionServer();
            if (ps::IsTrue(c) && !ps::Eq(*c, domain) && ConnectionOurs(c, previous))
            {
                SaveOriginal(L"OriginalConnectionHost", c);
                RegistryPath::Set(ConnectionKey, ConnectionValue, domain);
                changed = true;
            }
        }
        catch (const PatchError&)
        {
        }
        return changed;
    }

    // Puts back what was saved; a saved value is only let go once it is back
    // in place.
    int RestoreSignInServer()
    {
        int done = 0;
        OptStr saved = RegistryPath::Get(SettingsPath, L"OriginalServerHost");
        OptStr k = DefaultPrefsKey();
        if (ps::IsTrue(saved) && k)
        {
            try
            {
                RegistryPath::Set(*k, SignInValue, *saved);
                RegistryPath::Remove(SettingsPath, L"OriginalServerHost");
                done++;
            }
            catch (const PatchError&)
            {
            }
        }
        saved = RegistryPath::Get(SettingsPath, L"OriginalConnectionHost");
        if (ps::IsTrue(saved) && RegistryPath::Exists(ConnectionKey))
        {
            try
            {
                RegistryPath::Set(ConnectionKey, ConnectionValue, *saved);
                RegistryPath::Remove(SettingsPath, L"OriginalConnectionHost");
                done++;
            }
            catch (const PatchError&)
            {
            }
        }
        return done;
    }

    // --- the binaries -----------------------------------------------------------------
    //
    // Every program file the patch changes is built again on each Apply, from
    // its original - the backup, or the file itself while it has none - with
    // the wanted changes in this order: code bytes, the links inside Icq.exe,
    // then resources: the Ukrainian interface and the blanked "Send By:".
    // Taking a change out is leaving it out of the build, and the result is
    // exact.

    const Translation& Tr() { return Translation::Get(); }

    std::vector<std::wstring> TranslationFiles()
    {
        std::vector<std::wstring> files;
        for (const TrFile& f : Tr().Files) files.push_back(f.Rel);
        return files;
    }

    // The original of a program file: its backup, or the file while it has none.
    std::wstring OriginalPath(const std::wstring& path)
    {
        std::wstring backup = path + Icq2003bClient::BinSuffix;
        if (PatchFiles::Exists(backup)) return backup;
        return path;
    }

    std::vector<std::optional<Bytes>> ReadResources(const std::wstring& path, const std::vector<std::wstring>& keys)
    {
        return IcqResources::Read(PatchFiles::ReadAllBytes(path), keys);
    }

    // A byte array in an if.
    bool IsTrue(const std::optional<Bytes>& b) { return b && ps::IsTrue(&*b); }

    // Everything one file's resources come to on this client, built from its
    // English original (the backup, or the file while it has none).
    MatFile Materialize(const std::wstring& rel, const std::wstring& path)
    {
        return Tr().Materialize(*Tr().File(rel), PatchFiles::ReadAllBytes(OriginalPath(path)));
    }

    // Two resources the same; nothing is the same as nothing else.
    bool Same(const std::optional<Bytes>& a, const std::optional<Bytes>& b) { return b && IcqResources::Same(a, *b); }

    // The "Send By:" words: blank in either language, or as they came.
    std::wstring SendByState(const std::wstring& path)
    {
        const TrSendBy& sb = Tr().SendBy;
        std::optional<Bytes> cur = ReadResources(path, { sb.Key })[0];
        MatFile mat = Materialize(sb.File, path);
        if (Same(cur, mat.BlankEn) || Same(cur, mat.BlankUk)) return L"patched";
        if (IsTrue(cur) && ps::Eq(Translation::Sha(*cur), sb.From)) return L"original";
        const Bytes* table = mat.ByKey(sb.Key);
        if (table != nullptr && IcqResources::Same(cur, *table)) return L"original";
        return L"unknown";
    }

    // --- moving the links -----------------------------------------------------------

    std::wstring Base(const std::wstring& domain) { return PagesRoot(domain) + PagesPath; }

    // Where https?:// ends at the start of s (ignoring case), or 0.
    size_t SchemeEnd(const std::wstring& s)
    {
        if (!ps::StartsWithIgnoreCase(s, L"http")) return 0;
        if (s.size() > 4 && ps::CharEqIgnoreCase(s[4], L's') && s.compare(5, 3, L"://") == 0) return 8;
        if (s.compare(4, 3, L"://") == 0) return 7;
        return 0;
    }

    // ^https?://([^/:]+), ignoring case; the host lower-cased.
    std::wstring UrlHost(const std::wstring& url)
    {
        size_t at = SchemeEnd(url);
        if (at == 0) return L"";
        size_t end = at;
        while (end < url.size() && url[end] != L'/' && url[end] != L':') end++;
        if (end == at) return L"";
        return ps::ToLower(url.substr(at, end - at));
    }

    bool IsDead(const std::wstring& url) { return ps::Contains(DeadHosts, UrlHost(url)); }

    std::wstring WithBase(const std::wstring& target, const std::wstring& b) { return ps::Replace(target, L"{base}", b, true); }

    // What a link becomes: by its name, by the pattern of its address, a
    // stub - or nothing.
    std::wstring ResolveTarget(const std::wstring& name, const std::wstring& url, const std::wstring& b)
    {
        if (ps::IsTrue(name))
        {
            for (const auto& r : NamedRoutes)
            {
                if (ps::KeyEq(r.first, name)) return WithBase(r.second, b);
            }
        }
        for (const auto& r : UrlRoutes)
        {
            if (ps::Has(url, r.first, true)) return WithBase(r.second, b);
        }
        if (IsDead(url))
        {
            std::wstring leaf = ps::TrimEnd(ps::Split(url, L"?", true)[0], L"/");
            std::vector<std::wstring> parts = ps::Split(leaf, L"/", true);
            leaf = parts.back();
            if (!ps::IsTrue(leaf)) leaf = L"index";
            return b + L"/stub/" + leaf;
        }
        return L"";
    }

    // https?://[^\s"'<>\]]+ - minding case. Gives where each address starts
    // and how long it is, left to right, as Regex.Matches finds them.
    std::vector<std::pair<size_t, size_t>> FindUrls(const std::wstring& text)
    {
        std::vector<std::pair<size_t, size_t>> found;
        auto allowed = [](wchar_t c) {
            return !ps::IsWhiteSpace(c) && c != L'"' && c != L'\'' && c != L'<' && c != L'>' && c != L']';
        };
        size_t i = 0;
        while (i < text.size())
        {
            if (text.compare(i, 4, L"http") == 0)
            {
                size_t j = i + 4, k = 0;
                if (j < text.size() && text[j] == L's' && text.compare(j + 1, 3, L"://") == 0 && j + 4 < text.size() && allowed(text[j + 4]))
                    k = j + 4;
                else if (text.compare(j, 3, L"://") == 0 && j + 3 < text.size() && allowed(text[j + 3]))
                    k = j + 3;
                if (k != 0)
                {
                    size_t end = k;
                    while (end < text.size() && allowed(text[end])) end++;
                    found.push_back({ i, end - i });
                    i = end;
                    continue;
                }
            }
            i++;
        }
        return found;
    }

    // (?is)<tag>\s*([^<]*?)\s*</tag> in text: where the group starts and how
    // long it is, for the first match; nothing without one.
    std::optional<std::pair<size_t, size_t>> TagText(const std::wstring& text, const std::wstring& tag)
    {
        std::wstring open = L"<" + tag + L">", close = L"</" + tag + L">";
        size_t p = 0;
        for (;;)
        {
            p = ps::Find(text, open, p, true);
            if (p == std::wstring::npos) return std::nullopt;
            size_t start = p + open.size();
            while (start < text.size() && ps::IsWhiteSpace(text[start])) start++;
            for (size_t end = start;; end++)
            {
                size_t r = end;
                while (r < text.size() && ps::IsWhiteSpace(text[r])) r++;
                if (ps::StartsWithIgnoreCase(text.substr(r, close.size()), close) && text.size() - r >= close.size())
                {
                    return std::make_pair(start, end - start);
                }
                if (end >= text.size() || text[end] == L'<') break;
            }
            p++;
        }
    }

    std::wstring ConvertLinkText(const std::wstring& input, const std::wstring& b)
    {
        std::wstring text = input;
        // Entries with a name: the name and the address lie in one <item> block.
        if (ps::Has(text, L"<item>", true))
        {
            std::wstring out;
            size_t pos = 0;
            for (;;)
            {
                // (?s)<item>.*?</item>, minding case.
                size_t open = text.find(L"<item>", pos);
                if (open == std::wstring::npos) break;
                size_t close = text.find(L"</item>", open + 6);
                if (close == std::wstring::npos) break;
                size_t end = close + 7;
                std::wstring block = text.substr(open, end - open);
                out.append(text, pos, open - pos);
                std::wstring replaced = block;
                std::optional<std::pair<size_t, size_t>> um = TagText(block, L"url");
                if (um)
                {
                    std::wstring url = block.substr(um->first, um->second);
                    if (SchemeEnd(url) != 0)
                    {
                        std::optional<std::pair<size_t, size_t>> nm = TagText(block, L"name");
                        std::wstring name = nm ? block.substr(nm->first, nm->second) : L"";
                        std::wstring target = ResolveTarget(name, url, b);
                        if (ps::IsTrue(target) && !ps::Eq(target, url))
                        {
                            replaced = block.substr(0, um->first) + target + block.substr(um->first + um->second);
                        }
                    }
                }
                out += replaced;
                pos = end;
            }
            out.append(text, pos, std::wstring::npos);
            text = out;
        }

        // Everything else: addresses in other tags, in attributes, in the
        // fields of WebSearch.fld. Only dead hosts are touched, so nothing of
        // anybody else's is.
        std::wstring out;
        size_t pos = 0;
        for (const auto& m : FindUrls(text))
        {
            out.append(text, pos, m.first - pos);
            std::wstring url = text.substr(m.first, m.second);
            std::wstring result = url;
            if (IsDead(url))
            {
                std::wstring target = ResolveTarget(L"", url, b);
                if (ps::IsTrue(target) && !ps::Eq(target, url)) result = target;
            }
            out += result;
            pos = m.first + m.second;
        }
        out.append(text, pos, std::wstring::npos);
        return out;
    }

    // --- applying -----------------------------------------------------------------

    std::wstring StringAt(const std::wstring& path, int offset, size_t len)
    {
        Bytes buf = PatchFiles::ReadAt(path, offset, len);
        std::wstring text;
        for (unsigned char c : buf)
        {
            if (c == 0) break;
            text += c < 0x80 ? (wchar_t)c : L'?';
        }
        return text;
    }

    // Backs a program file up once, before its first change: while it has
    // no backup, the file is still the original.
    void BackupBin(const std::wstring& path) { PatchFiles::BackupOnce(path, Icq2003bClient::BinSuffix); }

    // Every program file the patch may change.
    std::vector<std::wstring> BinaryFiles()
    {
        std::vector<std::wstring> all;
        for (const CodePatch& p : Patches()) all.push_back(p.File);
        for (const StringPatch& s : StringPatches()) all.push_back(s.File);
        for (const std::wstring& f : TranslationFiles()) all.push_back(f);
        return ps::Unique(all);
    }

    void Put(Bytes& bytes, size_t at, const Bytes& data)
    {
        if (at + data.size() > bytes.size()) throw PatchError{ L"Destination array was not long enough. Check destIndex and length, and the array's lower bounds." };
        std::copy(data.begin(), data.end(), bytes.begin() + at);
    }
}

// --- the client ------------------------------------------------------------------

const PatchJobs& Icq2003bClient::Jobs()
{
    static PatchJobs* jobs = nullptr;
    if (jobs == nullptr)
    {
        PatchJobs* j = new PatchJobs();
        j->Add(L"banners", L"Advertising", L"the banners of the contact list and the message window");
        j->Add(L"google bar", L"Advertising", L"the Google search bar and the strip kept for it");
        j->Add(L"send-by", L"Services that are gone", L"the \"Send By: ICQ / SMS / Email\" strip of the message window");
        j->Add(L"links", L"Your server", L"ICQ.com links in menus and help point at your server");
        j->Add(L"sign-in", L"Your server", L"ICQ signs in to your server, \"Get an ICQ Number\" too");
        // Off until chosen: not everyone wants the client in another language.
        j->Add(L"ukrainian", L"Language", L"Ukrainian interface: menus, windows and messages", true);

        j->Assign(L"sign-in", L"sign-in");
        for (const CodePatch& p : Patches())
        {
            if (ps::IsTrue(p.Job)) j->Assign(p.What, p.Job);
        }
        for (const std::wstring& f : TranslationFiles()) j->Assign(L"uk:" + f, L"ukrainian");
        for (const StringPatch& sp : StringPatches()) j->Assign(sp.What, L"links");
        for (const std::wstring& rel : LinkFiles) j->Assign(rel, L"links");
        jobs = j;
    }
    return *jobs;
}

OptStr Icq2003bClient::SavedBase()
{
    OptStr value = PatchSettings::Read(SettingsKey, L"ServerBase");
    if (!value) return std::nullopt;
    return Domain::Of(value);
}

void Icq2003bClient::SaveBase(const std::wstring& value) { PatchSettings::Save(SettingsKey, L"ServerBase", value); }

OptStr Icq2003bClient::SignInServer()
{
    OptStr k = DefaultPrefsKey();
    if (!k) return std::nullopt;
    return RegistryPath::Get(*k, SignInValue);
}

OptStr Icq2003bClient::ConnectionServer() { return RegistryPath::Get(ConnectionKey, ConnectionValue); }

bool Icq2003bClient::IsClientFolder(const OptStr& path)
{
    if (ps::IsNullOrWhiteSpace(path) || !PatchFiles::Exists(*path)) return false;
    for (const CodePatch& p : Patches())
    {
        if (!PatchFiles::Exists(PatchFiles::Join(*path, p.File))) return false;
    }
    return true;
}

OptStr Icq2003bClient::FindRoot()
{
    ClientSearch search;
    search.AppPathsExe = L"Icq.exe";
    search.TrimQuotes = false;
    search.IsDisplayName = [](const std::wstring& name) { return ps::StartsWithIgnoreCase(name, L"icq"); };  // (?i)^icq
    search.UseUninstallString = true;
    search.StandardFolder = L"ICQ";
    search.IsClient = [](const std::wstring& path) { return IsClientFolder(path); };
    return ClientFolder::Find(search);
}

std::wstring Icq2003bClient::ExpectedFiles()
{
    std::vector<std::wstring> files;
    for (const CodePatch& p : Patches()) files.push_back(p.File);
    return ps::Join(files, L", ");
}

namespace
{
    std::wstring State(const std::wstring& root, const CodePatch& patch)
    {
        if (!ps::IsTrue(root)) return L"no folder";
        std::wstring path = PatchFiles::Join(root, patch.File);
        if (!PatchFiles::Exists(path)) return L"missing";
        // The offsets are right for build 3916 only: the original is
        // recognised by its size, and the change by its bytes - which a
        // translated file keeps in place.
        if (PatchFiles::Length(OriginalPath(path)) != patch.Size) return L"other version";
        if (ps::IsTrue(patch.Resource)) return SendByState(path);
        size_t len = (std::max)(patch.From.size(), patch.To.size());
        Bytes buf = PatchFiles::ReadAt(path, patch.Offset, len);
        auto same = [&](const Bytes& expect) { return std::equal(expect.begin(), expect.end(), buf.begin()); };
        if (same(patch.To)) return L"patched";
        if (same(patch.From)) return L"original";
        return L"unknown";
    }

    // Whether a file speaks Ukrainian: all its resources translated, none,
    // or a mix.
    std::wstring TranslationState(const std::wstring& root, const std::wstring& rel)
    {
        if (!ps::IsTrue(root)) return L"no folder";
        std::wstring path = PatchFiles::Join(root, rel);
        if (!PatchFiles::Exists(path)) return L"missing";
        const TrFile& entry = *Tr().File(rel);
        if (PatchFiles::Length(OriginalPath(path)) != entry.Size) return L"other version";
        const TrSendBy& sb = Tr().SendBy;
        MatFile mat = Tr().Materialize(entry, PatchFiles::ReadAllBytes(OriginalPath(path)));
        const std::vector<MatItem>& items = mat.Items;
        int done = 0, orig = 0;
        if (!items.empty())
        {
            std::vector<std::wstring> keys;
            for (const MatItem& i : items) keys.push_back(i.Key);
            std::vector<std::optional<Bytes>> cur = ReadResources(path, keys);
            for (size_t i = 0; i < items.size(); i++)
            {
                const MatItem& it = items[i];
                const std::optional<Bytes>& c = cur[i];
                bool isSendBy = ps::Eq(rel, sb.File) && ps::Eq(it.Key, sb.Key);
                bool blankUk = isSendBy && Same(c, mat.BlankUk);
                bool blankEn = isSendBy && Same(c, mat.BlankEn);
                if (IcqResources::Same(c, it.Data) || blankUk) done++;
                else if (blankEn || (IsTrue(c) && ps::Eq(Translation::Sha(*c), it.From))) orig++;
            }
        }
        if (!entry.Inplace.empty())
        {
            Bytes bytes = PatchFiles::ReadAllBytes(path);
            for (const TrPlace& pl : entry.Inplace)
            {
                if ((size_t)pl.Offset + pl.Data.size() > bytes.size()) throw PatchError{ L"Source array was not long enough. Check srcIndex and length, and the array's lower bounds." };
                Bytes c(bytes.begin() + pl.Offset, bytes.begin() + pl.Offset + pl.Data.size());
                if (c == pl.Data) done++;
                else if (c == pl.Original) orig++;
            }
        }
        size_t all = items.size() + entry.Inplace.size();
        if (entry.HasWhole)
        {
            // A text file written whole.
            all++;
            Bytes bytes = PatchFiles::ReadAllBytes(path);
            if (bytes == entry.Whole) done++;
            else if (ps::Eq(Translation::Sha(bytes), entry.WholeFrom)) orig++;
        }
        if ((size_t)done == all) return L"patched";
        if ((size_t)orig == all) return L"original";
        if (done > 0) return L"partly";
        return L"unknown";
    }

    std::wstring LinkState(const std::wstring& root, const std::wstring& rel)
    {
        if (!ps::IsTrue(root)) return L"no folder";
        std::wstring path = PatchFiles::Join(root, rel);
        if (!PatchFiles::Exists(path)) return L"missing";
        std::wstring text = PatchFiles::ReadAllTextLatin1(path);
        std::vector<std::pair<size_t, size_t>> urls = FindUrls(text);
        int dead = 0;
        for (const auto& m : urls)
        {
            if (IsDead(text.substr(m.first, m.second))) dead++;
        }
        if (urls.empty()) return L"no links";
        return dead > 0 ? L"original" : L"patched";
    }

    std::wstring StringState(const std::wstring& root, const StringPatch& sp)
    {
        if (!ps::IsTrue(root)) return L"no folder";
        std::wstring path = PatchFiles::Join(root, sp.File);
        if (!PatchFiles::Exists(path)) return L"missing";
        std::wstring cur = StringAt(path, sp.Offset, sp.Original.size());
        if (ps::Eq(cur, sp.Original)) return L"original";
        if (SchemeEnd(cur) != 0) return L"patched";
        return L"other version";
    }

    // Builds one program file from its original with the wanted changes, and
    // writes it if it came out different. The links that did not fit are
    // added to tooLong.
    bool BuildBinary(const std::wstring& root, const std::wstring& rel, const std::wstring& domain, const ps::StringSet& skip,
                     std::vector<std::wstring>& tooLong)
    {
        const PatchJobs& jobs = Icq2003bClient::Jobs();
        std::wstring path = PatchFiles::Join(root, rel);
        if (!PatchFiles::Exists(path)) return false;
        Bytes bytes = PatchFiles::ReadAllBytes(OriginalPath(path));
        // The English original, kept aside: the translated resources are
        // built from it, whatever the code patches change in these bytes.
        const Bytes pristine = bytes;

        for (const CodePatch& p : Patches())
        {
            if (!ps::Eq(p.File, rel) || ps::IsTrue(p.Resource)) continue;
            if (jobs.IsWanted(skip, p.What) && (long long)bytes.size() == p.Size) Put(bytes, p.Offset, p.To);
        }

        // The strings built into the code get only the root of the address:
        // the room in the file is the length of the original link, and every
        // character counts.
        std::wstring pagesRoot = PagesRoot(domain);
        for (const StringPatch& sp : StringPatches())
        {
            if (!ps::Eq(sp.File, rel)) continue;
            if (!jobs.IsWanted(skip, sp.What)) continue;
            std::wstring url = pagesRoot + sp.Path;
            if (url.size() > sp.Original.size())
            {
                tooLong.push_back(sp.Path + L" (needs " + ps::Num((long long)url.size()) + L", room for " +
                                  ps::Num((long long)sp.Original.size()) + L")");
                continue;
            }
            Bytes text;
            for (wchar_t c : url) text.push_back(c < 0x80 ? (unsigned char)c : (unsigned char)'?');
            Bytes field(sp.Original.size(), 0);
            std::copy(text.begin(), text.end(), field.begin());
            if ((size_t)sp.Offset + field.size() > bytes.size()) throw PatchError{ L"Index was outside the bounds of the array." };
            Put(bytes, sp.Offset, field);
        }

        // The resources, by key; a later one for the same key wins. Texts that
        // are not resources - in the data of a program, in the skin - are
        // written in place, over the English ones.
        std::vector<std::pair<std::wstring, Bytes>> res;
        auto put = [&](const std::wstring& key, const Bytes& data) {
            for (auto& r : res)
            {
                if (ps::KeyEq(r.first, key))
                {
                    r.second = data;
                    return;
                }
            }
            res.push_back({ key, data });
        };
        const TrFile* entry = Tr().File(rel);
        bool ukrainian = entry != nullptr && jobs.IsWanted(skip, L"uk:" + rel) && (long long)bytes.size() == entry->Size;
        MatFile mat;
        if (entry != nullptr) mat = Tr().Materialize(*entry, pristine);
        if (ukrainian && entry->HasWhole) bytes = entry->Whole;
        if (ukrainian)
        {
            for (const MatItem& it : mat.Items) put(it.Key, it.Data);
            for (const TrPlace& pl : entry->Inplace) Put(bytes, pl.Offset, pl.Data);
        }
        const CodePatch* words = nullptr;
        for (const CodePatch& p : Patches())
        {
            if (ps::Eq(p.Resource, L"sendBy"))
            {
                words = &p;
                break;
            }
        }
        const TrSendBy& sb = Tr().SendBy;
        if (ps::Eq(rel, sb.File) && jobs.IsWanted(skip, words->What) && (long long)bytes.size() == words->Size)
        {
            const std::optional<Bytes>& blank = ukrainian ? mat.BlankUk : mat.BlankEn;
            if (blank) put(sb.Key, *blank);
        }

        // The resources are laid into the file's own bytes, in memory: the
        // section that holds them is rebuilt where it is, nothing else moves.
        if (!res.empty())
        {
            std::vector<std::wstring> keys;
            std::vector<Bytes> data;
            for (const auto& r : res)
            {
                keys.push_back(r.first);
                data.push_back(r.second);
            }
            bytes = IcqResources::Write(bytes, keys, data);
        }
        const Bytes& built = bytes;

        if (built != PatchFiles::ReadAllBytes(path))
        {
            BackupBin(path);
            PatchFiles::WriteAllBytes(path, built);
            return true;
        }
        return false;
    }

    // The client keeps the names its plugins give themselves - menu items,
    // pages of the preferences - in .pnCache, and takes them from there
    // rather than from the plugins once it has it. When the programs change -
    // another language - the cache goes, and the client builds it again from
    // them.
    void ClearPluginCache(const std::wstring& root)
    {
        std::wstring cache = PatchFiles::Join(root, L".pnCache");
        if (!PatchFiles::Exists(cache)) return;
        if (PatchFiles::FileExists(cache))
        {
            DWORD a = GetFileAttributesW(cache.c_str());
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_READONLY)) SetFileAttributesW(cache.c_str(), a & ~(DWORD)FILE_ATTRIBUTE_READONLY);
            DeleteFileW(cache.c_str());
            return;
        }
        // A folder only goes while it is empty.
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((cache + L"\\*").c_str(), &fd);
        bool any = false;
        if (h != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) any = true;
            } while (!any && FindNextFileW(h, &fd));
            FindClose(h);
        }
        if (!any) RemoveDirectoryW(cache.c_str());
    }
}

std::vector<PatchItem> Icq2003bClient::Items(const std::wstring& domain) const
{
    std::vector<PatchItem> items;
    auto add = [&](const std::wstring& group, const std::wstring& key, const std::wstring& what, const std::wstring& where,
                   const std::wstring& state) { items.push_back(PatchItem{ group, key, what, where, state }); };
    for (const CodePatch& p : Patches())
    {
        add(L"Code", p.What, p.What, p.File + L" at 0x" + ps::Hex((unsigned)p.Offset), State(Root, p));
    }
    for (const StringPatch& sp : StringPatches())
    {
        add(L"Links inside the executable", sp.What, sp.What, sp.File + L" at 0x" + ps::Hex((unsigned)sp.Offset), StringState(Root, sp));
    }
    for (const std::wstring& rel : LinkFiles)
    {
        std::wstring name = PatchFiles::FileName(rel);
        add(L"Links", rel, L"menu items in " + name + L" point at your server", name, LinkState(Root, rel));
    }
    OptStr shown = ConnectionServer();
    if (!ps::IsTrue(shown)) shown = SignInServer();
    if (!ps::IsTrue(shown)) shown = std::wstring(L"(not set)");
    add(L"Sign-in server", L"sign-in", L"ICQ signs in to your server", L"now " + *shown, SignInState(domain, SavedBase()));
    for (const std::wstring& f : TranslationFiles()) add(L"Language", L"uk:" + f, L"uk:" + f, f, TranslationState(Root, f));
    return Jobs().Merge(items);
}

Icq2003bResult Icq2003bClient::ApplyAll(const std::wstring& domain, const OptStr& previous, const ps::StringSet& skip) const
{
    const PatchJobs& jobs = Jobs();
    std::vector<std::wstring> wrongFiles;
    for (const CodePatch& p : Patches())
    {
        if (jobs.IsWanted(skip, p.What) && State(Root, p) == L"other version") wrongFiles.push_back(p.File);
    }
    std::vector<std::wstring> wrong = ps::Unique(wrongFiles);
    if (!wrong.empty())
    {
        throw PatchError{ L"These files do not match ICQ Pro 2003b build 3916:\n\n  " + ps::Join(wrong, L"\n  ") +
                          L"\n\nThe code patches are tied to exact offsets in that build. Applying them to " +
                          L"another version would overwrite unrelated code, so nothing was changed." };
    }
    std::vector<std::wstring> binaries = BinaryFiles();
    PatchSteps::Start((int)binaries.size() + 4);
    PatchSteps::Step(L"Checking the client...");
    std::vector<PatchItem> before = Items(domain);

    std::vector<std::wstring> tooLong;
    bool changed = false;
    for (const std::wstring& rel : binaries)
    {
        PatchSteps::Step(L"Building " + rel + L"...");
        if (BuildBinary(Root, rel, domain, skip, tooLong)) changed = true;
    }
    if (changed) ClearPluginCache(Root);
    PatchSteps::Step(L"Links in DataFiles...");

    std::wstring b = Base(domain);
    for (const std::wstring& rel : LinkFiles)
    {
        std::wstring path = PatchFiles::Join(Root, rel);
        if (!PatchFiles::Exists(path)) continue;
        std::wstring backup = path + LinkSuffix;
        if (!jobs.IsWanted(skip, rel))
        {
            if (PatchFiles::Exists(backup)) PatchFiles::Copy(backup, path, true);
            continue;
        }
        // Built again from the original each time, like the programs: a
        // new domain or a new target for a link then reaches a client
        // patched before, and nothing of an earlier server is left behind.
        if (!PatchFiles::Exists(backup)) PatchFiles::Copy(path, backup, false);
        std::wstring text = ConvertLinkText(PatchFiles::ReadAllTextLatin1(backup), b);
        if (!ps::Ceq(text, PatchFiles::ReadAllTextLatin1(path))) PatchFiles::WriteAllTextLatin1(path, text);
    }

    PatchSteps::Step(L"Sign-in server...");
    if (NoRegistry)
    {
    }
    else if (jobs.IsWanted(skip, L"sign-in"))
    {
        SetSignInServer(domain, previous);
    }
    else
    {
        try
        {
            RestoreSignInServer();
        }
        catch (const PatchError&)
        {
        }
    }

    Icq2003bResult result;
    PatchSteps::Step(L"Checking the result...");
    std::vector<PatchItem> after = Items(domain);
    for (size_t i = 0; i < after.size(); i++)
    {
        if (ps::Eq(after[i].State, before[i].State)) continue;
        if (ps::Eq(after[i].State, L"patched")) result.Lines.push_back(L"applied: " + after[i].What);
        else result.Lines.push_back(L"taken out: " + after[i].What);
    }
    result.TooLong = tooLong;
    return result;
}

int Icq2003bClient::RestoreAll() const
{
    int done = 0;
    std::vector<std::wstring> binaries = BinaryFiles();
    PatchSteps::Start((int)(binaries.size() + LinkFiles.size() + 1));
    for (const std::wstring& f : binaries)
    {
        PatchSteps::Step(L"Restoring " + f + L"...");
        std::wstring path = PatchFiles::Join(Root, f);
        std::wstring backup = path + BinSuffix;
        if (PatchFiles::Exists(backup))
        {
            PatchFiles::Copy(backup, path, true);
            done++;
        }
    }
    if (done > 0) ClearPluginCache(Root);
    for (const std::wstring& rel : LinkFiles)
    {
        PatchSteps::Step(L"Restoring " + rel + L"...");
        std::wstring path = PatchFiles::Join(Root, rel);
        std::wstring backup = path + LinkSuffix;
        if (PatchFiles::Exists(backup))
        {
            PatchFiles::Copy(backup, path, true);
            done++;
        }
    }
    PatchSteps::Step(L"Sign-in server...");
    if (!NoRegistry) done += RestoreSignInServer();
    return done;
}
