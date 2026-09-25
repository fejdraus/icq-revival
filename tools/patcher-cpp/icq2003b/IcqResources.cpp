// See IcqResources.h.

#include "IcqResources.h"
#include "../common/Ps.h"

namespace IcqResources
{
    namespace
    {
        // int.Parse / int.TryParse of the invariant culture: blanks around, a sign.
        bool ParseInt(const std::wstring& text, long& out)
        {
            std::wstring s = ps::Trim(text);
            size_t i = 0;
            bool negative = false;
            if (i < s.size() && (s[i] == L'-' || s[i] == L'+')) negative = s[i++] == L'-';
            if (i >= s.size()) return false;
            long long n = 0;
            for (; i < s.size(); i++)
            {
                if (s[i] < L'0' || s[i] > L'9') return false;
                n = n * 10 + (s[i] - L'0');
                if (n > 0x80000000LL) return false;
            }
            if (negative) n = -n;
            if (n > 0x7FFFFFFFLL || n < -0x80000000LL) return false;
            out = (long)n;
            return true;
        }

        PeResources::Id NameId(const std::wstring& name)
        {
            long id;
            if (!name.empty() && name[0] == L'#' && ParseInt(name.substr(1), id) && id >= 0)
            {
                return PeResources::Id::Of((uint32_t)id);
            }
            return PeResources::Id::OfName(name);
        }
    }

    PeResources::Key ParseKey(const std::wstring& key)
    {
        std::vector<std::wstring> p = ps::Split(key, L"|", false);
        long type, lang;
        if (p.size() < 3 || !ParseInt(p[0], type) || !ParseInt(p[2], lang)) throw PatchError{ L"Input string was not in a correct format." };
        return PeResources::Key{ PeResources::Id::Of((uint32_t)type), NameId(p[1]), (uint32_t)lang };
    }

    std::vector<std::optional<Bytes>> Read(const Bytes& file, const std::vector<std::wstring>& keys)
    {
        std::vector<PeResources::Key> parsed;
        for (const std::wstring& k : keys) parsed.push_back(ParseKey(k));
        return PeResources::Read(file, parsed);
    }

    bool Same(const std::optional<Bytes>& a, const Bytes& b) { return a && *a == b; }

    Bytes Write(const Bytes& file, const std::vector<std::wstring>& keys, const std::vector<Bytes>& data)
    {
        std::vector<PeResources::Key> parsed;
        for (const std::wstring& k : keys) parsed.push_back(ParseKey(k));
        return PeResources::Write(file, parsed, data);
    }
}
