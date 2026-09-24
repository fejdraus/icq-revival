// See PatchCli.h.

#include "PatchCli.h"

#include <stdlib.h>

const CliArgs::Value* CliArgs::Find(const std::wstring& name) const
{
    for (const Value& v : values_)
    {
        if (ps::OrdinalIgnoreCaseEq(v.Name, name)) return &v;
    }
    return nullptr;
}

CliArgs::Value& CliArgs::Slot(const std::wstring& name)
{
    for (Value& v : values_)
    {
        if (ps::OrdinalIgnoreCaseEq(v.Name, name)) return v;
    }
    values_.push_back(Value{ name });
    return values_.back();
}

bool CliArgs::Has(const std::wstring& name) const { return Find(name) != nullptr; }

bool CliArgs::Switch(const std::wstring& name) const
{
    const Value* v = Find(name);
    return v != nullptr && v->On;
}

OptStr CliArgs::Text(const std::wstring& name) const
{
    const Value* v = Find(name);
    if (v == nullptr) return std::nullopt;
    return v->Text;
}

std::vector<std::wstring> CliArgs::List(const std::wstring& name) const
{
    const Value* v = Find(name);
    return v != nullptr ? v->List : std::vector<std::wstring>();
}

void CliArgs::SetSwitch(const std::wstring& name, bool on) { Slot(name).On = on; }
void CliArgs::SetText(const std::wstring& name, const std::wstring& value) { Slot(name).Text = value; }
void CliArgs::SetList(const std::wstring& name, const std::vector<std::wstring>& value) { Slot(name).List = value; }

namespace PatchCli
{
    namespace
    {
        bool IsName(const std::wstring& a) { return !a.empty() && a[0] == L'-'; }

        const CliParam* Resolve(const std::wstring& name, const std::vector<CliParam>& spec)
        {
            for (const CliParam& p : spec)
            {
                if (ps::OrdinalIgnoreCaseEq(p.Name, name)) return &p;
            }
            std::vector<const CliParam*> prefix;
            for (const CliParam& p : spec)
            {
                if (ps::StartsWithOrdinalIgnoreCase(p.Name, name)) prefix.push_back(&p);
            }
            if (prefix.size() == 1) return prefix[0];
            if (prefix.size() > 1)
            {
                std::wstring names;
                for (size_t i = 0; i < prefix.size(); i++)
                {
                    if (i > 0) names += L" ";
                    names += L"-" + prefix[i]->Name;
                }
                throw CliException{ L"Parameter cannot be processed because the parameter name '" + name +
                                    L"' is ambiguous. Possible matches include: " + names + L"." };
            }
            return nullptr;
        }

        void Bind(CliArgs& result, const CliParam& p, const std::wstring& value)
        {
            if (p.Kind == CliKind::List) result.SetList(p.Name, SplitList(value));
            else result.SetText(p.Name, value);
        }
    }

    std::vector<std::wstring> SplitList(const std::wstring& value)
    {
        std::wstring v = ps::Trim(value);
        if (v.size() >= 2 && v.compare(0, 2, L"@(") == 0 && v.back() == L')') v = v.substr(2, v.size() - 3);
        std::vector<std::wstring> result;
        size_t start = 0;
        for (;;)
        {
            size_t comma = v.find(L',', start);
            std::wstring s = ps::Trim(v.substr(start, comma == std::wstring::npos ? std::wstring::npos : comma - start));
            if (s.size() >= 2 && (s[0] == L'\'' || s[0] == L'"') && s.back() == s[0]) s = s.substr(1, s.size() - 2);
            if (!s.empty()) result.push_back(s);
            if (comma == std::wstring::npos) break;
            start = comma + 1;
        }
        return result;
    }

    CliArgs Parse(const std::vector<std::wstring>& args, const std::vector<CliParam>& spec)
    {
        CliArgs result;
        std::vector<std::wstring> loose;
        for (size_t i = 0; i < args.size(); i++)
        {
            const std::wstring& a = args[i];
            if (!IsName(a))
            {
                loose.push_back(a);
                continue;
            }
            std::wstring name = ps::TrimStart(a, L"-");
            OptStr joined;
            size_t colon = name.find(L':');
            if (colon != std::wstring::npos)
            {
                joined = name.substr(colon + 1);
                name = name.substr(0, colon);
            }
            const CliParam* p = Resolve(name, spec);
            if (p == nullptr)
            {
                // Not one of ours: passed over, with its value.
                if (!joined && i + 1 < args.size() && !IsName(args[i + 1])) i++;
                continue;
            }
            if (result.Has(p->Name))
            {
                throw CliException{ L"Cannot bind parameter because parameter '" + p->Name + L"' is specified more than once. " +
                                    L"To pass several values to a parameter that takes a list, separate them with commas: -" + p->Name + L" value1,value2" };
            }
            if (p->Kind == CliKind::Switch)
            {
                bool on = true;
                if (joined)
                {
                    std::wstring v = ps::TrimStart(*joined, L"$");
                    if (ps::OrdinalIgnoreCaseEq(v, L"true")) on = true;
                    else if (ps::OrdinalIgnoreCaseEq(v, L"false")) on = false;
                    else throw CliException{ L"Cannot convert '" + *joined + L"' for the switch -" + p->Name + L": use $true or $false." };
                }
                result.SetSwitch(p->Name, on);
                continue;
            }
            std::wstring value;
            if (joined)
            {
                value = *joined;
            }
            else
            {
                if (i + 1 >= args.size() || IsName(args[i + 1]))
                {
                    throw CliException{ L"Missing an argument for parameter '" + p->Name + L"'. Specify a parameter of type " +
                                        std::wstring(p->Kind == CliKind::List ? L"'System.String[]'" : L"'System.String'") + L" and try again." };
                }
                value = args[++i];
            }
            Bind(result, *p, value);
        }
        // What came without a name fills the parameters that take a value,
        // in their order, once the named ones are bound.
        size_t next = 0;
        for (const std::wstring& value : loose)
        {
            while (next < spec.size() && (spec[next].Kind == CliKind::Switch || result.Has(spec[next].Name))) next++;
            if (next >= spec.size()) break;
            Bind(result, spec[next], value);
        }
        return result;
    }

    std::vector<std::wstring> ProcessArgs()
    {
        // The C runtime splits the command line by the rules the .NET
        // runtime follows too; the program's own name is left out.
        std::vector<std::wstring> args;
        for (int i = 1; i < __argc; i++) args.push_back(__wargv[i]);
        return args;
    }
}
