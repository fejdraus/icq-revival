// The command line of a client patch, read the way PowerShell read the
// parameters of the scripts the patches were first written as - the port of
// tools\patcher\Common\PatchCli.cs.
//
//   -Apply -Root C:\ICQ -Server icq.example.org -Skip xtraz,ads
//
// Names ignore case and may be cut short while they stay unambiguous (-Ro,
// -Se); a value follows its name or is joined to it with a colon (-Root:C:\x);
// a switch takes :$true or :$false; values without a name fill the named
// parameters that take one, in their order (Root, Server, Skip). A name the
// patch does not know is passed over together with the value after it. A list
// is separated by commas, as PowerShell writes one: -Skip xtraz,ads.

#pragma once

#include "Ps.h"

#include <string>
#include <vector>

enum class CliKind { Switch, Text, List };

struct CliParam
{
    std::wstring Name;
    CliKind Kind;
};

struct CliException
{
    std::wstring Message;
};

class CliArgs
{
public:
    bool Has(const std::wstring& name) const;
    bool Switch(const std::wstring& name) const;
    // A text value; nothing when not given.
    OptStr Text(const std::wstring& name) const;
    // A list value; empty when not given.
    std::vector<std::wstring> List(const std::wstring& name) const;

    void SetSwitch(const std::wstring& name, bool on);
    void SetText(const std::wstring& name, const std::wstring& value);
    void SetList(const std::wstring& name, const std::vector<std::wstring>& value);

private:
    struct Value
    {
        std::wstring Name;
        bool On = false;
        std::wstring Text;
        std::vector<std::wstring> List;
    };
    const Value* Find(const std::wstring& name) const;
    Value& Slot(const std::wstring& name);
    std::vector<Value> values_;
};

namespace PatchCli
{
    // Throws a CliException with the message PowerShell gave.
    CliArgs Parse(const std::vector<std::wstring>& args, const std::vector<CliParam>& spec);

    // "a,b", "'a','b'" and "@('a','b')" are all the list of a and b.
    std::vector<std::wstring> SplitList(const std::wstring& value);

    // The arguments the process was started with, split the way the .NET
    // runtime splits them for Main.
    std::vector<std::wstring> ProcessArgs();
}
