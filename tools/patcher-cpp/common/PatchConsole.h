// Where a scripted run writes - the PatchConsole of
// tools\patcher\Common\PatchCli.cs.
//
// The exe is a windowed program, which starts without a console: output
// redirected to a file or a pipe is written there as it is, and otherwise the
// run joins the console of whoever started it, so "applied: ..." lines show
// in the command prompt too.

#pragma once

#include <string>

namespace PatchConsole
{
    // Joins the console of the parent where the output goes nowhere yet.
    void Attach();

    // Console.WriteLine and Console.Error.WriteLine: the line and CR LF, in
    // the code page of the console (UTF-8 without a mark for 65001), or of
    // Windows when there is no console.
    void OutLine(const std::wstring& line);
    void ErrorLine(const std::wstring& line);
}
