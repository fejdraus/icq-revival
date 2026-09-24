// The command line of a client patch, read the way PowerShell read the
// parameters of the scripts the patches were first written as, and the
// console a scripted run reports to.
//
//   -Apply -Root C:\ICQ -Server icq.example.org -Skip xtraz,ads
//
// Names ignore case and may be cut short while they stay unambiguous (-Ro,
// -Se); a value follows its name or is joined to it with a colon (-Root:C:\x);
// a switch takes :$true or :$false; values without a name fill the named
// parameters that take one, in their order (Root, Server, Skip). A name the
// patch does not know is passed over together with the value after it. A list
// is separated by commas, as PowerShell writes one: -Skip xtraz,ads.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace IcqRevival.Patch
{
    internal enum CliKind { Switch, Text, List }

    internal sealed class CliParam
    {
        public readonly string Name;
        public readonly CliKind Kind;
        public CliParam(string name, CliKind kind) { Name = name; Kind = kind; }
    }

    internal sealed class CliException : Exception
    {
        public CliException(string message) : base(message) { }
    }

    internal sealed class CliArgs
    {
        readonly Dictionary<string, object> values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        internal void Set(string name, object value) { values[name] = value; }
        internal bool Has(string name) { return values.ContainsKey(name); }

        public bool Switch(string name)
        {
            object v;
            return values.TryGetValue(name, out v) && (bool)v;
        }

        // A text value; null when not given.
        public string Text(string name)
        {
            object v;
            return values.TryGetValue(name, out v) ? (string)v : null;
        }

        // A list value; empty when not given.
        public string[] List(string name)
        {
            object v;
            return values.TryGetValue(name, out v) ? (string[])v : new string[0];
        }
    }

    internal static class PatchCli
    {
        public static CliArgs Parse(string[] args, params CliParam[] spec)
        {
            var result = new CliArgs();
            var loose = new List<string>();
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (!a.StartsWith("-"))
                {
                    loose.Add(a);
                    continue;
                }
                string name = a.TrimStart('-');
                string joined = null;
                int colon = name.IndexOf(':');
                if (colon >= 0)
                {
                    joined = name.Substring(colon + 1);
                    name = name.Substring(0, colon);
                }
                CliParam p = Resolve(name, spec);
                if (p == null)
                {
                    // Not one of ours: passed over, with its value.
                    if (joined == null && i + 1 < args.Length && !args[i + 1].StartsWith("-")) i++;
                    continue;
                }
                if (result.Has(p.Name))
                {
                    throw new CliException("Cannot bind parameter because parameter '" + p.Name + "' is specified more than once. " +
                        "To pass several values to a parameter that takes a list, separate them with commas: -" + p.Name + " value1,value2");
                }
                if (p.Kind == CliKind.Switch)
                {
                    bool on = true;
                    if (joined != null)
                    {
                        string v = joined.TrimStart('$');
                        if (v.Equals("true", StringComparison.OrdinalIgnoreCase)) on = true;
                        else if (v.Equals("false", StringComparison.OrdinalIgnoreCase)) on = false;
                        else throw new CliException("Cannot convert '" + joined + "' for the switch -" + p.Name + ": use $true or $false.");
                    }
                    result.Set(p.Name, on);
                    continue;
                }
                string value = joined;
                if (value == null)
                {
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("-"))
                    {
                        throw new CliException("Missing an argument for parameter '" + p.Name + "'. Specify a parameter of type " +
                            (p.Kind == CliKind.List ? "'System.String[]'" : "'System.String'") + " and try again.");
                    }
                    value = args[++i];
                }
                Bind(result, p, value);
            }
            // What came without a name fills the parameters that take a value,
            // in their order, once the named ones are bound.
            int next = 0;
            foreach (string value in loose)
            {
                while (next < spec.Length && (spec[next].Kind == CliKind.Switch || result.Has(spec[next].Name))) next++;
                if (next >= spec.Length) break;
                Bind(result, spec[next], value);
            }
            return result;
        }

        static void Bind(CliArgs result, CliParam p, string value)
        {
            if (p.Kind == CliKind.List) result.Set(p.Name, SplitList(value));
            else result.Set(p.Name, value);
        }

        // "a,b", "'a','b'" and "@('a','b')" are all the list of a and b.
        public static string[] SplitList(string value)
        {
            string v = value.Trim();
            if (v.StartsWith("@(") && v.EndsWith(")")) v = v.Substring(2, v.Length - 3);
            return v.Split(',')
                .Select(s => s.Trim())
                .Select(s => s.Length >= 2 && (s[0] == '\'' || s[0] == '"') && s[s.Length - 1] == s[0] ? s.Substring(1, s.Length - 2) : s)
                .Where(s => s.Length > 0)
                .ToArray();
        }

        static CliParam Resolve(string name, CliParam[] spec)
        {
            CliParam exact = spec.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (exact != null) return exact;
            CliParam[] prefix = spec.Where(p => p.Name.StartsWith(name, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (prefix.Length == 1) return prefix[0];
            if (prefix.Length > 1)
            {
                throw new CliException("Parameter cannot be processed because the parameter name '" + name + "' is ambiguous. Possible matches include: " +
                    string.Join(" ", prefix.Select(p => "-" + p.Name)) + ".");
            }
            return null;
        }
    }

    // Where a scripted run writes. The exe is a windowed program, which starts
    // without a console: output redirected to a file or a pipe is written there
    // as it is, and otherwise the run joins the console of whoever started it,
    // so "applied: ..." lines show in the command prompt too.
    internal static class PatchConsole
    {
        const int StdOutput = -11, StdError = -12, AttachParent = -1;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AttachConsole(int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int which);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetStdHandle(int which, IntPtr handle);

        [DllImport("kernel32.dll")]
        static extern int GetFileType(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

        static bool Usable(IntPtr h)
        {
            return h != IntPtr.Zero && h != new IntPtr(-1) && GetFileType(h) != 0;
        }

        public static void Attach()
        {
            bool outOk = Usable(GetStdHandle(StdOutput));
            bool errOk = Usable(GetStdHandle(StdError));
            if (!(outOk && errOk) && AttachConsole(AttachParent))
            {
                IntPtr con = IntPtr.Zero;
                if (!outOk && !Usable(GetStdHandle(StdOutput))) SetStdHandle(StdOutput, con = OpenConsoleOutput());
                if (!errOk && !Usable(GetStdHandle(StdError))) SetStdHandle(StdError, con != IntPtr.Zero ? con : OpenConsoleOutput());
            }
            Console.SetOut(Writer(Console.OpenStandardOutput()));
            Console.SetError(Writer(Console.OpenStandardError()));
        }

        static IntPtr OpenConsoleOutput()
        {
            const uint GenericReadWrite = 0xC0000000, ShareReadWrite = 3, OpenExisting = 3;
            return CreateFile("CONOUT$", GenericReadWrite, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        }

        static TextWriter Writer(Stream stream)
        {
            return new StreamWriter(stream, Console.OutputEncoding.CodePage == 65001 ? new UTF8Encoding(false) : Console.OutputEncoding) { AutoFlush = true };
        }
    }
}
