// The icq-e2e.ini the ICQ 6.5 and 7.2 patches write next to the client for
// the E2E add-on (tools\icq-e2e), and how they read it back.
//
// The add-on reads `key = value` lines, `#` and `;` comments, keys without
// case, the first non-empty value of a key (tools\icq-e2e\core\src\config.rs).
// The patch owns five of them and leaves every other line as it is - tls_pin,
// calls_log, a comment, anything the user added - so applying again never
// loses what was set by hand:
//
//   directory     = the key directory of the domain
//   server        = the domain: its connections go over TLS 1.3
//   e2e           = on | off - the row "End-to-end encryption of messages"
//   tls           = on | off - the row "Encrypted connection to the server (TLS)"
//   calls_encrypt = on | off - the row "End-to-end encryption of calls"
//
// A file from before these rows has no e2e= line, which the add-on reads as
// on: such an install had both, and shows both rows applied. calls_encrypt=
// is read the other way round: off unless it clearly says on (the add-on's
// default, tools\icq-e2e\README.md, "Call encryption"), and it only works with
// e2e= on, so the patch writes it on only when both rows are ticked.

using System;
using System.Collections.Generic;
using System.Linq;

namespace IcqRevival.Patch
{
    internal static class E2eIni
    {
        public const string FileName = "icq-e2e.ini";

        // The job keys of the two rows, and the key of the single row that came
        // before them, which -Skip, -Include and the saved selection still take
        // for both.
        public const string E2eJob = "e2e";
        public const string TlsJob = "e2e-tls";
        public const string CallsJob = "e2e-calls";
        public const string OldJob = "e2e-probe";

        public const string E2eRow = "end-to-end encryption of messages";
        public const string TlsRow = "encrypted connection to the server (TLS)";
        public const string CallsRow = "end-to-end encryption of calls (voice and video; needs the row above)";

        // The rows that need our DLL: unavailable together without it.
        public static readonly string[] Jobs = { E2eJob, TlsJob, CallsJob };

        // The lines the patch owns, in the order a new file has them.
        static readonly string[] Owned = { "directory", "server", "e2e", "tls", "calls_encrypt" };

        static readonly string[] OnWords = { "on", "1", "true", "yes" };
        static readonly string[] OffWords = { "off", "0", "false", "no" };

        // The key of a `key = value` line, or null for a comment, a blank line
        // or a line without "=".
        static string KeyOf(string line)
        {
            string t = line.Trim();
            if (t.Length == 0 || t.StartsWith("#") || t.StartsWith(";")) return null;
            int eq = t.IndexOf('=');
            return eq < 0 ? null : t.Substring(0, eq).Trim();
        }

        static List<string> Lines(string text)
        {
            if (string.IsNullOrEmpty(text)) return new List<string>();
            List<string> lines = text.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
            // The line break after the last line is not a line of its own.
            if (lines.Count > 0 && lines[lines.Count - 1].Length == 0) lines.RemoveAt(lines.Count - 1);
            return lines;
        }

        // What the add-on reads for key: the first non-empty value, or null.
        public static string Value(string text, string key)
        {
            foreach (string line in Lines(text))
            {
                string k = KeyOf(line);
                if (k == null || !k.Equals(key, StringComparison.OrdinalIgnoreCase)) continue;
                string v = line.Substring(line.IndexOf('=') + 1).Trim().Trim('"');
                if (v.Length > 0) return v;
            }
            return null;
        }

        // e2e= as the add-on reads it: only a clear "off" turns it off.
        public static bool E2eOn(string text)
        {
            string v = Value(text, "e2e");
            return v == null || !OffWords.Any(w => w.Equals(v, StringComparison.OrdinalIgnoreCase));
        }

        // tls= as the add-on reads it: none, or a clear "on". Anything else is
        // off or refused, and neither is the row applied.
        public static bool TlsOn(string text)
        {
            string v = Value(text, "tls");
            return v == null || OnWords.Any(w => w.Equals(v, StringComparison.OrdinalIgnoreCase));
        }

        // calls_encrypt= as the add-on reads it: off unless it clearly says on,
        // and in effect only with e2e= on (config.rs, callneg.rs).
        public static bool CallsOn(string text)
        {
            string v = Value(text, "calls_encrypt");
            return v != null && OnWords.Any(w => w.Equals(v, StringComparison.OrdinalIgnoreCase)) && E2eOn(text);
        }

        // Whether the lines the patch owns say what they would for this domain;
        // e2e=, tls= and calls_encrypt= are the rows' own business.
        public static bool Points(string text, string directory, string domain)
        {
            return Ps.Ceq(Value(text, "directory"), directory) && Ps.Eq(Value(text, "server"), domain);
        }

        // The file as it is written: header first, every line of current that
        // is not one of the patch's own kept where it was, the patch's own given
        // the values asked for in place - once - and the missing ones added at
        // the end. ASCII, CRLF, as config.rs reads it.
        public static string Compose(string header, string current, string directory, string domain, bool e2e, bool tls, bool calls)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "directory", directory },
                { "server", domain },
                { "e2e", e2e ? "on" : "off" },
                { "tls", tls ? "on" : "off" },
                // Calls are encrypted inside the E2E session: without it the
                // add-on would only say calls_encrypt=on but inactive.
                { "calls_encrypt", calls && e2e ? "on" : "off" },
            };
            List<string> lines = Lines(current);
            if (lines.Count > 0 && lines[0] == header) lines.RemoveAt(0);
            var written = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<string> { header };
            foreach (string line in lines)
            {
                string k = KeyOf(line);
                string own = k == null ? null : Owned.FirstOrDefault(o => o.Equals(k, StringComparison.OrdinalIgnoreCase));
                if (own == null) { result.Add(line); continue; }
                if (written.Add(own)) result.Add(own + " = " + values[own]);
            }
            foreach (string own in Owned)
            {
                if (written.Add(own)) result.Add(own + " = " + values[own]);
            }
            return string.Join("\r\n", result) + "\r\n";
        }

        // The ports the patch points the client's own sign-in at when the TLS
        // row is ticked: the TLS port itself for OSCAR, and for the ICQ 7.2 web
        // sign-in a port the server never listens on. Without the add-on
        // nothing there speaks the client's plain protocol, so a client whose
        // add-on is missing cannot sign in at all, instead of signing in
        // unencrypted (fail closed; docs\e2e\STAGE-TLS.md, 3.5). The add-on
        // maps both to the TLS port (tools\icq-e2e\core\src\route.rs).
        public const int TlsPort = 5194;
        public const int TlsOnlyWebPort = 5195;

        // What the window says after Apply about the E2E rows, or "" with none
        // ticked. signInPorts names the ports the client's sign-in now goes to
        // when the TLS row moved them (the sign-in row is ticked too), or is
        // null; addOnFile is the add-on's file name in the ICQ folder.
        public static string Summary(string server, bool e2e, bool tls, bool calls, string signInPorts = null, string addOnFile = null)
        {
            if (!e2e && !tls)
            {
                return calls ? "End-to-end encryption of calls needs end-to-end encryption of messages, which is not ticked: calls go as they are." : "";
            }
            var s = new List<string>();
            if (e2e) s.Add("End-to-end encryption is in place: the text of a message is encrypted to the recipient's device with keys from " + server + ", and only that device can read it. A contact without the add-on still gets the message in clear, and the add-on says so once per sign-on. Whether a chat is encrypted is said in the chat; type /e2e status there to ask.");
            else s.Add("Messages are not end-to-end encrypted: they go as they are typed, and the key directory is never asked. A /e2e command typed in a chat is answered there and never sent.");
            if (tls) s.Add("Every connection the client makes to " + server + " goes over TLS 1.3 (port " + TlsPort + ", which the server must have open); if it cannot be secured, the client is not let through in plaintext and the add-on says why.");
            if (tls && signInPorts != null) s.Add("The client's own sign-in settings now point at " + signInPorts + ", which only the add-on can reach: while this row is ticked, a client without the add-on (" + (addOnFile ?? "its DLL") + " missing or renamed) cannot sign in at all instead of signing in unencrypted. Untick the row and apply to sign in without TLS.");
            else s.Add("The connection to " + server + " is not encrypted, and the chat says so at every sign-on.");
            if (calls && e2e) s.Add("Voice and video calls are encrypted end to end when the other side has the add-on with this row ticked too; any other call goes as it is and is never blocked. The call's chat says whether it was encrypted.");
            else if (calls) s.Add("End-to-end encryption of calls needs end-to-end encryption of messages, which is not ticked: calls go as they are.");
            else s.Add("Calls are not encrypted end to end: they go as they are.");
            s.Add(FileName + " in the ICQ folder holds these settings (e2e =, tls = and calls_encrypt =); lines added to it by hand are kept. Set ICQE2E_LOG to a file path before starting ICQ to log what the add-on does.");
            return string.Join(" ", s);
        }

        // The rows' keys with the single row of before expanded into them: what
        // -Skip and -Include are given, as the run reads it.
        public static string[] Expand(IEnumerable<string> keys)
        {
            var result = new List<string>();
            foreach (string k in keys ?? new string[0])
            {
                if (Ps.Eq(k, OldJob)) { result.Add(E2eJob); result.Add(TlsJob); }
                else result.Add(k);
            }
            return result.ToArray();
        }
    }
}
