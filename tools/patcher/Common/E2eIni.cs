// The icq-e2e.ini the ICQ 6.5 and 7.2 patches write next to the client for
// the E2E add-on (tools\icq-e2e), and how they read it back.
//
// The add-on reads `key = value` lines, `#` and `;` comments, keys without
// case, the first non-empty value of a key (tools\icq-e2e\core\src\config.rs).
// The patch owns seven of them and leaves every other line as it is -
// tls_pin, calls_log, files_log, a comment, anything the user added - so
// applying again never loses what was set by hand:
//
//   directory     = the key directory of the domain
//   server        = the domain: its connections go over TLS 1.3
//   e2e           = on | off - the row "End-to-end encryption of messages"
//   tls           = on | off - the row "Encrypted connection to the server (TLS)"
//   calls_encrypt = on | off - the row "End-to-end encryption of calls"
//                   (a hand-set "required" - calls that are not encrypted
//                   are not let through - counts as on and is kept)
//   files_encrypt = on | off - the row "End-to-end encryption of file transfers"
//   auditors      = the key log's auditors, pinned (with the messages row)
//
// auditors= is what the server names on GET /e2e/v1/log/auditors at Apply
// time, fetched over HTTPS and checked against the certificate chain like any
// web request - the patch takes only the domain from the user. With it, the
// add-on trusts exactly those auditors instead of the ones the server names
// on first use (docs\e2e\KEY-TRANSPARENCY.md). Applying again only ever adds
// keys: one the server stops naming stays pinned, and the summary says so. If
// the server cannot be asked, the line is left as it was - absent, the add-on
// trusts on first use as before.
//
// A file from before these rows has no e2e= line, which the add-on reads as
// on: such an install had both, and shows both rows applied. calls_encrypt=
// and files_encrypt= are read the other way round: off unless they clearly
// say on (the add-on's defaults, tools\icq-e2e\README.md, "Call encryption"
// and "File encryption"), and they only work with e2e= on, so the patch
// writes each on only when its row and the messages row are both ticked.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

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
        public const string FilesJob = "e2e-files";
        public const string OldJob = "e2e-probe";

        public const string E2eRow = "end-to-end encryption of messages";
        public const string TlsRow = "encrypted connection to the server (TLS)";
        public const string CallsRow = "end-to-end encryption of calls (voice and video; needs the row above)";
        public const string FilesRow = "end-to-end encryption of file transfers (needs the messages row)";

        // The rows that need our DLL: unavailable together without it.
        public static readonly string[] Jobs = { E2eJob, TlsJob, CallsJob, FilesJob };

        // The lines the patch owns, in the order a new file has them.
        static readonly string[] Owned = { "directory", "server", "e2e", "tls", "calls_encrypt", "files_encrypt", "auditors" };

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
            return v != null && (OnWords.Any(w => w.Equals(v, StringComparison.OrdinalIgnoreCase)) || CallsRequired(text)) && E2eOn(text);
        }

        // calls_encrypt=required: the strict level set by hand, which the
        // calls row keeps rather than turning it back into on.
        public static bool CallsRequired(string text)
        {
            string v = Value(text, "calls_encrypt");
            return v != null && v.Equals("required", StringComparison.OrdinalIgnoreCase);
        }

        // files_encrypt= as the add-on reads it: off unless it clearly says on,
        // and in effect only with e2e= on, as calls_encrypt=.
        public static bool FilesOn(string text)
        {
            string v = Value(text, "files_encrypt");
            return v != null && OnWords.Any(w => w.Equals(v, StringComparison.OrdinalIgnoreCase)) && E2eOn(text);
        }

        // Whether the lines the patch owns say what they would for this domain;
        // e2e=, tls=, calls_encrypt= and files_encrypt= are the rows' own business.
        public static bool Points(string text, string directory, string domain)
        {
            return Ps.Ceq(Value(text, "directory"), directory) && Ps.Eq(Value(text, "server"), domain);
        }

        // The file as it is written: header first, every line of current that
        // is not one of the patch's own kept where it was, the patch's own given
        // the values asked for in place - once - and the missing ones added at
        // the end. ASCII, CRLF, as config.rs reads it. auditors is the value of
        // the auditors= line (PinAuditors), or null for no such line.
        public static string Compose(string header, string current, string directory, string domain, bool e2e, bool tls, bool calls, bool files, string auditors)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "directory", directory },
                { "server", domain },
                { "e2e", e2e ? "on" : "off" },
                { "tls", tls ? "on" : "off" },
                // Calls are encrypted inside the E2E session: without it the
                // add-on would only say calls_encrypt=on but inactive.
                { "calls_encrypt", calls && e2e ? (CallsRequired(current) ? "required" : "on") : "off" },
                // File transfers likewise: their keys come from the E2E session.
                { "files_encrypt", files && e2e ? "on" : "off" },
                { "auditors", auditors },
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
                if (written.Add(own) && values[own] != null) result.Add(own + " = " + values[own]);
            }
            foreach (string own in Owned)
            {
                if (written.Add(own) && values[own] != null) result.Add(own + " = " + values[own]);
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

        const string FilesNeedE2e = "End-to-end encryption of file transfers needs end-to-end encryption of messages, which is not ticked: file transfers go as they are.";

        // What the window says after Apply about the E2E rows, or "" with none
        // ticked. signInPorts names the ports the client's sign-in now goes to
        // when the TLS row moved them (the sign-in row is ticked too), or is
        // null; addOnFile is the add-on's file name in the ICQ folder.
        public static string Summary(string server, bool e2e, bool tls, bool calls, bool files, string signInPorts = null, string addOnFile = null, string auditorsNote = null)
        {
            if (!e2e && !tls)
            {
                var only = new List<string>();
                if (calls) only.Add("End-to-end encryption of calls needs end-to-end encryption of messages, which is not ticked: calls go as they are.");
                if (files) only.Add(FilesNeedE2e);
                return string.Join(" ", only);
            }
            var s = new List<string>();
            if (e2e) s.Add("End-to-end encryption is in place: the text of a message is encrypted to the recipient's device with keys from " + server + ", and only that device can read it. A contact without the add-on still gets the message in clear, and the add-on says so once per sign-on. Whether a chat is encrypted is said in the chat; type /e2e status there to ask.");
            else s.Add("Messages are not end-to-end encrypted: they go as they are typed, and the key directory is never asked. A /e2e command typed in a chat is answered there and never sent.");
            if (tls) s.Add("Every connection the client makes to " + server + " goes over TLS 1.3 (port " + TlsPort + ", which the server must have open); if it cannot be secured, the client is not let through in plaintext and the add-on says why.");
            if (tls && signInPorts != null) s.Add("The client's own sign-in settings now point at " + signInPorts + ", which only the add-on can reach: while this row is ticked, a client without the add-on (" + (addOnFile ?? "its DLL") + " missing or renamed) cannot sign in at all instead of signing in unencrypted. Untick the row and apply to sign in without TLS.");
            else if (!tls) s.Add("The connection to " + server + " is not encrypted, and the chat says so at every sign-on.");
            if (calls && e2e) s.Add("Voice and video calls are encrypted end to end when the other side has the add-on with this row ticked too; any other call goes as it is and is never blocked. The call's chat says whether it was encrypted.");
            else if (calls) s.Add("End-to-end encryption of calls needs end-to-end encryption of messages, which is not ticked: calls go as they are.");
            else s.Add("Calls are not encrypted end to end: they go as they are.");
            if (files && e2e) s.Add("File transfers are encrypted end to end when the other side has the add-on with this row ticked too; any other transfer goes as it is and is never blocked. The chat says whether a transfer was encrypted.");
            else if (files) s.Add(FilesNeedE2e);
            else s.Add("File transfers are not encrypted end to end: they go as they are.");
            s.Add(FileName + " in the ICQ folder holds these settings (e2e =, tls =, calls_encrypt =, files_encrypt = and auditors =); lines added to it by hand are kept. Set ICQE2E_LOG to a file path before starting ICQ to log what the add-on does.");
            string text = string.Join(" ", s);
            if (!string.IsNullOrEmpty(auditorsNote)) text += "\n\n" + auditorsNote;
            return text;
        }

        // --- the key log's auditors ------------------------------------------

        // Whether text is an auditor's verifier key as e2e-kt-auditor
        // -print-key prints it: name+<key ID, 8 hex>+base64(0x04 || Ed25519
        // key), the key ID being the first four bytes of SHA-256(name || "\n"
        // || 0x04 || key) (c2sp.org/tlog-cosignature; tools\icq-e2e\core\src\kt.rs).
        public static bool IsAuditorKey(string text)
        {
            string[] parts = (text ?? "").Trim().Split(new[] { '+' }, 3);
            if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length != 8) return false;
            uint id;
            if (!uint.TryParse(parts[1], System.Globalization.NumberStyles.AllowHexSpecifier, null, out id)) return false;
            byte[] key;
            try { key = Convert.FromBase64String(parts[2]); }
            catch (FormatException) { return false; }
            if (key.Length != 33 || key[0] != 4) return false;
            byte[] name = Encoding.UTF8.GetBytes(parts[0] + "\n");
            byte[] all = new byte[name.Length + key.Length];
            Buffer.BlockCopy(name, 0, all, 0, name.Length);
            Buffer.BlockCopy(key, 0, all, name.Length, key.Length);
            byte[] h;
            using (var sha = SHA256.Create()) h = sha.ComputeHash(all);
            return ((uint)h[0] << 24 | (uint)h[1] << 16 | (uint)h[2] << 8 | h[3]) == id;
        }

        // The auditors' keys in a list - one per line from the server, commas
        // on the auditors= line - those that read, each once.
        public static string[] AuditorKeys(string text)
        {
            return (text ?? "").Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(k => k.Trim()).Where(IsAuditorKey).Distinct(StringComparer.Ordinal).ToArray();
        }

        // An auditor's name: the part of its key before the first plus sign.
        static string AuditorName(string key) { return key.Split('+')[0]; }

        // The auditors the server at directory names, or null when it could not
        // be asked (error says why). Over HTTPS, the certificate checked by
        // .NET against the Windows trust store as for any web request. A
        // server without a key log answers 404: it names none.
        public static string[] FetchAuditors(string directory, out string error)
        {
            error = null;
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
                var req = (HttpWebRequest)WebRequest.Create(directory + "log/auditors");
                req.Timeout = 15000;
                req.ReadWriteTimeout = 15000;
                req.UserAgent = "ICQ-Revival-Patch";
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                {
                    return AuditorKeys(r.ReadToEnd());
                }
            }
            catch (WebException e) when ((e.Response as HttpWebResponse)?.StatusCode == HttpStatusCode.NotFound)
            {
                return new string[0];
            }
            catch (Exception e) when (e is WebException || e is IOException || e is NotSupportedException || e is UriFormatException)
            {
                error = e.Message;
                return null;
            }
        }

        // What the auditors= line becomes, and what the summary says of it.
        public sealed class AuditorPins
        {
            // The line's value, or null for no line (trust on first use).
            public string Line;
            public string Note;
        }

        // The auditors= line for domain, from the file as it is (current) and
        // what the server named just now (fetched; null when it could not be
        // asked, error saying why). Keys pinned before for the same server are
        // never dropped: the set only grows, and a key the server no longer
        // names is kept and reported. A line for another server is not kept.
        public static AuditorPins PinAuditors(string current, string domain, string[] fetched, string error)
        {
            bool sameServer = current != null && Ps.Eq(Value(current, "server"), domain);
            string[] pinned = sameServer ? AuditorKeys(Value(current, "auditors")) : new string[0];
            var r = new AuditorPins();
            Func<IEnumerable<string>, string> names = ks => string.Join(", ", ks.Select(AuditorName));
            Func<IEnumerable<string>, string> list = ks => string.Join("", ks.Select(k => "\n  " + k));
            if (fetched == null)
            {
                if (pinned.Length > 0)
                {
                    r.Line = string.Join(",", pinned);
                    r.Note = "The key log's auditors could not be asked for at " + domain + " (" + error + "): the " + pinned.Length + " pinned before stay (" + names(pinned) + ").";
                }
                else
                {
                    r.Note = "The key log's auditors could not be asked for at " + domain + " (" + error + "): none pinned, so the add-on trusts the ones the server names when it first sees them. Apply again to pin them.";
                }
                return r;
            }
            string[] added = fetched.Where(k => !pinned.Contains(k)).ToArray();
            string[] gone = pinned.Where(k => !fetched.Contains(k)).ToArray();
            string[] all = pinned.Concat(added).ToArray();
            if (all.Length == 0)
            {
                r.Note = domain + " names no auditor for its key log: none pinned, so the add-on trusts the ones the server names when it first sees them.";
                return r;
            }
            r.Line = string.Join(",", all);
            var s = new List<string>();
            if (pinned.Length == 0) s.Add("The key log's auditors are pinned from " + domain + "; the add-on trusts these and no others:" + list(all));
            else if (added.Length == 0 && gone.Length == 0) s.Add("The key log's auditors pinned are unchanged (" + names(all) + ").");
            else
            {
                if (added.Length > 0) s.Add("Auditors added to the pinned ones:" + list(added));
                if (gone.Length > 0) s.Add(domain + " no longer names " + names(gone) + "; kept pinned all the same. Delete the auditors line of " + FileName + " and apply again to take only the server's.");
            }
            r.Note = string.Join("\n", s);
            return r;
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
