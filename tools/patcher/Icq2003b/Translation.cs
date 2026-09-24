// The Ukrainian interface the patch carries: every translated resource of the
// client's programs, the texts that live in a program's data or in the skin,
// and the blank "Send By:" in both languages.
//
// Built by ..\..\icq2003b\translate\build.py into ICQ-2003b-uk-UA.txt (JSON,
// gzip, base64), which is compiled into the exe as it is and decoded once.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IcqRevival.Patch
{
    internal sealed class TrItem
    {
        public string Key;      // "type|name|lang"
        public byte[] Bytes;    // the translated data
        public string From;     // SHA-256 of the English data
    }

    internal sealed class TrPlace
    {
        public int Offset;
        public byte[] Bytes;
        public byte[] Original;
    }

    internal sealed class TrFile
    {
        public string Rel;
        public long Size;
        public List<TrItem> Items = new List<TrItem>();
        public List<TrPlace> Inplace = new List<TrPlace>();
        // A text file written whole, and the SHA-256 of the English one.
        public byte[] Whole;
        public string WholeFrom;
    }

    internal sealed class TrSendBy
    {
        public string File;
        public string Key;
        public string From;
        public byte[] BlankEn;
        public byte[] BlankUk;
    }

    internal sealed class Translation
    {
        public const string ResourceName = "ICQ-2003b-uk-UA.txt";

        // In the order of the file; looked up ignoring case.
        public readonly List<TrFile> Files = new List<TrFile>();
        readonly Dictionary<string, TrFile> byRel = new Dictionary<string, TrFile>(StringComparer.OrdinalIgnoreCase);
        public TrSendBy SendBy;

        public TrFile File(string rel)
        {
            TrFile f;
            return rel != null && byRel.TryGetValue(rel, out f) ? f : null;
        }

        static Translation loaded;

        public static Translation Get()
        {
            if (loaded == null) loaded = Load();
            return loaded;
        }

        // "#123" for a number, the name itself otherwise.
        static string ResName(object n)
        {
            var s = n as string;
            if (s != null) return s;
            return "#" + Convert.ToString(n, CultureInfo.InvariantCulture);
        }

        static string KeyOf(Json o)
        {
            return string.Format(CultureInfo.InvariantCulture, "{0}|{1}|{2}", o["t"], ResName(o["n"]), o["l"]);
        }

        static byte[] B64(object s) { return Convert.FromBase64String((string)s); }

        static Translation Load()
        {
            string packed;
            using (Stream s = typeof(Translation).Assembly.GetManifestResourceStream(ResourceName))
            using (var r = new StreamReader(s, Encoding.UTF8))
            {
                packed = r.ReadToEnd();
            }
            string json;
            using (var ms = new MemoryStream(Convert.FromBase64String(packed)))
            using (var gz = new GZipStream(ms, CompressionMode.Decompress))
            using (var reader = new StreamReader(gz, Encoding.UTF8))
            {
                json = reader.ReadToEnd();
            }
            var t = (Json)Json.Parse(json);
            var result = new Translation();
            foreach (KeyValuePair<string, object> f in ((Json)t["files"]).Pairs)
            {
                var v = (Json)f.Value;
                var file = new TrFile { Rel = f.Key, Size = Convert.ToInt64(v["size"], CultureInfo.InvariantCulture) };
                foreach (object o in Json.List(v["items"]))
                {
                    var it = (Json)o;
                    file.Items.Add(new TrItem { Key = KeyOf(it), Bytes = B64(it["d"]), From = (string)it["from"] });
                }
                foreach (object o in Json.List(v["inplace"]))
                {
                    var it = o as Json;
                    if (it == null) continue;
                    file.Inplace.Add(new TrPlace
                    {
                        Offset = Convert.ToInt32(it["o"], CultureInfo.InvariantCulture),
                        Bytes = B64(it["d"]),
                        Original = B64(it["from"]),
                    });
                }
                var whole = v["whole"] as Json;
                if (whole != null)
                {
                    file.Whole = B64(whole["d"]);
                    file.WholeFrom = (string)whole["from"];
                }
                result.Files.Add(file);
                if (!result.byRel.ContainsKey(file.Rel)) result.byRel.Add(file.Rel, file);
            }
            var sb = (Json)t["sendBy"];
            result.SendBy = new TrSendBy
            {
                File = (string)sb["file"],
                Key = KeyOf(sb),
                From = (string)sb["from"],
                BlankEn = B64(sb["en"]),
                BlankUk = B64(sb["uk"]),
            };
            return result;
        }

        // SHA-256 of some bytes, as lower-case hex.
        public static string Sha(byte[] bytes)
        {
            using (var sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
        }
    }

    // A JSON object that keeps the order of its members and finds them
    // ignoring case, as PowerShell's ConvertFrom-Json does. Arrays are
    // List<object>, numbers long or double, and null is null.
    internal sealed class Json
    {
        public readonly List<KeyValuePair<string, object>> Pairs = new List<KeyValuePair<string, object>>();

        public object this[string name]
        {
            get
            {
                foreach (KeyValuePair<string, object> p in Pairs)
                {
                    if (string.Equals(p.Key, name, StringComparison.OrdinalIgnoreCase)) return p.Value;
                }
                return null;
            }
        }

        // A member as a list: an array as it is, nothing as none, anything else as one.
        public static IEnumerable<object> List(object value)
        {
            if (value == null) return Enumerable.Empty<object>();
            var list = value as List<object>;
            return list ?? new List<object> { value };
        }

        public static object Parse(string text)
        {
            int i = 0;
            object v = Value(text, ref i);
            Space(text, ref i);
            if (i != text.Length) throw new FormatException("JSON: text after the value at " + i);
            return v;
        }

        static void Space(string s, ref int i)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        }

        static object Value(string s, ref int i)
        {
            Space(s, ref i);
            if (i >= s.Length) throw new FormatException("JSON: unexpected end");
            char c = s[i];
            if (c == '{')
            {
                var o = new Json();
                i++;
                Space(s, ref i);
                if (s[i] == '}') { i++; return o; }
                while (true)
                {
                    Space(s, ref i);
                    string name = Str(s, ref i);
                    Space(s, ref i);
                    if (s[i] != ':') throw new FormatException("JSON: ':' expected at " + i);
                    i++;
                    o.Pairs.Add(new KeyValuePair<string, object>(name, Value(s, ref i)));
                    Space(s, ref i);
                    if (s[i] == ',') { i++; continue; }
                    if (s[i] == '}') { i++; return o; }
                    throw new FormatException("JSON: ',' or '}' expected at " + i);
                }
            }
            if (c == '[')
            {
                var a = new List<object>();
                i++;
                Space(s, ref i);
                if (s[i] == ']') { i++; return a; }
                while (true)
                {
                    a.Add(Value(s, ref i));
                    Space(s, ref i);
                    if (s[i] == ',') { i++; continue; }
                    if (s[i] == ']') { i++; return a; }
                    throw new FormatException("JSON: ',' or ']' expected at " + i);
                }
            }
            if (c == '"') return Str(s, ref i);
            if (s.Length - i >= 4 && string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            if (s.Length - i >= 4 && string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (s.Length - i >= 5 && string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            int start = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            string num = s.Substring(start, i - start);
            if (num.Length == 0) throw new FormatException("JSON: value expected at " + start);
            long l;
            if (long.TryParse(num, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out l)) return l;
            return double.Parse(num, NumberStyles.Float, CultureInfo.InvariantCulture);
        }

        static string Str(string s, ref int i)
        {
            if (s[i] != '"') throw new FormatException("JSON: string expected at " + i);
            i++;
            var sb = new StringBuilder();
            while (true)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default: throw new FormatException("JSON: bad escape at " + (i - 1));
                }
            }
        }
    }
}
