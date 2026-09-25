// The Ukrainian interface the patch carries: a recipe of what to change in the
// client's menus, dialogs and string tables, the texts that live in a
// program's data or in the skin, the text files written whole, and where the
// "Send By:" words sit.
//
// The recipe is ..\..\icq2003b\patch\ICQ-2003b-uk-UA.json, written by the
// translation tools (translate\build.py) from the translator's uk-UA.json. It
// is embedded in the exe as it is - readable UTF-8 text, no packed or binary
// payload. The patch rebuilds each translated resource itself, from the
// client's own English resource, following the recipe (ResourceCodec), so a
// resource comes out exactly as before.
//
// A resource is only translated when the client's original matches the one the
// recipe was built from: each record carries the SHA-256 of that original.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IcqRevival.Patch
{
    // One resource to translate: its key and the SHA-256 of the English
    // original, and the change - replaced strings, menu items or the dialog's
    // caption, control captions and control widths, by index.
    internal sealed class ResRecipe
    {
        public int Type;
        public string Key;   // "type|name|lang", a numeric name written "#123"
        public string From;
        public Dictionary<int, string> Strings;
        public Dictionary<int, string> Items;
        public string Caption;
        public Dictionary<int, string> Controls;
        public Dictionary<int, int> Widths;

        // The translated resource, built from the English original's bytes.
        public byte[] Build(byte[] original)
        {
            switch (Type)
            {
                case ResourceCodec.RtString: return ResourceCodec.TranslateStrings(original, Strings ?? Empty);
                case ResourceCodec.RtMenu: return ResourceCodec.TranslateMenu(original, Items ?? Empty);
                default: return ResourceCodec.TranslateDialog(original, Caption, Controls, Widths);
            }
        }

        static readonly Dictionary<int, string> Empty = new Dictionary<int, string>();
    }

    // A text in a program's data or in the skin, written over the English one:
    // the bytes to write, and the original bytes, for telling the state.
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
        public List<ResRecipe> Resources = new List<ResRecipe>();
        public List<TrPlace> Inplace = new List<TrPlace>();
        // A text file written whole (a datafile), and the SHA-256 of the English one.
        public byte[] Whole;
        public string WholeFrom;
    }

    // Where the "Send By:" words live, and how to blank them.
    internal sealed class TrSendBy
    {
        public string File;
        public string Key;
        public string From;
        public int Index;
        public string Blank;
    }

    // What one file's resources come to on a given client: the translated bytes
    // by key, and the send-by table blanked in either language (for Icq.exe).
    internal sealed class MatFile
    {
        public readonly List<KeyValuePair<string, byte[]>> Items = new List<KeyValuePair<string, byte[]>>();
        public readonly Dictionary<string, string> KeyFrom = new Dictionary<string, string>(StringComparer.Ordinal);
        public byte[] BlankEn;
        public byte[] BlankUk;

        public byte[] ByKey(string key)
        {
            foreach (KeyValuePair<string, byte[]> it in Items) { if (Ps.Eq(it.Key, key)) return it.Value; }
            return null;
        }
    }

    internal sealed class Translation
    {
        static readonly Encoding Cp1251 = Encoding.GetEncoding(1251);
        static readonly Encoding Cp1252 = Encoding.GetEncoding(1252);

        public readonly List<TrFile> Files = new List<TrFile>();
        public TrSendBy SendBy;

        public TrFile File(string rel)
        {
            if (rel == null) return null;
            foreach (TrFile f in Files)
            {
                if (string.Equals(f.Rel, rel, StringComparison.OrdinalIgnoreCase)) return f;
            }
            return null;
        }

        static Translation loaded;

        public static Translation Get()
        {
            if (loaded == null) loaded = Parse(Resource("ICQ-2003b-uk-UA.json"));
            return loaded;
        }

        static string Resource(string name)
        {
            using (Stream s = typeof(Translation).Assembly.GetManifestResourceStream(name))
            {
                if (s == null) throw new InvalidOperationException("The translation is missing from the exe: " + name);
                using (var r = new StreamReader(s, Encoding.UTF8)) return r.ReadToEnd();
            }
        }

        // Everything one file's resources come to on this client, built from the
        // English original's bytes.
        public MatFile Materialize(TrFile file, byte[] originalFileBytes)
        {
            var mat = new MatFile();
            foreach (ResRecipe r in file.Resources)
            {
                byte[] orig = IcqResources.Read(originalFileBytes, new[] { r.Key })[0];
                if (orig == null) continue;
                byte[] built = r.Build(orig);
                mat.Items.Add(new KeyValuePair<string, byte[]>(r.Key, built));
                if (!mat.KeyFrom.ContainsKey(r.Key)) mat.KeyFrom[r.Key] = r.From;
            }
            if (SendBy != null && Ps.Eq(file.Rel, SendBy.File))
            {
                byte[] sbOrig = IcqResources.Read(originalFileBytes, new[] { SendBy.Key })[0];
                if (sbOrig != null)
                {
                    string[] orig = ResourceCodec.ReadStrings(sbOrig);
                    var translated = (string[])orig.Clone();
                    ResRecipe table = file.Resources.FirstOrDefault(x => Ps.Eq(x.Key, SendBy.Key));
                    if (table != null && table.Strings != null)
                    {
                        foreach (KeyValuePair<int, string> kv in table.Strings) translated[kv.Key] = kv.Value;
                    }
                    var blankEn = (string[])orig.Clone();
                    var blankUk = (string[])translated.Clone();
                    blankEn[SendBy.Index] = blankUk[SendBy.Index] = SendBy.Blank;
                    mat.BlankEn = ResourceCodec.WriteStrings(blankEn);
                    mat.BlankUk = ResourceCodec.WriteStrings(blankUk);
                }
            }
            return mat;
        }

        static Translation Parse(string text)
        {
            var doc = (JsonObject)Json.Parse(text);
            var t = new Translation();
            var sb = doc["sendBy"] as JsonObject;
            if (sb != null)
            {
                t.SendBy = new TrSendBy
                {
                    File = (string)sb["file"],
                    Key = KeyOf(sb["type"], sb["name"], sb["lang"]),
                    From = (string)sb["from"],
                    Index = (int)AsLong(sb["index"]),
                    Blank = (string)sb["blank"],
                };
            }
            var files = doc["files"] as JsonObject;
            if (files != null)
            {
                foreach (KeyValuePair<string, object> f in files.Pairs)
                {
                    var v = (JsonObject)f.Value;
                    var file = new TrFile { Rel = f.Key, Size = AsLong(v["size"]) };
                    foreach (object o in Json.List(v["resources"]))
                    {
                        var ro = (JsonObject)o;
                        var r = new ResRecipe
                        {
                            Type = (int)AsLong(ro["type"]),
                            Key = KeyOf(ro["type"], ro["name"], ro["lang"]),
                            From = (string)ro["from"],
                            Strings = MapStr(ro["strings"]),
                            Items = MapStr(ro["items"]),
                            Caption = ro["caption"] as string,
                            Controls = MapStr(ro["controls"]),
                            Widths = MapInt(ro["widths"]),
                        };
                        file.Resources.Add(r);
                    }
                    foreach (object o in Json.List(v["inplace"]))
                    {
                        var p = (JsonObject)o;
                        string encoding = (string)p["encoding"];
                        int slot = (int)AsLong(p["slot"]);
                        Encoding enc = encoding == "ansi" ? Cp1251 : Encoding.Unicode;
                        Encoding encEn = encoding == "ansi" ? Cp1252 : Encoding.Unicode;
                        file.Inplace.Add(new TrPlace
                        {
                            Offset = (int)AsLong(p["offset"]),
                            Bytes = Pad(enc.GetBytes((string)p["uk"]), slot),
                            Original = Pad(encEn.GetBytes((string)p["en"]), slot),
                        });
                    }
                    var whole = v["whole"] as JsonObject;
                    if (whole != null)
                    {
                        file.Whole = Cp1251.GetBytes((string)whole["text"]);
                        file.WholeFrom = (string)whole["from"];
                    }
                    t.Files.Add(file);
                }
            }
            return t;
        }

        static byte[] Pad(byte[] b, int slot)
        {
            if (b.Length >= slot) return b;
            var r = new byte[slot];
            Buffer.BlockCopy(b, 0, r, 0, b.Length);
            return r;
        }

        // "type|name|lang"; a numeric name is written "#123", as the resource
        // reader expects.
        static string KeyOf(object type, object name, object lang)
        {
            string n = name is string ? (string)name : "#" + AsLong(name).ToString(CultureInfo.InvariantCulture);
            return AsLong(type).ToString(CultureInfo.InvariantCulture) + "|" + n + "|" + AsLong(lang).ToString(CultureInfo.InvariantCulture);
        }

        static long AsLong(object v) { return Convert.ToInt64(v, CultureInfo.InvariantCulture); }

        static Dictionary<int, string> MapStr(object v)
        {
            var o = v as JsonObject;
            if (o == null) return null;
            var m = new Dictionary<int, string>();
            foreach (KeyValuePair<string, object> kv in o.Pairs) m[int.Parse(kv.Key, CultureInfo.InvariantCulture)] = (string)kv.Value;
            return m;
        }

        static Dictionary<int, int> MapInt(object v)
        {
            var o = v as JsonObject;
            if (o == null) return null;
            var m = new Dictionary<int, int>();
            foreach (KeyValuePair<string, object> kv in o.Pairs) m[int.Parse(kv.Key, CultureInfo.InvariantCulture)] = (int)AsLong(kv.Value);
            return m;
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

    // A JSON object that keeps the order of its members and finds them ignoring
    // case, as PowerShell's ConvertFrom-Json does. Arrays are List<object>,
    // numbers long or double, null is null.
    internal sealed class JsonObject
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
    }

    internal static class Json
    {
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
                var o = new JsonObject();
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
            if (string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            if (string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
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
