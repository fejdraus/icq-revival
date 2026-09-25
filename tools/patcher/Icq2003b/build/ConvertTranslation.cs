// A build step of the ICQ 2003b patch (see ConvertTranslation.targets): turns
// the Ukrainian interface of ICQ Pro 2003b into the two files the exe carries.
//
// ICQ-2003b-uk-UA.txt stays the source: JSON, gzip, base64, as
// tools\icq2003b\translate\build.py writes it. It is decoded here, at build
// time, so the exe holds nothing packed or encoded and decodes nothing. The
// output is the same as tools\patcher-cpp\icq2003b\Convert-Translation.ps1
// writes for the C++ build, byte for byte:
//
//   translation.idx  a UTF-8 text index, one record per line, fields split by
//                    tabs (see ..\Translation.cs for the records)
//   translation.dat  the raw bytes of every item, one after another
//
// The JSON is read the way PowerShell's ConvertFrom-Json reads it: members in
// the order of the file, a single value where a list is expected taken as a
// list of one.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class ConvertTranslation : Task
{
    [Required] public string Source { get; set; }
    [Required] public string OutDir { get; set; }

    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    MemoryStream data;
    StringBuilder index;

    public override bool Execute()
    {
        string packed = File.ReadAllText(Source, Encoding.UTF8).Trim();
        string json;
        using (var ms = new MemoryStream(Convert.FromBase64String(packed)))
        using (var gz = new GZipStream(ms, CompressionMode.Decompress))
        using (var reader = new StreamReader(gz, Encoding.UTF8))
        {
            json = reader.ReadToEnd();
        }
        var t = (Obj)Json.Parse(json);

        data = new MemoryStream();
        index = new StringBuilder();
        index.Append("# The Ukrainian interface of ICQ Pro 2003b, from ICQ-2003b-uk-UA.txt. Generated; do not edit.\n");
        Line("language", Field(t["language"]));
        foreach (KeyValuePair<string, object> f in ((Obj)t["files"]).Pairs)
        {
            var v = (Obj)f.Value;
            Line("file", Field(f.Key), Field(Convert.ToInt64(v["size"], Inv)));
            foreach (object o in ListOf(v["items"]))
            {
                var it = (Obj)o;
                Line("item", KeyOf(it), Field(it["from"]), Blob(it["d"]));
            }
            foreach (object o in ListOf(v["inplace"]))
            {
                var it = o as Obj;
                if (it == null) continue;
                Line("place", Field(Convert.ToInt32(it["o"], Inv)), Blob(it["d"]), Blob(it["from"]));
            }
            var whole = v["whole"] as Obj;
            if (whole != null) Line("whole", Field(whole["from"]), Blob(whole["d"]));
        }
        var sb = (Obj)t["sendBy"];
        Line("sendby", Field(sb["file"]), KeyOf(sb), Field(sb["from"]), Blob(sb["en"]), Blob(sb["uk"]));

        Directory.CreateDirectory(OutDir);
        File.WriteAllText(Path.Combine(OutDir, "translation.idx"), index.ToString(), new UTF8Encoding(false));
        File.WriteAllBytes(Path.Combine(OutDir, "translation.dat"), data.ToArray());
        Log.LogMessage(MessageImportance.Normal, "translation: " + index.Length + " characters of index, " + data.Length + " bytes of data");
        return true;
    }

    // A list: none as none, an array as it is, anything else as a list of one.
    static IEnumerable<object> ListOf(object value)
    {
        if (value == null) return new object[0];
        var list = value as List<object>;
        return list ?? new List<object> { value };
    }

    // Appends bytes to the data and gives "offset<TAB>length".
    string Blob(object base64)
    {
        byte[] bytes = Convert.FromBase64String((string)base64);
        long at = data.Position;
        data.Write(bytes, 0, bytes.Length);
        return at.ToString(Inv) + "\t" + bytes.Length.ToString(Inv);
    }

    // One field of a record: tabs and line breaks would split it.
    static string Field(object value)
    {
        string s = Convert.ToString(value, Inv);
        if (s.IndexOfAny(new[] { '\t', '\r', '\n' }) >= 0) throw new InvalidDataException("a field of the translation holds a tab or a line break: " + s);
        return s;
    }

    // "type|name|lang"; the name is "#123" for a number.
    static string KeyOf(Obj o)
    {
        object n = o["n"];
        string name = n is string ? (string)n : "#" + Convert.ToString(n, Inv);
        return Field(string.Format(Inv, "{0}|{1}|{2}", o["t"], name, o["l"]));
    }

    void Line(params string[] fields)
    {
        index.Append(string.Join("\t", fields)).Append('\n');
    }

    // A JSON object that keeps the order of its members and finds them
    // ignoring case. Arrays are List<object>, numbers long or double.
    sealed class Obj
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

    static class Json
    {
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
                var o = new Obj();
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
            if (long.TryParse(num, NumberStyles.AllowLeadingSign, Inv, out l)) return l;
            return double.Parse(num, NumberStyles.Float, Inv);
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
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, Inv));
                        i += 4;
                        break;
                    default: throw new FormatException("JSON: bad escape at " + (i - 1));
                }
            }
        }
    }
}
