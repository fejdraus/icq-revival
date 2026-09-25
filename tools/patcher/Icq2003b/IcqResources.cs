// Reading and replacing the resources of the client's programs, over their
// bytes (PeResources) - no Windows resource API is called on them.
//
// The layout PeResources writes is what Windows' UpdateResource wrote before:
// .rsrc rebuilt where it is, nothing before it moved, so the offsets of the
// code patches hold in a translated file as well.

using System.Globalization;
using System.Linq;

namespace IcqRevival.Patch
{
    internal static class IcqResources
    {
        // A resource by its key "type|name|lang"; the name is "#123" for a
        // number, anything else for a name.
        public static PeResources.Key ParseKey(string key)
        {
            string[] p = Ps.Split(key, "\\|");
            int id;
            PeResources.Id name = p[1].StartsWith("#") && int.TryParse(p[1].Substring(1), out id) && id >= 0
                ? PeResources.Id.Of((uint)id)
                : PeResources.Id.OfName(p[1]);
            return new PeResources.Key
            {
                Type = PeResources.Id.Of((uint)int.Parse(p[0].Trim(), CultureInfo.InvariantCulture)),
                Name = name,
                Lang = (uint)int.Parse(p[2].Trim(), CultureInfo.InvariantCulture),
            };
        }

        // The data of each resource of the file's bytes, null where it has none -
        // for every resource when the file is not a program that can be read.
        public static byte[][] Read(byte[] file, string[] keys)
        {
            try
            {
                return PeResources.Read(file, keys.Select(ParseKey).ToArray());
            }
            catch (PeResources.BadFileException)
            {
                return new byte[keys.Length][];
            }
        }

        public static bool Same(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        // The file's bytes with those resources' data replaced.
        public static byte[] Write(byte[] file, string[] keys, byte[][] data)
        {
            return PeResources.Write(file, keys.Select(ParseKey).ToArray(), data);
        }
    }
}
