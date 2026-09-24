// Reading and writing the resources of the client's programs.
//
// Resources are written by Windows itself (UpdateResource). It rebuilds the
// resource section and nothing before it - code and data stay where they are,
// so the offsets of the code patches hold in a translated file as well.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace IcqRevival.Patch
{
    internal static class IcqResources
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr LoadLibraryEx(string file, IntPtr reserved, uint flags);
        [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "FindResourceExW")]
        static extern IntPtr FindResourceEx(IntPtr module, IntPtr type, IntPtr name, ushort lang);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "FindResourceExW")]
        static extern IntPtr FindResourceExNamed(IntPtr module, IntPtr type, string name, ushort lang);
        [DllImport("kernel32.dll")] static extern IntPtr LoadResource(IntPtr module, IntPtr res);
        [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr data);
        [DllImport("kernel32.dll")] static extern uint SizeofResource(IntPtr module, IntPtr res);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr BeginUpdateResource(string file, bool deleteExisting);
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "UpdateResourceW")]
        static extern bool UpdateResource(IntPtr update, IntPtr type, IntPtr name, ushort lang, byte[] data, uint size);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "UpdateResourceW")]
        static extern bool UpdateResourceNamed(IntPtr update, IntPtr type, string name, ushort lang, byte[] data, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool EndUpdateResource(IntPtr update, bool discard);

        // A resource by its key "type|name|lang"; the name is "#123" for a
        // number, anything else for a name.
        internal struct Key
        {
            public int Type;
            public string Name;
            public int Lang;

            public static Key Parse(string key)
            {
                string[] p = Ps.Split(key, "\\|");
                return new Key { Type = int.Parse(p[0].Trim()), Name = p[1], Lang = int.Parse(p[2].Trim()) };
            }
        }

        static bool IsId(string name, out int id)
        {
            id = 0;
            return name.StartsWith("#") && int.TryParse(name.Substring(1), out id);
        }

        // The data of each resource, null where the file has none.
        public static byte[][] Read(string file, Key[] keys)
        {
            var result = new byte[keys.Length][];
            IntPtr module = LoadLibraryEx(file, IntPtr.Zero, 0x22);  // as data file, as image resource
            if (module == IntPtr.Zero) return result;
            try
            {
                for (int i = 0; i < keys.Length; i++)
                {
                    int id;
                    IntPtr res = IsId(keys[i].Name, out id)
                        ? FindResourceEx(module, (IntPtr)keys[i].Type, (IntPtr)id, (ushort)keys[i].Lang)
                        : FindResourceExNamed(module, (IntPtr)keys[i].Type, keys[i].Name, (ushort)keys[i].Lang);
                    if (res == IntPtr.Zero) continue;
                    uint size = SizeofResource(module, res);
                    IntPtr p = LockResource(LoadResource(module, res));
                    var data = new byte[size];
                    Marshal.Copy(p, data, 0, (int)size);
                    result[i] = data;
                }
            }
            finally { FreeLibrary(module); }
            return result;
        }

        public static bool Same(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        public static void Write(string file, Key[] keys, byte[][] data)
        {
            IntPtr update = BeginUpdateResource(file, false);
            if (update == IntPtr.Zero) throw new Win32Exception();
            for (int i = 0; i < keys.Length; i++)
            {
                int id;
                bool ok = IsId(keys[i].Name, out id)
                    ? UpdateResource(update, (IntPtr)keys[i].Type, (IntPtr)id, (ushort)keys[i].Lang, data[i], (uint)data[i].Length)
                    : UpdateResourceNamed(update, (IntPtr)keys[i].Type, keys[i].Name, (ushort)keys[i].Lang, data[i], (uint)data[i].Length);
                if (!ok)
                {
                    var e = new Win32Exception();
                    EndUpdateResource(update, true);
                    throw e;
                }
            }
            if (!EndUpdateResource(update, false)) throw new Win32Exception();
        }
    }
}
