// What the patch for ICQ Pro 2003b (build 3916) changes.
//
// It does two things at once:
//
//   1. Removes the advertising and the Google search bar with a few point
//      changes in the client's code.
//   2. Points the links to the dead ICQ.com services - help, white pages, the
//      web pager, the panel after sign-in, search - at our server. The domain
//      of the server is typed in the window.
//
// It can also give the client a Ukrainian interface, and it sets the server
// the client signs in to, which lives in the registry.
//
// The user's database and the skin's look are left alone: changing the
// database kills the client for good.
//
// Apply makes the client match the selection: what is wanted is put in, what
// is not wanted and in place is taken out again, from the backup of the file.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace IcqRevival.Patch
{
    internal sealed class Icq2003bResult
    {
        public List<string> Lines;
        public List<string> TooLong;
    }

    internal sealed class Icq2003bClient
    {
        public const string BinSuffix = ".antibanner-backup";
        public const string LinkSuffix = ".icq-links-backup";
        static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

        // --- code patches -----------------------------------------------------------
        //
        // The names of the functions come from the export tables of the modules
        // themselves: they export decorated C++ names, so the places were found by
        // name, not by guessing.

        internal sealed class CodePatch
        {
            public string File;
            public int Offset;
            public string Resource;
            public byte[] From;
            public byte[] To;
            public long Size;
            public string Sha256From;
            public string Sha256To;
            public string What;
            public string Job;
        }

        static byte[] B(params int[] b) { return b.Select(x => (byte)x).ToArray(); }

        internal static readonly CodePatch[] Patches =
        {
            new CodePatch
            {
                File = "icqmutl.dll", Offset = 0x20626,
                From = B(0xB8, 0x96, 0x9B, 0x22, 0x20),
                To = B(0x31, 0xC0, 0xC2, 0x04, 0x00),
                Size = 270421,
                Sha256From = "7B3198D703D4AB2DAAD6A8062B0C4F885419C3BC72151BF78427D3FA32A6680A",
                Sha256To = "4530FF4F8190DCE7D213D40BBDC3602E774A65490AE5D927CF7B77D8C245E347",
                What = "contact list banner is never created",
                Job = "banners",
            },
            new CodePatch
            {
                File = "ICQProLib.dll", Offset = 0x1217B,
                From = B(0xB8, 0xBA, 0x7D, 0x89, 0x24),
                To = B(0x31, 0xC0, 0xC3),
                Size = 198739,
                Sha256From = "192941271B7B50BC9298B665C2C1F0C9F3F74E2AF43FAFF3C0FE0F0E082A31A3",
                Sha256To = "631780FABA446E9AB5598D88B45296A626F373DAFAA275D828B1920692EC139E",
                What = "message window banner is never shown",
                Job = "banners",
            },
            new CodePatch
            {
                File = "ICQTicker.dll", Offset = 0x750,
                From = B(0x53, 0x55, 0x8B, 0x6C, 0x24, 0x14, 0x56),
                To = B(0xB8, 0x11, 0x01, 0x04, 0x80, 0xC2, 0x0C, 0x00),
                Size = 37977,
                Sha256From = "92058B9563288A066DC4884E68930BB67F78A6D10AD8BAB8BD0F8287FB847A39",
                Sha256To = "2E901493EFB3914273DDD952159B3135FD959A8FC2F0DB8DD67EFDE875D031FF",
                What = "Google search bar and its button are gone",
                Job = "google bar",
            },
            new CodePatch
            {
                File = "Icq.exe", Offset = 0x39AA2,
                From = B(0x74, 0x41),
                To = B(0xEB, 0x41),
                Size = 1880639,
                Sha256From = "6C97F1B8045ED6E6801E0AFD97548B040819F153836B25B0F968184483F1546A",
                Sha256To = "BE8AEA553DCABA7108E3442EEEBAA5F00A56A2BE78653290EFFF6A83DF5F0B1B",
                What = "no empty strip reserved for them",
                // The 22 px the layout keeps for the bar above: one job with it.
                Job = "google bar",
            },
            // The "Send By: ICQ / SMS / Email" strip in the message window. SMS and
            // Email went through gateways on ICQ.com and there is nothing behind
            // them any more, so the strip only offers ways to fail.
            //
            // The strip is made of three layers that know nothing about each
            // other, and each needed its own change:
            //
            //   1. the three tick boxes - controls of the plugin's dialog;
            //   2. the words "Send By:"  - a string in Icq.exe, painted by the skin;
            //   3. the frame around them - an object in Skin\IcqPro.skn.
            //
            // This is the first layer. The dialog template is not where visibility
            // is decided: a layout routine calls ShowWindow itself and works out
            // the argument as 5 (SW_SHOW) or 0 (SW_HIDE):
            //
            //   neg eax ; sbb eax, eax ; and al, 0xFB ; add eax, 5
            //
            // Zeroing the result makes the client hide the boxes with its own
            // call. They stay in the dialog and the ICQ box stays ticked, so the
            // code still reads it and Send keeps working. Two places: eax for the
            // group, edi for the three boxes pushed after it.
            new CodePatch
            {
                File = "ICQMessagePlugin.dll", Offset = 0x7B63,
                From = B(0x83, 0xC0, 0x05),
                To = B(0x31, 0xC0, 0x90),
                Size = 236144,
                Sha256From = "AFC36BD67D353EECA1F952C3ED56D372FE93C018D58C966F0A930EDEE5AC887B",
                Sha256To = "E40BEEE28D67ECACA0A10182F215CB2901F8CD4A56F85C667C0AE8E09E18E486",
                What = "tick boxes ICQ / SMS / Email are hidden",
                Job = "send-by",
            },
            new CodePatch
            {
                File = "ICQMessagePlugin.dll", Offset = 0x7B84,
                From = B(0x83, 0xC7, 0x05),
                To = B(0x31, 0xFF, 0x90),
                Size = 236144,
                Sha256From = "AFC36BD67D353EECA1F952C3ED56D372FE93C018D58C966F0A930EDEE5AC887B",
                Sha256To = "E40BEEE28D67ECACA0A10182F215CB2901F8CD4A56F85C667C0AE8E09E18E486",
                What = "the same for the group around them",
                Job = "send-by",
            },
            // Second layer: the words. There is no control behind them - a walk
            // of the open window shows none - the skin paints them from this
            // string, string 8727 of Icq.exe, so only the string itself can be
            // changed. It is written as a resource, blank, in English or in
            // Ukrainian - see "the binaries" below; the offset is where it sits
            // in the original.
            new CodePatch
            {
                File = "Icq.exe", Offset = 0x1C489C,
                Resource = "sendBy",
                From = Encoding.Unicode.GetBytes("Send By:"),
                To = Encoding.Unicode.GetBytes("        "),
                Size = 1880639,
                Sha256From = "85F31E2FB53366F1FCC03D16788E50E6932AE2BB3F13C10C3242F1D68AD68684",
                Sha256To = "64EA6C32386A04D71B873522EF3A2662E074EB048AF584459F9E8492DC4F0EBA",
                What = "the words \"Send By:\" are gone",
                // The three layers of the strip only make sense together.
                Job = "send-by",
            },
            // Third layer: the frame. An object named RgnFrame in the skin, 334x32
            // from x=136 to x=470 - it used to hold the tick boxes, and with them
            // hidden its left half was empty. Its position is worked out from
            // anchors and offsets, not from the rectangle, so the offset is what
            // actually moves it; the rectangle is kept in step so the file stays
            // consistent with itself.
            //
            // 344 is as close to the Send button as the skin can draw: the curve
            // of the left end is part of a stretched image, and below this width
            // it visibly flattens. Hiding the object outright is not an option -
            // it shapes the window, and without it the right edge clips the
            // indicator.
            new CodePatch
            {
                File = @"Skin\IcqPro.skn", Offset = 0x41750,
                From = B(0xAB, 0xFE, 0xFF, 0xFF),
                To = B(0x7B, 0xFF, 0xFF, 0xFF),
                Size = 423358,
                Sha256From = "B9E7997D2E60A5E172F09376550596B61C871A45B9804243F23F07D2B14CECD0",
                Sha256To = "5E126B5C13CF0400FAAF43BBA6631E497F70EC7C85C41B5645BBB5F700CA2370",
                What = "the frame is pulled up to the Send button",
                Job = "send-by",
            },
            new CodePatch
            {
                File = @"Skin\IcqPro.skn", Offset = 0x41782,
                From = B(0x88, 0x00, 0x00, 0x00),
                To = B(0x58, 0x01, 0x00, 0x00),
                Size = 423358,
                Sha256From = "B9E7997D2E60A5E172F09376550596B61C871A45B9804243F23F07D2B14CECD0",
                Sha256To = "5E126B5C13CF0400FAAF43BBA6631E497F70EC7C85C41B5645BBB5F700CA2370",
                What = "its rectangle follows the offset",
                Job = "send-by",
            },
        };

        // --- addresses built into the code ---------------------------------------------
        //
        // These links sit in Icq.exe as strings; there is no file with them. A
        // string can only be replaced by one no longer than it: the tail is
        // filled with zeros, and nothing can be moved. So the server has the
        // short paths /p, /u, /e, /m at the root of the address, which only
        // redirect to the full pages.

        sealed class StringPatch
        {
            public string File;
            public int Offset;
            public string Path;
            public string Original;
            public string What;
        }

        static readonly StringPatch[] StringPatches =
        {
            new StringPatch { File = "Icq.exe", Offset = 0x14269C, Path = "/p",
                Original = "http://cf.icq.com/cf/2003b/password.html",
                What = "\"Forgot your ICQ#/Password?\" on the login window" },
            new StringPatch { File = "Icq.exe", Offset = 0x14283C, Path = "/e",
                Original = "http://cf.icq.com/cf/2003b/email_login.html",
                What = "\"ICQ#/Email\" help on the login window" },
            new StringPatch { File = "Icq.exe", Offset = 0x140448, Path = "/u",
                Original = "http://cf.icq.com/cf/2003b/unregister.html",
                What = "help on deleting your number" },
            new StringPatch { File = "Icq.exe", Offset = 0x142804, Path = "/m",
                Original = "http://cf.icq.com/cf/2003b/public_private_modes.html",
                What = "help on public and private mode" },
        };

        // --- the old hosts in the code --------------------------------------------------
        //
        // Hosts built into programs the rest of the patch does not touch
        // (CodeStrings, in Common, has how they are written over). Each file is
        // recognised by the checksum of its original before a byte is written,
        // and built again from it, so a change comes out byte-exact:
        //   ICQCool.dll    the hardcoded fallback login IP 205.188.147.46 (the
        //                  old AOL/ICQ login server), and Email Express's
        //                  @pager.icq.com
        //   DBAdmin.exe    the fallback login IP 205.188.252.121 and the
        //                  cb.icq.com datafile bundles (banners, channels)
        //   ICQFTLib.dll   the file-transfer rendezvous relay rars.oscar.aol.com
        //                  (our server and TURN carry transfers instead)
        //   ICQSmLib.dll   a.root-servers.net, a hardcoded DNS probe
        //   icqsrp.exe     the statistics/registration reporter ("SRP") posting
        //                  to the sign-in host under /cb/...srp.cb
        // The login IPs, the relay and the DNS probe go with the sign-in; the
        // stats and datafile bundles with the links.
        static readonly Dictionary<string, string> CodeHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "ICQCool.dll", "76DB4E062442A173B7CBD01E6B13B7EAB0AAB50B5D0B98359F016499971F4D94" },
            { "DBAdmin.exe", "C215FDB0505B3789453B91433BAAB5D8960F9EACEE22D8428F1F9923EA67221F" },
            { "ICQFTLib.dll", "D81738642AC110DF18D10D0E87E4F04302A08B63C65DC85926C3EA155750A20D" },
            { "ICQSmLib.dll", "6123AB42B88D17E8D03247CCD8ABAD5CA4DD90751B05F6538024BDEADF9BB85D" },
            { "icqsrp.exe", "EAF496AF954F2364470EBDD1241D4323FFD3AF5819BDFAFD817DB1D3868F040F" },
        };

        // A host inside a longer ASCII string (a URL or e-mail): matched with
        // no terminator, so the path after it stays but is cut off by the zeros
        // the replacement leaves - the string becomes http://127.0.0.1 and the
        // connection is refused on the client's own machine.
        static CodeString Ai(string file, string part, string host)
        {
            return new CodeString { File = file, Part = part, Infix = true, From = host, To = CodeStrings.NoHost };
        }

        static readonly CodeString[] CodeStringList =
        {
            // 203.0.113.0 is from TEST-NET-3 (RFC 5737), a documentation range
            // that routes nowhere, used where a bare IP must stay an IP.
            CodeStrings.A("ICQCool.dll", "sign-in", "205.188.147.46", "203.0.113.0"),
            Ai("ICQCool.dll", "links", "pager.icq.com"),
            CodeStrings.A("DBAdmin.exe", "sign-in", "205.188.252.121", "203.0.113.0"),
            Ai("DBAdmin.exe", "links", "cb.icq.com"),
            CodeStrings.A("ICQFTLib.dll", "sign-in", "Rars.oscar.aol.com", CodeStrings.NoHost),
            CodeStrings.A("ICQSmLib.dll", "sign-in", "a.root-servers.net", CodeStrings.NoHost),
            Ai("icqsrp.exe", "links", "web.icq.com"),
        };

        static IEnumerable<string> CodeStringFiles { get { return CodeStrings.Files(CodeStringList); } }

        string CodeStringSource(string file)
        {
            string path = PatchFiles.Join(Root, file);
            if (Ps.Eq(PatchFiles.Sha256(path), CodeHashes[file])) return path;
            return PatchFiles.Exists(path + BinSuffix) ? path + BinSuffix : path;
        }

        bool CodeStringOtherVersion(string file)
        {
            return PatchFiles.Exists(PatchFiles.Join(Root, file)) && !Ps.Eq(PatchFiles.Sha256(CodeStringSource(file)), CodeHashes[file]);
        }

        string CodeStringState(string file, string part)
        {
            string path = PatchFiles.Join(Root, file);
            if (!PatchFiles.Exists(path)) return "missing";
            if (CodeStringOtherVersion(file)) return "other version";
            return CodeStrings.State(File.ReadAllBytes(path), CodeStringList.Where(s => Ps.Eq(s.File, file) && Ps.Eq(s.Part, part)));
        }

        void SetCodeStrings(string file, ICollection<string> skip)
        {
            string path = PatchFiles.Join(Root, file);
            if (!PatchFiles.Exists(path)) return;
            string source = CodeStringSource(file);
            if (!Ps.Eq(PatchFiles.Sha256(source), CodeHashes[file])) return;
            byte[] bytes = File.ReadAllBytes(source);
            CodeStrings.Apply(bytes, CodeStringList.Where(s => Ps.Eq(s.File, file) && Jobs.IsWanted(skip, s.Part)));
            if (bytes.SequenceEqual(File.ReadAllBytes(path))) return;
            BackupBin(path);
            File.WriteAllBytes(path, bytes);
        }

        // --- links ----------------------------------------------------------------------

        static readonly string[] LinkFiles =
        {
            @"DataFiles\icqlinks.xml",
            @"DataFiles\channels.xml",
            @"DataFiles\atelink.xml",
            @"DataFiles\icqacc.xml",
            @"DataFiles\psearch.xml",
            @"DataFiles\WebSearch.fld",
        };

        static readonly string[] DeadHosts =
        {
            "cb.icq.com", "cf.icq.com", "cgi.icq.com", "google.icq.com", "mail.icqmail.com",
            "members.icq.com", "news.icqit.com", "public.icq.com", "search.icq.com",
            "web.icq.com", "www.icq.com", "www.icqit.com", "wwp.icq.com",
        };

        // Links with a known name in icqlinks.xml go to their own pages.
        static readonly Dictionary<string, string> NamedRoutes = new Dictionary<string, string>(Ps.Keys)
        {
            { "StartPage", "{base}/today?uin=%icquin%" },
            { "WWP", "{base}/center?uin=%d" },
            { "HowTo", "{base}/howto?uin=%icquin%" },
            { "Main Page", "{base}/howto?uin=%icquin%" },
            { "Password", "{base}/password" },
            { "PasswordR", "{base}/password" },
            { "Registration", "{base}/register" },
            { "Fail Register", "{base}/register" },
            { "Delete User", "{base}/account" },
            { "Whitepages", "{base}/whitepages" },
            { "White Pages Update", "{base}/whitepages" },
            { "Users Lists", "{base}/whitepages" },
            { "OtherDirectories", "{base}/whitepages" },
            { "Homepage Directory", "{base}/whitepages" },
            { "Map", "{base}/map" },           // Google Maps at the address the client appends
        };

        // Links without a name are recognised by the address itself. The order
        // matters: the particular before the general, or the general rule would
        // catch the search request and lose the word.
        //
        // About "=REPLACEME": the client puts the typed word in place of this
        // sequence together with the equals sign, hence the two signs - the
        // first one stays in the address.
        static readonly KeyValuePair<string, string>[] UrlRoutes =
        {
            new KeyValuePair<string, string>("google\\.icq\\.com/search", "https://www.google.com/search?q==REPLACEME"),
            new KeyValuePair<string, string>("search\\.icq\\.com", "{base}/whitepages"),
            new KeyValuePair<string, string>("google\\.icq\\.com", "https://www.google.com/"),
            new KeyValuePair<string, string>("/welcome/", "{base}/welcome?uin=%icquin%"),
        };

        // Only the server's domain is asked for. The port and path of the pages
        // are the same on every ICQ Revival server (deploy/VM-SPEC.md, section 3),
        // so the patch fills them in: 2003b opens these links in the browser,
        // which wants HTTPS.
        const int PagesPortHttps = 8102;
        const string PagesPath = "/icq";

        static string PagesRoot(string domain) { return "https://" + domain + ":" + PagesPortHttps; }

        // The domain typed is remembered, so it need not be typed on every run.
        public const string SettingsKey = @"Software\OpenOSCAR\IcqPatch";
        const string SettingsPath = @"HKCU:\Software\OpenOSCAR\IcqPatch";

        // Older versions saved the whole address here; only the domain is kept now.
        public static string SavedBase()
        {
            string value = PatchSettings.Read(SettingsKey, "ServerBase");
            return value == null ? null : Domain.Of(value);
        }

        public static void SaveBase(string value)
        {
            PatchSettings.Save(SettingsKey, "ServerBase", value);
        }

        // --- sign-in server -----------------------------------------------------------
        //
        // ICQ 2003b keeps the server in two places. Default Server Host under
        // HKLM is what a new install starts from - and what "Get an ICQ Number"
        // connects to: out of the box it is login.icq.com, which is gone, so
        // registering failed with "Info Number 117". On its first run the client
        // copies it into the connection settings under HKCU, and from then on
        // signs in with those; the default is not read again. So both are set.
        //
        // The connection settings are only taken over while they still hold the
        // dead default, or a server this patch put there before: a server the
        // user typed under Preferences -> Connection stays theirs. The port stays
        // 5190, as it is there already. What each held first is saved once, for
        // Restore original.

        static readonly string[] DefaultPrefsKeys =
        {
            @"HKLM:\SOFTWARE\WOW6432Node\Mirabilis\ICQ\ICQPro\DefaultPrefs",   // 64-bit Windows
            @"HKLM:\SOFTWARE\Mirabilis\ICQ\ICQPro\DefaultPrefs",               // 32-bit Windows
        };
        const string SignInValue = "Default Server Host";
        const string ConnectionKey = @"HKCU:\Software\Mirabilis\ICQ\CommonPrefs\Connection";
        const string ConnectionValue = "ServerHostName";
        const string DeadSignIn = "login.icq.com";

        static string DefaultPrefsKey()
        {
            foreach (string k in DefaultPrefsKeys) { if (RegistryPath.Exists(k)) return k; }
            return null;
        }

        public static string SignInServer()
        {
            string k = DefaultPrefsKey();
            if (k == null) return null;
            return RegistryPath.Get(k, SignInValue);
        }

        // The server the client signs in with; null before its first run.
        public static string ConnectionServer() { return RegistryPath.Get(ConnectionKey, ConnectionValue); }

        // Whether the connection settings are the patch's to change: the dead
        // default, or the server of an earlier apply.
        static bool ConnectionOurs(string current, string previous)
        {
            return Ps.Eq(current, DeadSignIn) || (Ps.IsTrue(previous) && Ps.Eq(current, previous));
        }

        // Saves what a value held first - once, so a second apply does not save
        // our own domain as the "original".
        static void SaveOriginal(string name, string value)
        {
            try { if (!RegistryPath.Exists(SettingsPath)) RegistryPath.Create(SettingsPath); }
            catch (Exception e) { PatchFiles.Error(e.Message); }
            if (!Ps.IsTrue(RegistryPath.Get(SettingsPath, name)))
            {
                try { RegistryPath.Set(SettingsPath, name, value ?? ""); }
                catch (Exception e) { PatchFiles.Error(e.Message); }
            }
        }

        // original / patched / missing, for the domain.
        static string SignInState(string domain, string previous)
        {
            if (DefaultPrefsKey() == null) return "missing";
            if (!Ps.IsTrue(domain) || !Ps.Eq(SignInServer(), domain)) return "original";
            string c = ConnectionServer();
            if (Ps.IsTrue(c) && !Ps.Eq(c, domain) && ConnectionOurs(c, previous)) return "original";
            return "patched";
        }

        static bool SetSignInServer(string domain, string previous)
        {
            string k = DefaultPrefsKey();
            if (k == null) return false;
            bool changed = false;
            try
            {
                string current = SignInServer();
                if (!Ps.Eq(current, domain))
                {
                    SaveOriginal("OriginalServerHost", current);
                    RegistryPath.Set(k, SignInValue, domain);
                    changed = true;
                }
                string c = ConnectionServer();
                if (Ps.IsTrue(c) && !Ps.Eq(c, domain) && ConnectionOurs(c, previous))
                {
                    SaveOriginal("OriginalConnectionHost", c);
                    RegistryPath.Set(ConnectionKey, ConnectionValue, domain);
                    changed = true;
                }
            }
            catch { }
            return changed;
        }

        // Puts back what was saved; a saved value is only let go once it is back
        // in place.
        static int RestoreSignInServer()
        {
            int done = 0;
            string saved = RegistryPath.Get(SettingsPath, "OriginalServerHost");
            string k = DefaultPrefsKey();
            if (Ps.IsTrue(saved) && k != null)
            {
                try
                {
                    RegistryPath.Set(k, SignInValue, saved);
                    RegistryPath.Remove(SettingsPath, "OriginalServerHost");
                    done++;
                }
                catch { }
            }
            saved = RegistryPath.Get(SettingsPath, "OriginalConnectionHost");
            if (Ps.IsTrue(saved) && RegistryPath.Exists(ConnectionKey))
            {
                try
                {
                    RegistryPath.Set(ConnectionKey, ConnectionValue, saved);
                    RegistryPath.Remove(SettingsPath, "OriginalConnectionHost");
                    done++;
                }
                catch { }
            }
            return done;
        }

        // --- finding the client ---------------------------------------------------------

        public static bool IsClientFolder(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !PatchFiles.Exists(path)) return false;
            foreach (CodePatch p in Patches)
            {
                if (!PatchFiles.Exists(PatchFiles.Join(path, p.File))) return false;
            }
            return true;
        }

        public static string FindRoot()
        {
            return ClientFolder.Find(new ClientSearch
            {
                AppPathsExe = "Icq.exe",
                TrimQuotes = false,
                DisplayName = "(?i)^icq",
                UseUninstallString = true,
                StandardFolder = "ICQ",
                IsClient = IsClientFolder,
            });
        }

        // The files a folder must have to be taken for the client, as the
        // window names them (each change names its file, so some twice).
        public static string ExpectedFiles { get { return string.Join(", ", Patches.Select(p => p.File)); } }

        // --- the binaries -----------------------------------------------------------------
        //
        // Every program file the patch changes is built again on each Apply, from
        // its original - the backup, or the file itself while it has none - with
        // the wanted changes in this order: code bytes, the links inside Icq.exe,
        // then resources: the Ukrainian interface and the blanked "Send By:".
        // Taking a change out is leaving it out of the build, and the result is
        // exact.

        public readonly string Root;
        // Leaves the registry alone - the sign-in server lives there, for the
        // whole machine, not in the folder. For runs on a copy of the client.
        public readonly bool NoRegistry;

        public Icq2003bClient(string root, bool noRegistry)
        {
            Root = root;
            NoRegistry = noRegistry;
        }

        static Translation Tr { get { return Translation.Get(); } }

        static IEnumerable<string> TranslationFiles() { return Tr.Files.Select(f => f.Rel); }

        // The original of a program file: its backup, or the file while it has none.
        static string OriginalPath(string path)
        {
            string backup = path + BinSuffix;
            if (PatchFiles.Exists(backup)) return backup;
            return path;
        }

        static byte[][] ReadResources(string path, IEnumerable<string> keys)
        {
            return IcqResources.Read(File.ReadAllBytes(path), keys.ToArray());
        }

        // Everything one file's resources come to on this client, built from its
        // English original (the backup, or the file while it has none).
        static MatFile Materialize(string rel, string path)
        {
            return Tr.Materialize(Tr.File(rel), File.ReadAllBytes(OriginalPath(path)));
        }

        // The "Send By:" words: blank in either language, or as they came.
        static string SendByState(string path)
        {
            TrSendBy sb = Tr.SendBy;
            byte[] cur = ReadResources(path, new[] { sb.Key })[0];
            MatFile mat = Materialize(sb.File, path);
            if (IcqResources.Same(cur, mat.BlankEn) || IcqResources.Same(cur, mat.BlankUk)) return "patched";
            if (Ps.IsTrue(cur) && Ps.Eq(Translation.Sha(cur), sb.From)) return "original";
            byte[] table = mat.ByKey(sb.Key);
            if (table != null && IcqResources.Same(cur, table)) return "original";
            return "unknown";
        }

        string State(CodePatch patch)
        {
            if (!Ps.IsTrue(Root)) return "no folder";
            string path = PatchFiles.Join(Root, patch.File);
            if (!PatchFiles.Exists(path)) return "missing";
            // The offsets are right for build 3916 only: the original is
            // recognised by its size, and the change by its bytes - which a
            // translated file keeps in place.
            if (new FileInfo(OriginalPath(path)).Length != patch.Size) return "other version";
            if (Ps.IsTrue(patch.Resource)) return SendByState(path);
            int len = Math.Max(patch.From.Length, patch.To.Length);
            var buf = new byte[len];
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                fs.Seek(patch.Offset, SeekOrigin.Begin);
                fs.Read(buf, 0, len);
            }
            Func<byte[], bool> same = expect =>
            {
                for (int i = 0; i < expect.Length; i++) { if (buf[i] != expect[i]) return false; }
                return true;
            };
            if (same(patch.To)) return "patched";
            if (same(patch.From)) return "original";
            return "unknown";
        }

        // Whether a file speaks Ukrainian: all its resources translated, none,
        // or a mix.
        string TranslationState(string rel)
        {
            if (!Ps.IsTrue(Root)) return "no folder";
            string path = PatchFiles.Join(Root, rel);
            if (!PatchFiles.Exists(path)) return "missing";
            TrFile entry = Tr.File(rel);
            if (new FileInfo(OriginalPath(path)).Length != entry.Size) return "other version";
            TrSendBy sb = Tr.SendBy;
            MatFile mat = Tr.Materialize(entry, File.ReadAllBytes(OriginalPath(path)));
            List<KeyValuePair<string, byte[]>> items = mat.Items;
            List<TrPlace> places = entry.Inplace;
            int done = 0, orig = 0;
            if (items.Count > 0)
            {
                byte[][] cur = ReadResources(path, items.Select(i => i.Key));
                for (int i = 0; i < items.Count; i++)
                {
                    KeyValuePair<string, byte[]> it = items[i];
                    byte[] c = cur[i];
                    bool blankUk = Ps.Eq(rel, sb.File) && Ps.Eq(it.Key, sb.Key) && IcqResources.Same(c, mat.BlankUk);
                    bool blankEn = Ps.Eq(rel, sb.File) && Ps.Eq(it.Key, sb.Key) && IcqResources.Same(c, mat.BlankEn);
                    if (IcqResources.Same(c, it.Value) || blankUk) done++;
                    else if (blankEn || (Ps.IsTrue(c) && Ps.Eq(Translation.Sha(c), mat.KeyFrom[it.Key]))) orig++;
                }
            }
            if (places.Count > 0)
            {
                byte[] bytes = File.ReadAllBytes(path);
                foreach (TrPlace pl in places)
                {
                    var c = new byte[pl.Bytes.Length];
                    Array.Copy(bytes, pl.Offset, c, 0, c.Length);
                    if (IcqResources.Same(c, pl.Bytes)) done++;
                    else if (IcqResources.Same(c, pl.Original)) orig++;
                }
            }
            int all = items.Count + places.Count;
            if (entry.Whole != null)
            {
                // A text file written whole.
                all++;
                byte[] bytes = File.ReadAllBytes(path);
                if (IcqResources.Same(bytes, entry.Whole)) done++;
                else if (Ps.Eq(Translation.Sha(bytes), entry.WholeFrom)) orig++;
            }
            if (done == all) return "patched";
            if (orig == all) return "original";
            if (done > 0) return "partly";
            return "unknown";
        }

        // --- moving the links -----------------------------------------------------------

        static string Base(string domain) { return PagesRoot(domain) + PagesPath; }

        static string UrlHost(string url)
        {
            Match m = Regex.Match(url ?? "", "^https?://([^/:]+)", RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value.ToLower();
            return "";
        }

        static bool IsDead(string url) { return Ps.Contains(DeadHosts, UrlHost(url)); }

        static string WithBase(string target, string b) { return Ps.Replace(target, "\\{base\\}", b); }

        // What a link becomes: by its name, by the pattern of its address, a
        // stub - or nothing.
        static string ResolveTarget(string name, string url, string b)
        {
            string named;
            if (Ps.IsTrue(name) && NamedRoutes.TryGetValue(name, out named)) return WithBase(named, b);
            foreach (KeyValuePair<string, string> r in UrlRoutes)
            {
                if (Ps.Match(url, r.Key)) return WithBase(r.Value, b);
            }
            if (IsDead(url))
            {
                string leaf = Ps.Split(url, "\\?")[0].TrimEnd('/');
                string[] parts = Ps.Split(leaf, "/");
                leaf = parts[parts.Length - 1];
                if (!Ps.IsTrue(leaf)) leaf = "index";
                return b + "/stub/" + leaf;
            }
            return null;
        }

        const string UrlPattern = "https?://[^\\s\"'<>\\]]+";

        static string ConvertLinkText(string text, string b)
        {
            // Entries with a name: the name and the address lie in one <item> block.
            if (Ps.Match(text, "<item>"))
            {
                text = Regex.Replace(text, "(?s)<item>.*?</item>", m =>
                {
                    string block = m.Value;
                    Match um = Regex.Match(block, "(?is)<url>\\s*([^<]*?)\\s*</url>");
                    if (!um.Success) return block;
                    string url = um.Groups[1].Value;
                    if (!Ps.Match(url, "^https?://")) return block;
                    Match nm = Regex.Match(block, "(?is)<name>\\s*([^<]*?)\\s*</name>");
                    string name = nm.Success ? nm.Groups[1].Value : "";
                    string target = ResolveTarget(name, url, b);
                    if (!Ps.IsTrue(target) || Ps.Eq(target, url)) return block;
                    return block.Substring(0, um.Groups[1].Index) + target +
                           block.Substring(um.Groups[1].Index + um.Groups[1].Length);
                });
            }

            // Everything else: addresses in other tags, in attributes, in the
            // fields of WebSearch.fld. Only dead hosts are touched, so nothing of
            // anybody else's is.
            text = Regex.Replace(text, UrlPattern, m =>
            {
                string url = m.Value;
                if (!IsDead(url)) return url;
                string target = ResolveTarget("", url, b);
                if (!Ps.IsTrue(target) || Ps.Eq(target, url)) return url;
                return target;
            });
            return text;
        }

        string LinkState(string rel)
        {
            if (!Ps.IsTrue(Root)) return "no folder";
            string path = PatchFiles.Join(Root, rel);
            if (!PatchFiles.Exists(path)) return "missing";
            string text = File.ReadAllText(path, Latin1);
            MatchCollection urls = Regex.Matches(text, UrlPattern);
            int dead = urls.Cast<Match>().Count(m => IsDead(m.Value));
            if (urls.Count == 0) return "no links";
            return dead > 0 ? "original" : "patched";
        }

        // --- applying -----------------------------------------------------------------

        static string StringAt(string path, int offset, int len)
        {
            var buf = new byte[len];
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                fs.Seek(offset, SeekOrigin.Begin);
                fs.Read(buf, 0, len);
            }
            string text = Encoding.ASCII.GetString(buf);
            int z = text.IndexOf('\0');
            if (z >= 0) text = text.Substring(0, z);
            return text;
        }

        string StringState(StringPatch sp)
        {
            if (!Ps.IsTrue(Root)) return "no folder";
            string path = PatchFiles.Join(Root, sp.File);
            if (!PatchFiles.Exists(path)) return "missing";
            string cur = StringAt(path, sp.Offset, sp.Original.Length);
            if (Ps.Eq(cur, sp.Original)) return "original";
            if (Ps.Match(cur, "^https?://")) return "patched";
            return "other version";
        }

        // Backs a program file up once, before its first change: while it has
        // no backup, the file is still the original.
        static void BackupBin(string path)
        {
            PatchFiles.BackupOnce(path, BinSuffix);
        }

        // Every program file the patch may change.
        static List<string> BinaryFiles()
        {
            return Ps.Unique(Patches.Select(p => p.File).Concat(StringPatches.Select(s => s.File)).Concat(TranslationFiles()));
        }

        // Builds one program file from its original with the wanted changes, and
        // writes it if it came out different. The links that did not fit are
        // added to tooLong.
        bool BuildBinary(string rel, string domain, ICollection<string> skip, List<string> tooLong)
        {
            string path = PatchFiles.Join(Root, rel);
            if (!PatchFiles.Exists(path)) return false;
            byte[] bytes = File.ReadAllBytes(OriginalPath(path));
            // The English original, kept aside: the translated resources are
            // built from it, whatever the code patches change in these bytes.
            byte[] pristine = (byte[])bytes.Clone();

            foreach (CodePatch p in Patches.Where(x => Ps.Eq(x.File, rel) && !Ps.IsTrue(x.Resource)))
            {
                if (Jobs.IsWanted(skip, p.What) && bytes.Length == p.Size)
                {
                    Array.Copy(p.To, 0, bytes, p.Offset, p.To.Length);
                }
            }

            // The strings built into the code get only the root of the address:
            // the room in the file is the length of the original link, and every
            // character counts.
            string root = PagesRoot(domain);
            foreach (StringPatch sp in StringPatches.Where(x => Ps.Eq(x.File, rel)))
            {
                if (!Jobs.IsWanted(skip, sp.What)) continue;
                string url = root + sp.Path;
                if (url.Length > sp.Original.Length)
                {
                    tooLong.Add(string.Format(CultureInfo.InvariantCulture, "{0} (needs {1}, room for {2})", sp.Path, url.Length, sp.Original.Length));
                    continue;
                }
                byte[] text = Encoding.ASCII.GetBytes(url);
                for (int i = 0; i < sp.Original.Length; i++)
                {
                    bytes[sp.Offset + i] = i < text.Length ? text[i] : (byte)0;
                }
            }

            // The resources, by key; a later one for the same key wins. Texts that
            // are not resources - in the data of a program, in the skin - are
            // written in place, over the English ones.
            var resKeys = new List<string>();
            var res = new Dictionary<string, byte[]>(Ps.Keys);
            Action<string, byte[]> put = (key, data) =>
            {
                if (!res.ContainsKey(key)) resKeys.Add(key);
                res[key] = data;
            };
            TrFile entry = Tr.File(rel);
            bool ukrainian = entry != null && Jobs.IsWanted(skip, "uk:" + rel) && bytes.Length == entry.Size;
            MatFile mat = entry != null ? Tr.Materialize(entry, pristine) : null;
            if (ukrainian && entry.Whole != null)
            {
                bytes = (byte[])entry.Whole.Clone();
            }
            if (ukrainian)
            {
                foreach (KeyValuePair<string, byte[]> it in mat.Items) put(it.Key, it.Value);
                foreach (TrPlace pl in entry.Inplace) Array.Copy(pl.Bytes, 0, bytes, pl.Offset, pl.Bytes.Length);
            }
            CodePatch words = Patches.First(x => Ps.Eq(x.Resource, "sendBy"));
            if (Ps.Eq(rel, Tr.SendBy.File) && Jobs.IsWanted(skip, words.What) && bytes.Length == words.Size)
            {
                put(Tr.SendBy.Key, ukrainian ? mat.BlankUk : mat.BlankEn);
            }

            // The resources are laid into the file's own bytes, in memory: the
            // section that holds them is rebuilt where it is, nothing else moves.
            byte[] built = bytes;
            if (resKeys.Count > 0)
            {
                built = IcqResources.Write(bytes, resKeys.ToArray(), resKeys.Select(k => res[k]).ToArray());
            }

            if (!IcqResources.Same(built, File.ReadAllBytes(path)))
            {
                BackupBin(path);
                File.WriteAllBytes(path, built);
                return true;
            }
            return false;
        }

        // The client keeps the names its plugins give themselves - menu items,
        // pages of the preferences - in .pnCache, and takes them from there
        // rather than from the plugins once it has it. When the programs change -
        // another language - the cache goes, and the client builds it again from
        // them.
        void ClearPluginCache()
        {
            string cache = PatchFiles.Join(Root, ".pnCache");
            if (PatchFiles.Exists(cache))
            {
                try
                {
                    if (File.Exists(cache))
                    {
                        FileAttributes a = File.GetAttributes(cache);
                        if ((a & FileAttributes.ReadOnly) != 0) File.SetAttributes(cache, a & ~FileAttributes.ReadOnly);
                        File.Delete(cache);
                    }
                    else if (!Directory.EnumerateFileSystemEntries(cache).Any())
                    {
                        Directory.Delete(cache);
                    }
                }
                catch { }
            }
        }

        // What a person chooses between: one row per job, whatever number of
        // files and places it takes.
        public static readonly PatchJobs Jobs = MakeJobs();

        static PatchJobs MakeJobs()
        {
            var j = new PatchJobs();
            j.Add("banners", "Advertising", "the banners of the contact list and the message window");
            j.Add("google bar", "Advertising", "the Google search bar and the strip kept for it");
            j.Add("send-by", "Services that are gone", "the \"Send By: ICQ / SMS / Email\" strip of the message window");
            j.Add("links", "Your server", "ICQ.com links in menus and help point at your server");
            j.Add("sign-in", "Your server", "ICQ signs in to your server, \"Get an ICQ Number\" too");
            // Off until chosen: not everyone wants the client in another language.
            j.Add("ukrainian", "Language", "Ukrainian interface: menus, windows and messages", off: true);

            j.Assign("sign-in", "sign-in");
            foreach (CodePatch p in Patches) { if (Ps.IsTrue(p.Job)) j.Assign(p.What, p.Job); }
            foreach (string f in TranslationFiles()) j.Assign("uk:" + f, "ukrainian");
            foreach (StringPatch sp in StringPatches) j.Assign(sp.What, "links");
            foreach (string rel in LinkFiles) j.Assign(rel, "links");
            return j;
        }

        // Every change with its current state, in the order the window lists
        // them, the parts of one job folded into one row. A row's key is what it
        // is chosen by: the job, or the change itself.
        public List<PatchItem> Items(string domain)
        {
            var items = new List<PatchItem>();
            Action<string, string, string, string, string> add = (group, key, what, where, state) =>
                items.Add(new PatchItem { Group = group, Key = key, What = what, Where = where, State = state });
            foreach (CodePatch p in Patches)
            {
                add("Code", p.What, p.What, string.Format(CultureInfo.InvariantCulture, "{0} at 0x{1:X}", p.File, p.Offset), State(p));
            }
            foreach (StringPatch sp in StringPatches)
            {
                add("Links inside the executable", sp.What, sp.What,
                    string.Format(CultureInfo.InvariantCulture, "{0} at 0x{1:X}", sp.File, sp.Offset), StringState(sp));
            }
            foreach (string rel in LinkFiles)
            {
                string name = Path.GetFileName(rel);
                add("Links", rel, "menu items in " + name + " point at your server", name, LinkState(rel));
            }
            string shown = ConnectionServer();
            if (!Ps.IsTrue(shown)) shown = SignInServer();
            if (!Ps.IsTrue(shown)) shown = "(not set)";
            add("Sign-in server", "sign-in", "ICQ signs in to your server", "now " + shown, SignInState(domain, SavedBase()));
            foreach (string f in TranslationFiles()) add("Language", "uk:" + f, "uk:" + f, f, TranslationState(f));
            foreach (string file in CodeStringFiles)
            {
                foreach (string part in new[] { "sign-in", "links" })
                {
                    string state = CodeStringState(file, part);
                    if (state != "missing") add("", part, part, file, state);
                }
            }
            return Jobs.Merge(items);
        }

        // Makes the client match the selection. Gives what changed, one line per
        // change, and the links that did not fit. Throws, before anything is
        // written, when a file that would be patched is not from build 3916.
        public Icq2003bResult ApplyAll(string domain, string previous, ICollection<string> skip)
        {
            List<string> wrong = Ps.Unique(Patches.Where(p => Jobs.IsWanted(skip, p.What) && State(p) == "other version").Select(p => p.File));
            if (wrong.Count > 0)
            {
                throw new InvalidOperationException("These files do not match ICQ Pro 2003b build 3916:\n\n  " + string.Join("\n  ", wrong) +
                    "\n\nThe code patches are tied to exact offsets in that build. Applying them to " +
                    "another version would overwrite unrelated code, so nothing was changed.");
            }
            foreach (string file in CodeStringFiles)
            {
                if ((Jobs.IsWanted(skip, "sign-in") || Jobs.IsWanted(skip, "links")) && CodeStringOtherVersion(file))
                {
                    throw new InvalidOperationException(file + " does not match ICQ Pro 2003b build 3916; nothing was changed.");
                }
            }
            List<string> binaries = BinaryFiles();
            PatchSteps.Start(binaries.Count + CodeStringFiles.Count() + 4);
            PatchSteps.Step("Checking the client...");
            List<PatchItem> before = Items(domain);

            var tooLong = new List<string>();
            bool changed = false;
            foreach (string rel in binaries)
            {
                PatchSteps.Step("Building " + rel + "...");
                if (BuildBinary(rel, domain, skip, tooLong)) changed = true;
            }
            if (changed) ClearPluginCache();
            foreach (string file in CodeStringFiles)
            {
                PatchSteps.Step("Building " + file + "...");
                SetCodeStrings(file, skip);
            }
            PatchSteps.Step("Links in DataFiles...");

            string b = Base(domain);
            foreach (string rel in LinkFiles)
            {
                string path = PatchFiles.Join(Root, rel);
                if (!PatchFiles.Exists(path)) continue;
                string backup = path + LinkSuffix;
                if (!Jobs.IsWanted(skip, rel))
                {
                    if (PatchFiles.Exists(backup)) PatchFiles.Copy(backup, path, true);
                    continue;
                }
                // Built again from the original each time, like the programs: a
                // new domain or a new target for a link then reaches a client
                // patched before, and nothing of an earlier server is left behind.
                if (!PatchFiles.Exists(backup)) PatchFiles.Copy(path, backup, false);
                string text = ConvertLinkText(File.ReadAllText(backup, Latin1), b);
                if (!Ps.Ceq(text, File.ReadAllText(path, Latin1))) File.WriteAllText(path, text, Latin1);
            }

            PatchSteps.Step("Sign-in server...");
            if (NoRegistry)
            {
            }
            else if (Jobs.IsWanted(skip, "sign-in"))
            {
                SetSignInServer(domain, previous);
            }
            else
            {
                try { RestoreSignInServer(); } catch { }
            }

            var lines = new List<string>();
            PatchSteps.Step("Checking the result...");
            List<PatchItem> after = Items(domain);
            for (int i = 0; i < after.Count; i++)
            {
                if (Ps.Eq(after[i].State, before[i].State)) continue;
                if (Ps.Eq(after[i].State, "patched")) lines.Add("applied: " + after[i].What);
                else lines.Add("taken out: " + after[i].What);
            }
            return new Icq2003bResult { Lines = lines, TooLong = tooLong };
        }

        // Puts the originals back from their backups, which stay, and gives how
        // many things were put back.
        public int RestoreAll()
        {
            int done = 0;
            List<string> binaries = Ps.Unique(BinaryFiles().Concat(CodeStringFiles));
            PatchSteps.Start(binaries.Count + LinkFiles.Length + 1);
            foreach (string f in binaries)
            {
                PatchSteps.Step("Restoring " + f + "...");
                string path = PatchFiles.Join(Root, f);
                string backup = path + BinSuffix;
                if (PatchFiles.Exists(backup)) { PatchFiles.Copy(backup, path, true); done++; }
            }
            if (done > 0) ClearPluginCache();
            foreach (string rel in LinkFiles)
            {
                PatchSteps.Step("Restoring " + rel + "...");
                string path = PatchFiles.Join(Root, rel);
                string backup = path + LinkSuffix;
                if (PatchFiles.Exists(backup)) { PatchFiles.Copy(backup, path, true); done++; }
            }
            PatchSteps.Step("Sign-in server...");
            if (!NoRegistry) done += RestoreSignInServer();
            return done;
        }
    }
}
