// What the patch for ICQ 6.5 (build 2024) changes in the client's folder.
//
// One pass does everything the client needs to live on a private server:
//
//   1. Interface. The frames left behind by services that are gone - the Xtraz
//      strip and panel, the advertising, tZers, SMS and phone buttons - are
//      taken out of the client's own markup (services\icqApp\ver1, Boxely .box
//      files, plain XML), and the "SMS & Phone" entry of the preferences list,
//      which is built in code, out of MUICore.dll.
//   2. Links. The pages the client opens on ICQ.com - help, search, "My page",
//      the About box and the legal notice, the add-on galleries, e-mail
//      confirmation, the Xtraz list - are pointed at our server over HTTPS,
//      which is also added to the client's content whitelists. They live in
//      the configuration files, in the DTDs of the interface and its
//      translations, and one in MUIMessage.dll. What the client fetched for
//      itself from the old ICQ hosts - package lists, statistics - goes
//      nowhere instead of in plain HTTP to names someone else may answer.
//   3. Advertising and teasers. Their local descriptors are emptied, which is
//      what makes the client stop drawing them at all.
//
//   4. Sign-in server. The domain replaces login.icq.com as the server the
//      client signs in to with automatic connection settings; a server typed
//      under Options -> Connection -> manual stays the user's choice. It also
//      replaces turn.oscar.aol.com as the STUN server a voice or video call
//      asks for the caller's public address - without an answer from it a
//      call fails as soon as it is picked up. With the TLS row of the E2E
//      add-on as well, the sign-in port becomes the server's TLS port, which
//      only the add-on reaches, so the client cannot sign in without it
//      (fail closed).
//   5. tZers, only when asked for: instead of taking them out, our Flash-free
//      FlashPlayerControl.dll is put in and registered for the user, and the
//      tZer list is pointed at the server (see "tZers without Flash").
//
// Every file is backed up next to itself before the first change, and
// "Restore original" puts them all back. The user's profile is never touched.
//
// Apply makes the client match the selection: what is wanted is put in, what
// is not wanted and in place is taken out again. A file with several changes
// is rebuilt from its backup with the wanted ones only, so taking one out
// leaves exactly the original behind.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace IcqRevival.Patch
{
    internal sealed class Icq65Client
    {
        public const string Suffix = ".icq6patch-backup";
        // Suffixes left by the Python tools this patch replaces. Restore puts
        // those back too, so a client patched the old way can be returned to the
        // original.
        public static readonly string[] OlderSuffixes = { ".icq6-declutter-backup", ".icq6-retarget-backup" };
        static readonly string[] AllSuffixes = new[] { Suffix }.Concat(OlderSuffixes).ToArray();

        // Only the server's domain is asked for. Ports and paths are the same on
        // every ICQ Revival server (deploy/VM-SPEC.md, section 3), so the patch
        // fills them in itself; nobody has to know which port serves what.
        // Every page and file the client gets from the server, over HTTPS (see
        // "links, whitelists, advertising"); the plain HTTP port of the same
        // pages is never written.
        const int PagesPortHttps = 8102;
        public const string SettingsKey = @"Software\OpenOSCAR\Icq6Patch";

        public const string Content = @"services\icqApp\ver1\content";
        const string Theme = @"services\icqApp\ver1\theme";

        // --- code patches ---------------------------------------------------------
        //
        // The preferences list is built in code: each group is described in .data
        // by a pointer to its records and a count, and the records - name, label
        // key, icon, panel loader, 16 bytes each - are filled in by a run of mov
        // instructions. The "Advanced" group holds Connection, SMS, Advanced. The
        // SMS record is overwritten with the one after it and the count drops to
        // two, which leaves Connection and Advanced. Blanking the record instead
        // only leaves an empty row, and zeroing a loader takes the whole dialog
        // down.

        sealed class ByteEdit
        {
            public int Offset;
            public byte[] From;
            public byte[] To;
        }

        sealed class CodePatch
        {
            public string File;
            public long Size;
            public string Sha256From;
            public string Sha256To;
            public string What;
            public ByteEdit[] Edits;
        }

        static readonly CodePatch[] CodePatches =
        {
            new CodePatch
            {
                File = "MUICore.dll",
                Size = 3359744,
                Sha256From = "EA095362283BD56BEB5015DF0C56CA8EE1687A5A254775EDDA05203A33CC9F86",
                Sha256To = "C2AA9B7578690BA53F2A6B60540D25276AF61B454AF8F80F868411264C2BEDB0",
                What = "the \"SMS & Phone\" entry of the preferences list",
                Edits = new[]
                {
                    new ByteEdit { Offset = 0x258CE4, From = new byte[] { 0x40, 0xC9, 0xA6, 0x33 }, To = new byte[] { 0x28, 0xFD, 0xA7, 0x33 } },  // name
                    new ByteEdit { Offset = 0x258CEE, From = new byte[] { 0xC4, 0xF1, 0xA7, 0x33 }, To = new byte[] { 0x38, 0xF1, 0xA7, 0x33 } },  // label key
                    new ByteEdit { Offset = 0x258CF8, From = new byte[] { 0x3C, 0xFD, 0xA7, 0x33 }, To = new byte[] { 0x10, 0xFD, 0xA7, 0x33 } },  // icon
                    new ByteEdit { Offset = 0x258D02, From = new byte[] { 0xF0, 0x5C, 0x92, 0x33 }, To = new byte[] { 0x70, 0x5E, 0x92, 0x33 } },  // loader
                    new ByteEdit { Offset = 0x2F0190, From = new byte[] { 0x03, 0x00, 0x00, 0x00 }, To = new byte[] { 0x02, 0x00, 0x00, 0x00 } },  // count
                },
            },
            // The Xtraz entries lost after the list is read again. The Xtraz
            // description manager (MISB.dll) keeps the parsed list and, apart
            // from it, the entries it has loaded - what "Change my picture"
            // and "Welcome" look up (MNXtrazUtils::IsXtraAvailable). Every
            // ReloadTimeout its Update (RVA 0x494E0) empties the loaded entries
            // and then asks the server again. A 304 or an error refills them
            // from the copy on disk; a new list (200) is found to be parsed
            // already and returns before anything is loaded, so they stay empty
            // until the client restarts and those items open the Xtraz error
            // page. The edit skips the emptying: "mov ecx, edi; jmp" to the
            // download call that follows it.
            new CodePatch
            {
                File = "MISB.dll",
                Size = 765952,
                Sha256From = "994387921C16D553A678AD5DEEE57E5CC53950DA9D16803A32A3A8B1A303815C",
                Sha256To = "1E67145222BBD50433D83FE7F695E2D3739C67BEBF435432E2C6109276DEA30A",
                What = "Xtraz items lost when the list is read again",
                Edits = new[]
                {
                    new ByteEdit { Offset = 0x4953E, From = new byte[] { 0x8B, 0x46, 0x34, 0x8B }, To = new byte[] { 0x8B, 0xCF, 0xEB, 0x23 } },
                },
            },
        };

        // --- interface -----------------------------------------------------------
        //
        // Kinds of change:
        //   collapse  mark the element with this id collapsed="true" - how the
        //             client hides its own optional parts;
        //   dropline  remove the line holding this fragment;
        //   replace   swap one exact piece of text for another.
        //
        // Some things may not be removed although they look removable: the ad
        // element of the message window is looked up by the code, and without it
        // the emoticon and formatting panels stop opening, so it is given no size
        // instead; the empty band at the foot of that window holds the same
        // panels, and the buttons above it sit on a spacer that keeps them out of
        // its way.

        enum EditKind { Collapse, DropLine, Replace }

        sealed class MarkupEdit
        {
            public string File;
            public EditKind Kind;
            public string Key;
            public string New;
            public string What;
        }

        static MarkupEdit Collapse(string file, string id, string what)
        {
            return new MarkupEdit { File = file, Kind = EditKind.Collapse, Key = id, What = what };
        }

        static MarkupEdit DropLine(string file, string fragment, string what)
        {
            return new MarkupEdit { File = file, Kind = EditKind.DropLine, Key = fragment, What = what };
        }

        static MarkupEdit Replace(string file, string from, string to, string what)
        {
            return new MarkupEdit { File = file, Kind = EditKind.Replace, Key = from, New = to, What = what };
        }

        static readonly MarkupEdit[] MarkupEdits =
        {
            Collapse(Content + @"\MUICore\MainDlgPanelOwner.box", "idXtrazBarArea", "the Xtraz strip above the contact list"),
            Collapse(Content + @"\MUICore\MainDlgPanelOwner.box", "idMainEntertainmentBox", "the Xtraz panel below the contact list"),
            Collapse(Content + @"\MUIMessage\MsgSessionPanel.box", "idBottomBannerContainer", "the banner under the message window"),
            Collapse(Content + @"\MUIMessage\MsgSessionPanel.box", "idbtnTzers", "the tZers button of the message window"),
            Collapse(Content + @"\MUIMessage\CommToolbar.box", "btnSMS", "the SMS button of the message window"),
            Collapse(Content + @"\MUIMessage\CommToolbar.box", "btnPhone", "the phone button of the message window"),
            Collapse(Content + @"\MUICore\Preferences\OPrefsPanelNotifications.box", "idXtrazInvitation", "the \"Xtraz invitations\" option"),
            Collapse(Content + @"\MUICore\Preferences\OPrefsPanelMessage.box", "idAutoPlayTzers", "the \"play tZers automatically\" option"),
            Collapse(Content + @"\MUICore\ContactList\DataBoundCL.box", "sms", "the SMS icon on a contact row"),
            Collapse(Content + @"\MUICore\ContactList\DataBoundCL.box", "phone", "the phone icon on a contact row"),
            Collapse(Content + @"\MUICore\ContactList\MiniUserProfileDlg.gadgets.box", "miniUserDetails.autoSmsContainer", "the auto-SMS line of the contact card"),
            Collapse(Content + @"\MUICore\PopupMenus.box", "idCommSendSMS", "the \"Send SMS\" item of the contact menu"),
            Collapse(Content + @"\MUICore\PopupMenus.box", "idXtrazMenu", "the Xtraz submenu of the contact menu"),
            Collapse(Content + @"\MUICore\Preferences\OPrefsPanelGeneral.box", "idAutoSmsGroup", "the auto-SMS section of the options"),
            Collapse(Content + @"\MUICore\Preferences\OPrefsPanelHistory.box", "idSaveXtrazInvitations", "the \"save Xtraz invitations\" option"),
            Collapse(Content + @"\MUICore\Preferences\OPrefsPanelSkin.box", "IncomingSMS", "the incoming-SMS sound"),
            Collapse(Content + @"\MUICore\Preferences\OPrefsPanelSkin.box", "OutgoingSMS", "the outgoing-SMS sound"),
            Collapse(Content + @"\MUICore\Preferences\OPrefsPanelSkin.box", "IncomingTzer", "the incoming-tZer sound"),
            Collapse(Content + @"\MUICore\Preferences\OPrefsPanelSkin.box", "IncomingXtra", "the incoming-Xtraz sound"),
            Collapse(Content + @"\MUICore\HistorySearchDlg.box", "idMsgTypeSMS", "the SMS filter of the history search"),
            Collapse(Content + @"\MUICore\HistorySearchDlg.box", "idMsgTypeXtrazInvitation", "the Xtraz filter of the history search"),
            DropLine(Content + @"\MUICore\MainDlg.box", "cmdMyXtraz", "the \"My Xtraz\" item of the main menu"),
            Replace(Theme + @"\MUIMessage\MsgSessionDlg.style.box",
                "<style id=\"bannerStyle\" width=\"468\" height=\"60\"",
                "<style id=\"bannerStyle\" width=\"0\" height=\"0\"",
                "the ad box of the message window"),
            Replace(Theme + @"\MUIMessage\MsgSessionDlg.style.box",
                "<part name=\"idBottomBannerContainer\" flex=\"1\" hAlign=\"center\" fill=\"url(#image.MessageDlgXtra.window.background)\"",
                "<part name=\"idBottomBannerContainer\" flex=\"1\" hAlign=\"center\"",
                "the white frame at the foot of the message window"),
            Replace(Theme + @"\MUICore\MainDlgPanelOwner.style.box",
                "<style id=\"adBoxStyle\" width=\"120\" height=\"90\" />",
                "<style id=\"adBoxStyle\" width=\"0\" height=\"0\" />",
                "the ad box of the contact list"),
            // The tab list of the "Advanced" group was 98 high inside a box of 90,
            // and the overflow covered the rounded bottom of the box. Predates the
            // SMS entry.
            Replace(Theme + @"\MUICore\Preferences\OwnerPrefsDlg.style.box",
                "<style id=\"advancedTabStyle\" height=\"98\"",
                "<style id=\"advancedTabStyle\" height=\"56\"",
                "the cut-off bottom of the \"Advanced\" group"),
        };

        // Taken out of the way whole, renamed with the backup suffix.
        sealed class Removal
        {
            public string Path;
            public string What;
        }

        static readonly Removal[] Removals =
        {
            new Removal { Path = Content + @"\MUICore\Preferences\OPrefsPanelSMS.box", What = "the page of the \"SMS & Phone\" preferences" },
            // Loaded from disk rather than from the Xtraz list, so its buttons in
            // the message window survive whatever the server answers.
            new Removal { Path = @"packages\zlango", What = "the Zlango add-on and its message window buttons" },
        };

        // --- links, whitelists, advertising -----------------------------------------
        //
        // Every page path the client has on ICQ.com, all of them on the server
        // over HTTPS. Tried on a real client: whatever it opens in a window or
        // hands to the browser - the Xtraz list and its DTD, the welcome and
        // picture windows, help and registration - works over HTTPS. What it
        // fetches itself - the Xtraz list, the country lookup, the e-mail
        // activation, the SMS number check - goes through its HTTP service
        // (MCore.dll, URL monikers over WinINet), the one the Xtraz list has
        // come through over HTTPS all along. The only loader that drops an
        // https:// address without even connecting is the one that fetches a
        // buddy picture by its address (MCore.dll, next to the BART code), and
        // no address here goes to it; the picture page hands it a plain one.
        static readonly string[] PageLinkList =
        {
            "/xtraz2/global/",             // the Xtraz list and its DTD
            "/compad/",                    // help, registration, password, report
            "/legal",                      // the legal notice
            "/download/icq6/",             // the emoticon download page
            "/xtraz/srv/",                 // the country lookup
            "/register/email_activation/", // the e-mail activation the client posts
            "/sms",                        // SMS carriers (their entries are removed)
            "/ibs/icq6/",                  // the SMS number check
        };

        // Any host in front of those paths, not only the dead ICQ.com ones: the
        // paths belong to ICQ.com services and nothing else, so a match is either
        // still ICQ.com or a server this patch pointed them at before. Moving to
        // another server is then just applying again with the new domain.
        static readonly string LinkPattern = "https?://[A-Za-z0-9.-]+(?::\\d+)?" +
            "(?=" + string.Join("|", PageLinkList.Select(Regex.Escape)) + ")";

        // What a link is pointed at, for a given domain.
        static string PagesBase(string domain)
        {
            return "https://" + domain + ":" + PagesPortHttps;
        }

        // The addresses the client parses itself on the old ICQ hosts - the
        // package lists, the statistics it reports, the configuration bundles,
        // the teaser list - are not pages, and the server has nothing to give
        // for them: any quick reply, even a 404, makes the client treat a list
        // as empty and drop part of its interface. They used to be left to
        // time out on update.icq.com, cb.icq.com and c.icq.com - in plain
        // HTTP, to names that still resolve, and whoever answers there would
        // be handed those requests. They go to a port of the client's own
        // machine where nothing listens instead: the connection is refused at
        // once, as on a dead host, and nothing leaves the machine. ICQ does
        // the same with ConfigFilesUrlFormat in System.xml.
        const string Nowhere = "http://127.0.0.1:9";

        static readonly string DeadHostPattern =
            "https?://(?:(?:update|df|c|cb)\\.icq\\.com|a?openxtraz\\.icq\\.com|a?icq\\.openxtraz\\.com)(?::\\d+)?(?=[/\"])";

        static string NoDeadHosts(string text)
        {
            return Regex.Replace(text, DeadHostPattern, Nowhere, RegexOptions.IgnoreCase);
        }

        // --- links in the interface ------------------------------------------------
        //
        // The pages the interface itself opens - search, help, "My page", the
        // About box, the add-on galleries - are not in the configuration files
        // but in the DTDs of its markup: data.dtd for the addresses, and the
        // translations under resources\<language>\ where an address is written
        // into a sentence. Each is pointed at the same page on our server,
        // under /icq on the HTTPS port. The client's own placeholders - #STRING#,
        // #NUMBER#, &#37;s - are kept as they were, since it fills them in.
        //
        // What the client fetches by itself from these DTDs (the Xtraz install
        // counter) is left alone, like the machine-fetched addresses of the
        // configuration files.

        const string Ver1 = @"services\icqApp\ver1";
        const string DataDtd = Ver1 + @"\content\data.dtd";
        const string Resources = Ver1 + @"\resources";

        sealed class DtdLink
        {
            public string File;    // relative; a "*" segment stands for every folder there
            public string Entity;  // the entity whose value is changed, or null for the whole file
            public string Find;    // what is replaced, a pattern; null for the whole value
            public string To;      // the path on our server, placeholders and all
        }

        static DtdLink Value(string entity, string to)
        {
            return new DtdLink { File = DataDtd, Entity = entity, To = to };
        }

        static DtdLink InValue(string entity, string find, string to)
        {
            return new DtdLink { File = DataDtd, Entity = entity, Find = find, To = to };
        }

        static DtdLink InText(string file, string find, string to)
        {
            return new DtdLink { File = file, Find = find, To = to };
        }

        const string XtrazStub = "/icq/stub/xtraz.html";

        static readonly DtdLink[] DtdLinks =
        {
            // "My page" in a user's details: the client appends the number.
            Value("detailsDlg.IcqHomePageLink", "/icq/whitepages?icq="),
            Value("Search.SearchLink", "/icq/search?q=#STRING#"),
            Value("Password.ForgotPassword", "/icq/password"),
            Value("MainDlg.HelpLink", "/icq/help/"),
            Value("AboutDlg.icqSite_URL", "/icq/about"),
            Value("AboutDlg.icqSite_Legal", "/icq/legal/"),
            Value("AboutDlg.icqSite_ViewTerms", "/icq/terms?lspid=#NUMBER#&amp;lang=#STRING#"),
            Value("OPrefsPanelSkin.MoreSkinsLink", "/icq/addons/skins/"),
            Value("OPrefsPanelSkin.MoreLangsLink", "/icq/addons/languages/"),
            Value("MsgSessionDlg.MoreLexiconsLink", "/icq/addons/dictionaries/"),
            Value("MoodsGallery.MoreMoodsLink", "/icq/addons/moods"),
            // Escaped HTML: only the address of its link.
            InValue("MsgSessionPanel.BirthdayMessageHTML", "http://greetings\\.icq\\.com", "/icq/greetings"),
            Value("XtraController.UserXtraDetailsUrl", XtrazStub + "?xtra_id=#STRING#"),
            Value("XtraController.UserXtraTermsOfServiceUrl", XtrazStub),
            Value("XtraController.UserXtraTermsOfServiceMoreDetailsUrl", XtrazStub),
            Value("MyXtraz.XtrazGalleryURL", XtrazStub),
            Value("MyXtraz.DevelopersSiteURL", XtrazStub),
            Value("XtraController.XtraNotAvailableUrl", XtrazStub + "?xtra_id=&#37;s&client_id=&#37;s&client_lsp_id=&#37;s&build=&#37;s"),
            // Inside translated sentences: only the address, not the words or the
            // punctuation after it ("http://www.icq.com/Download," in German).
            InText(Resources + @"\*\AboutDlg.dtd", "http://www\\.icq\\.com/legal\\b/?", "/icq/legal/"),
            // The Russian and Belarusian texts send people to ICQ's Russian site
            // instead ("http://www.icq.rambler.ru." - the dot ends the sentence).
            InText(Resources + @"\*\MsgSessionPanel.dtd", "(?i)http://www\\.icq\\.(?:com/download(?:[\\w/-]|\\.(?=[\\w/]))*|rambler\\.ru\\b/?)", "/icq/download"),
            InText(Resources + @"\*\SMS.dtd", "http://www\\.icq\\.com/sms\\b", "/icq/stub/sms.html"),
        };

        static string LinkTo(string domain, string path)
        {
            return "https://" + domain + ":" + PagesPortHttps + path;
        }

        // A text with the links of one rule pointed at the domain; as it was
        // when the rule finds nothing in it.
        static string ApplyDtdLink(DtdLink link, string text, string domain)
        {
            string to = LinkTo(domain, link.To);
            if (link.Entity == null)
            {
                return Regex.Replace(text, link.Find, m => to);
            }
            string head = "<!ENTITY " + link.Entity + " \"";
            int at = text.IndexOf(head, StringComparison.Ordinal);
            if (at < 0) return text;
            int from = at + head.Length;
            int end = text.IndexOf('"', from);
            if (end < 0) return text;
            string value = text.Substring(from, end - from);
            string changed = link.Find == null ? to : Regex.Replace(value, link.Find, m => to);
            return text.Substring(0, from) + changed + text.Substring(end);
        }

        // Every DTD some rule is for, each with its rules, in the order of the
        // table. A "*" segment is every folder there - the languages.
        List<KeyValuePair<string, List<DtdLink>>> DtdFiles()
        {
            var files = new List<KeyValuePair<string, List<DtdLink>>>();
            var index = new Dictionary<string, List<DtdLink>>(Ps.Keys);
            foreach (DtdLink link in DtdLinks)
            {
                var paths = new List<string>();
                int star = link.File.IndexOf(@"\*\", StringComparison.Ordinal);
                if (star < 0)
                {
                    paths.Add(link.File);
                }
                else
                {
                    string parent = link.File.Substring(0, star);
                    string rest = link.File.Substring(star + 3);
                    string dir = At(parent);
                    if (!Directory.Exists(dir)) continue;
                    foreach (string d in Directory.GetDirectories(dir).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                    {
                        paths.Add(parent + @"\" + Path.GetFileName(d) + @"\" + rest);
                    }
                }
                foreach (string p in paths)
                {
                    List<DtdLink> rules;
                    if (!index.TryGetValue(p, out rules))
                    {
                        rules = new List<DtdLink>();
                        index[p] = rules;
                        files.Add(new KeyValuePair<string, List<DtdLink>>(p, rules));
                    }
                    rules.Add(link);
                }
            }
            return files;
        }

        static string BuildDtd(IEnumerable<DtdLink> rules, string original, string domain)
        {
            string text = original;
            foreach (DtdLink link in rules) text = ApplyDtdLink(link, text, domain);
            return text;
        }

        // One state per DTD that has something to change, keyed by its path.
        // A file whose original none of the rules finds anything in is left
        // out: that language says nothing about ICQ.com.
        List<KeyValuePair<string, string>> DtdStates(string domain)
        {
            var result = new List<KeyValuePair<string, string>>();
            foreach (var f in DtdFiles())
            {
                string path = At(f.Key);
                if (!PatchFiles.Exists(path)) continue;
                string current = PatchFiles.ReadText(path).Text;
                string original = OriginalText(path) ?? current;
                string built = BuildDtd(f.Value, original, domain);
                if (Ps.Ceq(built, original)) continue;
                string state = Ps.Ceq(current, built) ? "patched" : Ps.Ceq(current, original) ? "original" : "partly";
                result.Add(new KeyValuePair<string, string>(f.Key, state));
            }
            return result;
        }

        // Makes every DTD match the selection, built again from its original.
        void SetDtdLinks(string domain, bool wanted)
        {
            foreach (var f in DtdFiles())
            {
                string path = At(f.Key);
                if (!PatchFiles.Exists(path)) continue;
                TextFile file = PatchFiles.ReadText(path);
                string text = OriginalText(path) ?? file.Text;
                if (wanted) text = BuildDtd(f.Value, text, domain);
                if (!Ps.Ceq(text, file.Text))
                {
                    PatchFiles.BackupOnce(path, Suffix);
                    file.Text = text;
                    PatchFiles.WriteText(path, file);
                }
            }
        }

        // --- links in code ----------------------------------------------------------
        //
        // A few addresses have their default in a DLL, as a UTF-16 string one
        // instruction pushes. They are moved the way the sign-in server is (see
        // below): the new address goes into the unused tail of .rdata, the
        // section is made to map that tail, and the push - which carries a base
        // relocation, so the loader moves it with the image - is pointed at it.
        // The old string stays where it was. The DLLs have no checksum and no
        // signature to keep valid, and each is recognised by the checksum of
        // its original before a byte is written; a changed one is always built
        // again from its backup.
        //
        // MUICore.dll's "http://icq.com" is not one of them: it is where the
        // client sets its tracking cookie (CookieContent of System.xml, with
        // the screen name and session key), not a page anyone opens.

        sealed class CodeLink
        {
            public string File;
            public long Size;
            public string Sha256From;
            public int[] Pushes;      // file offsets of the pushes' 4-byte operands
            public uint OldTarget;    // where they point out of the box
            public uint NewTarget;    // the slot, at the image base
            public int Slot;          // file offset of the slot: .rdata, past its data
            public int SlotEnd;       // end of .rdata in the file
            public int VSizeAt;       // VirtualSize of .rdata in the section table
            public uint VSizeFrom;
            public uint VSizeTo;      // all of its raw data
            public string To;         // the path on our server
            public string What;
        }

        static readonly CodeLink[] CodeLinks =
        {
            // The default of DownloadEmoticonGalleriesUrl (System.xml), the page
            // "more emoticons" opens.
            new CodeLink
            {
                File = "MUIMessage.dll",
                Size = 1305600,
                Sha256From = "8C7654D2A4A225BFD6C3B9001E82A22564EB5A9514507C0C352850865DD1701D",
                Pushes = new[] { 0xC2B0A },
                OldTarget = 0x33DFE540,   // L"http://www.icq.com/download/icq6/download_emoticons.html"
                NewTarget = 0x33E23950,   // image base 0x33D00000
                Slot = 0x122D50,
                SlotEnd = 0x122E00,       // .data starts at RVA 0x124000
                VSizeAt = 0x250,
                VSizeFrom = 0x3E94E,
                VSizeTo = 0x3EA00,
                To = "/icq/addons/emoticons",
                What = "the emoticon download page",
            },
        };

        static bool PushesAt(CodeLink c, byte[] bytes, uint target)
        {
            return c.Pushes.All(at => BitConverter.ToUInt32(bytes, at) == target);
        }

        static string ReadSlot(byte[] bytes, int slot, int slotEnd)
        {
            int end = slot;
            while (end + 1 < slotEnd && (bytes[end] != 0 || bytes[end + 1] != 0)) end += 2;
            return Encoding.Unicode.GetString(bytes, slot, end - slot);
        }

        // original / patched / another server / other version / missing
        string CodeLinkState(CodeLink c, string domain)
        {
            string path = At(c.File);
            if (!PatchFiles.Exists(path)) return "missing";
            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length != c.Size) return "other version";
            if (PushesAt(c, bytes, c.OldTarget))
            {
                return Ps.Eq(PatchFiles.Sha256(path), c.Sha256From) ? "original" : "other version";
            }
            if (PushesAt(c, bytes, c.NewTarget))
            {
                return Ps.Ceq(ReadSlot(bytes, c.Slot, c.SlotEnd), LinkTo(domain, c.To)) ? "patched" : "another server";
            }
            return "other version";
        }

        // Makes one DLL match the selection. Gives a line for the report when
        // something could not be done, or null.
        string SetCodeLink(CodeLink c, string domain, bool wanted)
        {
            string state = CodeLinkState(c, domain);
            string path = At(c.File);
            if (!wanted)
            {
                if (state == "patched" || state == "another server") RestoreFromBackup(path);
                return null;
            }
            if (state == "patched" || state == "missing") return null;
            if (state == "other version") return c.File + " is not the one from build 2024 - " + c.What + " left as it is";
            byte[] text = Encoding.Unicode.GetBytes(LinkTo(domain, c.To));
            if (text.Length + 2 > c.SlotEnd - c.Slot) return "the domain is too long for " + c.File + " - " + c.What + " left as it is";

            // From the original: the file itself, or its backup once changed.
            string source = path;
            foreach (string suffix in AllSuffixes)
            {
                if (PatchFiles.Exists(path + suffix)) { source = path + suffix; break; }
            }
            if (!Ps.Eq(PatchFiles.Sha256(source), c.Sha256From)) return "the backup of " + c.File + " is not the original - " + c.What + " left as it is";
            byte[] bytes = File.ReadAllBytes(source);
            for (int i = c.Slot; i < c.SlotEnd; i++) bytes[i] = 0;
            Array.Copy(text, 0, bytes, c.Slot, text.Length);
            Array.Copy(BitConverter.GetBytes(c.VSizeTo), 0, bytes, c.VSizeAt, 4);
            foreach (int at in c.Pushes) Array.Copy(BitConverter.GetBytes(c.NewTarget), 0, bytes, at, 4);
            PatchFiles.BackupOnce(path, Suffix);
            File.WriteAllBytes(path, bytes);
            return null;
        }

        // The links in a text that do not point where they should yet.
        static int CountStrayLinks(string text, string domain)
        {
            return Regex.Matches(text, LinkPattern, RegexOptions.IgnoreCase).Cast<Match>()
                .Count(m => !Ps.Eq(m.Value, PagesBase(domain)))
                + Regex.Matches(text, DeadHostPattern, RegexOptions.IgnoreCase).Count;
        }

        // The client draws the ad slots and the teaser strip only while these
        // list something, and without SMS carriers it has nowhere to send a text.
        // What the pattern finds is taken out, or replaced with With.
        sealed class Strip
        {
            public string File;
            public string Pattern;
            public string With = "";
            public string What;
        }

        // adConfig.xml is not the only ad list the client reads: by the user's
        // country ConfigRedirect.xml has it read adConfigRus.xml,
        // adConfigUkr.xml, adConfigUs.xml and so on in its place. Build 2024
        // comes without them, but they are what the client would ask for, and
        // they would list their own slots, with ad.mail.ru as their ad server.
        // So the redirection of adConfig.xml goes, and every country reads the
        // emptied adConfig.xml: a <redir> left with nothing else goes whole -
        // a country not listed, like most - and from the one that also
        // redirects another file only that line goes. The ad servers
        // (ar.atwola.com, im.adtech.de) go nowhere as well, like the old ICQ
        // hosts: with no slot they are never asked, and then nothing in the
        // files names them either.
        const string AdRedirect = "<file\\s+name=\"adConfig\\.xml\"[^>]*/>";

        static readonly Strip[] Strips =
        {
            new Strip { File = @"ConfigFiles\adConfig.xml", Pattern = "[ \\t]*<spot\\b[^>]*/>[ \\t]*\\r?\\n?", What = "advertising slots" },
            new Strip { File = @"ConfigFiles\adConfig.xml", Pattern = "(?<=<server\\b[^>]*\\surl=\")(?!" + Regex.Escape(Nowhere) + "\")[^\"]+", With = Nowhere, What = "ad servers" },
            new Strip {
                File = @"ConfigFiles\ConfigRedirect.xml",
                Pattern = "[ \\t]*<redir>\\s*<country\\b[^>]*/>\\s*" + AdRedirect + "\\s*</redir>[ \\t]*\\r?\\n?|[ \\t]*" + AdRedirect + "[ \\t]*\\r?\\n?",
                What = "the advertising of each country" },
            new Strip { File = @"ConfigFiles\tzer.xml", Pattern = "[ \\t]*<tz\\b[^>]*/>[ \\t]*\\r?\\n?", What = "the teaser strip" },
            new Strip { File = @"ConfigFiles\SMSConfig.xml", Pattern = "[ \\t]*<i n=\"operator\"[^>]*/>[ \\t]*\\r?\\n?", What = "SMS carriers" },
        };

        // --- tZers without Flash ---------------------------------------------------
        //
        // ICQ 6.5 plays tZers through FlashPlayerControl.dll, a wrapper around
        // the Adobe Flash ActiveX control, which no longer exists. The job puts
        // three things in place, and takes them out again:
        //
        //   1. Our FlashPlayerControl.dll (tools\icq65\flashplayer, on Ruffle)
        //      over the original. The patch does not carry it - fifteen
        //      megabytes - but takes FlashPlayerControl-Ruffle.dll from next to
        //      its exe, or -Player: under its own name, so a patch dropped into
        //      the ICQ folder does not find it in place of the original. Ours
        //      is told by its version resource, the original by its checksum.
        //   2. The Flash type library of that DLL, registered for the user by
        //      its own DllRegisterServer: the client's event sinks look it up
        //      (LoadRegTypeLib) and get no events without it. The DLL is 32-bit
        //      and the patch may run as 64-bit, so the 32-bit regsvr32 does it.
        //      It writes HKCU only - TypeLib\{D27CDB6B-...}\1.0 and the
        //      Interface keys of IShockwaveFlash and its events - and stores
        //      the DLL's full path. Only one such registration exists per user.
        //   3. tzer.xml pointed at the tZers the server has (/icq/tzers/, from
        //      deploy/oscar-legacy-web/tzers), with only those listed, and the
        //      server let in by the list's whitelist. The buttons show the
        //      thumbnails the client comes with (theme\IMAGES\tzer); it fetches
        //      baseurl + thumb only for one missing there. The list has one
        //      base for thumbnails and movies, over HTTPS; our DLL fetches the
        //      movie from there with WinINet. A receiving client plays the
        //      address the sender's list gave.
        //
        // It is the rival of the "tzers" job, which takes the tZers out of the
        // interface: with the player the button, the option and the sound stay.

        public const string PlayerFile = "FlashPlayerControl.dll";
        // Our DLL as it is handed out, next to the patch.
        public const string PlayerShipped = "FlashPlayerControl-Ruffle.dll";
        const string PlayerSha256Original = "00F9EB5B63BEC2EEB3578DC7BCE6192F5EF4C455B48E55747F7D8F39ED1BAA9C";
        // What our DLL says in its version resource (typelib\resource.rc).
        const string PlayerProduct = "ICQ Revival";
        const string PlayerInternalName = "FlashPlayerControl-Ruffle";
        const string TzerList = @"ConfigFiles\tzer.xml";
        const string TzersPath = "/icq/tzers";
        // The tZers the server has, by the name of their files: the list the
        // client is given keeps these and drops any other.
        static readonly string[] ServedTzers =
        {
            "gangsta", "canthearu", "skratch", "boo", "kisses", "chillout",
            "akitaka", "laugh", "duh", "beback", "likeu", "sorry",
        };
        const string FlashTypeLib = @"Software\Classes\TypeLib\{D27CDB6B-AE6D-11CF-96B8-444553540000}\1.0\0\win32";
        const string FlashClass = @"Software\Classes\CLSID\{D27CDB6E-AE6D-11cf-96B8-444553540000}\InprocServer32";

        // Our DLL to put in: next to the patch unless given.
        public string PlayerSource;

        public static string DefaultPlayerSource()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, PlayerShipped);
        }

        static bool IsOurPlayer(string path)
        {
            if (!File.Exists(path)) return false;
            try
            {
                var v = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
                return v.ProductName == PlayerProduct && v.InternalName == PlayerInternalName;
            }
            catch { return false; }
        }

        // Why our DLL cannot be put in, or null when it can.
        string PlayerMissing()
        {
            if (string.IsNullOrEmpty(PlayerSource) || !File.Exists(PlayerSource))
            {
                return "no " + Path.GetFileName(PlayerSource ?? PlayerShipped) + " next to the patch";
            }
            if (!IsOurPlayer(PlayerSource)) return Path.GetFileName(PlayerSource) + " is not the tZers player";
            return null;
        }

        static bool SameFile(string a, string b)
        {
            return Ps.Eq(Path.GetFullPath(a), Path.GetFullPath(b));
        }

        // original / patched / unavailable / other version / missing. Ours in
        // place, but another build than the one to put in, is "original":
        // Apply puts that one in.
        string PlayerState()
        {
            string path = At(PlayerFile);
            if (!PatchFiles.Exists(path)) return "missing";
            if (IsOurPlayer(path))
            {
                if (PlayerMissing() != null || SameFile(path, PlayerSource)) return "patched";
                return Ps.Eq(PatchFiles.Sha256(path), PatchFiles.Sha256(PlayerSource)) ? "patched" : "original";
            }
            if (!Ps.Eq(PatchFiles.Sha256(path), PlayerSha256Original)) return "other version";
            return PlayerMissing() != null ? "unavailable" : "original";
        }

        // The DLL the Flash type library is registered to for this user, or null.
        static string RegisteredTypeLib()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(FlashTypeLib))
                {
                    return key == null ? null : key.GetValue("") as string;
                }
            }
            catch { return null; }
        }

        // The DLL the ShockwaveFlash control class is registered to for this
        // user, as the 32-bit client sees it, or null. The player registers
        // that class too, so ICQ's own Flash gadgets - the animated avatars -
        // create it.
        static string RegisteredFlashClass()
        {
            try
            {
                using (var root = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry32))
                using (var key = root.OpenSubKey(FlashClass))
                {
                    return key == null ? null : key.GetValue("") as string;
                }
            }
            catch { return null; }
        }

        // Both registrations - the type library and the control class - point
        // at the client's player.
        bool TypeLibIsOurs()
        {
            string dll = RegisteredTypeLib();
            string cls = RegisteredFlashClass();
            return !string.IsNullOrEmpty(dll) && SameFile(dll, At(PlayerFile))
                && !string.IsNullOrEmpty(cls) && SameFile(cls, At(PlayerFile));
        }

        string TypeLibState()
        {
            if (!PatchFiles.Exists(At(PlayerFile))) return "missing";
            return IsOurPlayer(At(PlayerFile)) && TypeLibIsOurs() ? "patched" : "original";
        }

        static string TzerBase(string domain)
        {
            return "https://" + domain + ":" + PagesPortHttps + TzersPath;
        }

        const string BaseUrlPattern = "(<R\\b[^>]*\\bbaseurl=\")([^\"]*)(\")";

        // The list with its base on the server, only the tZers the server has,
        // and the server let in.
        static string BuildTzerList(string text, string domain)
        {
            text = Regex.Replace(text, BaseUrlPattern, m => m.Groups[1].Value + TzerBase(domain) + m.Groups[3].Value);
            text = Regex.Replace(text, "[ \\t]*<tz\\b[^>]*/>[ \\t]*\\r?\\n?", m =>
            {
                Match url = Regex.Match(m.Value, "\\burl=\"/?([^\"/]*)\\.swf\"");
                return url.Success && Ps.Contains(ServedTzers, url.Groups[1].Value) ? m.Value : "";
            });
            return AddWhitelisted("tzer.xml", text, domain);
        }

        string TzerListState(string domain)
        {
            string path = At(TzerList);
            if (!PatchFiles.Exists(path)) return "missing";
            Match m = Regex.Match(PatchFiles.ReadText(path).Text, BaseUrlPattern);
            if (!m.Success) return "unknown";
            if (Ps.Eq(m.Groups[2].Value, TzerBase(domain))) return "patched";
            return m.Groups[2].Value.EndsWith(TzersPath, StringComparison.OrdinalIgnoreCase) ? "another server" : "original";
        }

        // The 32-bit regsvr32 on the DLL; its exit code, or -1 when it did not
        // finish. 0 is success.
        static int Regsvr32(string dll, bool unregister)
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string exe = Path.Combine(windows, Environment.Is64BitOperatingSystem ? "SysWOW64" : "System32", "regsvr32.exe");
            var info = new System.Diagnostics.ProcessStartInfo(exe, (unregister ? "/s /u " : "/s ") + "\"" + dll + "\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            try
            {
                using (var p = System.Diagnostics.Process.Start(info))
                {
                    if (p.WaitForExit(60000)) return p.ExitCode;
                    try { p.Kill(); } catch { }
                    return -1;
                }
            }
            catch (Exception e) when (e is System.ComponentModel.Win32Exception || e is InvalidOperationException)
            {
                return -1;
            }
        }

        // Takes the type library registration away from our DLL, if it is ours
        // and registered there. A line for the report when that failed, or null.
        string UnregisterPlayer()
        {
            string path = At(PlayerFile);
            string dll = RegisteredTypeLib(), cls = RegisteredFlashClass();
            bool ours = (!string.IsNullOrEmpty(dll) && SameFile(dll, path)) || (!string.IsNullOrEmpty(cls) && SameFile(cls, path));
            if (!IsOurPlayer(path) || !ours) return null;
            int code = Regsvr32(path, true);
            return code == 0 ? null : "the Flash type library could not be unregistered (regsvr32 exit code " + code + ")";
        }

        // The still pictures ICQ 6.5 keeps of the animated avatars it has
        // shown, %APPDATA%\ICQ\BART\613\<hash of the avatar>, next to the
        // avatars themselves in BART\8. The player that is in place draws them,
        // and the client keeps them for good: the ones an earlier build of ours
        // drew stay upside down or squeezed, and the original Flash drew none.
        // Whenever the player changes they go, and the client draws them again
        // from the avatars the next time it shows them. The avatars stay.
        static void ClearFlashSnapshots()
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ICQ", "BART", "613");
            if (!Directory.Exists(dir)) return;
            foreach (string file in Directory.GetFiles(dir))
            {
                try { File.Delete(file); } catch { }
            }
        }

        // Makes the DLL and its registration match the selection (the list is
        // done with the other configuration files). A line for the report when
        // something could not be done, or null.
        string SetPlayer(bool wanted)
        {
            string path = At(PlayerFile);
            string state = PlayerState();
            if (!wanted)
            {
                // Ours without a backup was not put there by the patch: it
                // stays, registered or not.
                if (!IsOurPlayer(path) || !AllSuffixes.Any(x => PatchFiles.Exists(path + x))) return null;
                string note = UnregisterPlayer();
                RestoreFromBackup(path);
                ClearFlashSnapshots();
                return note;
            }
            if (state == "missing") return PlayerFile + " is not in the client - tZers player left out";
            if (state == "other version") return PlayerFile + " is neither the one from build 2024 nor the tZers player - tZers player left out";
            if (state == "original")
            {
                if (!IsOurPlayer(path)) PatchFiles.BackupOnce(path, Suffix);
                PatchFiles.Copy(PlayerSource, path, true);
                ClearFlashSnapshots();
            }
            if (!IsOurPlayer(path)) return PlayerFile + " could not be put in - tZers player left out";
            if (!TypeLibIsOurs())
            {
                int code = Regsvr32(path, false);
                if (code != 0) return "the Flash type library could not be registered (regsvr32 exit code " + code + ") - tZers will not play";
            }
            return null;
        }

        // --- E2E add-on (stage 3, end-to-end encryption) -----------------------------
        //
        // The end-to-end-encryption add-on: a DLL that hooks the client's own
        // Winsock calls in coolcore49.dll, reassembles FLAP and encrypts the
        // text of every instant message to the recipient's device, with the
        // keys the server's key directory hands out. The rewriting harness of
        // the earlier phase is still there for transport checks and for the
        // log-only first phase (ICQE2E_MODE=observe); ICQE2E_PEERS limits
        // rewriting and encryption to some contacts. Decoded messages go to
        // the file named by the ICQE2E_LOG environment variable. See
        // tools\icq-e2e.
        //
        // ICQ 6.5 has no free load slot of its own, so the add-on ships as a
        // proxy msimg32.dll: MUtils.dll (loaded at process init) statically
        // imports msimg32, which is not a KnownDLL, so a copy in the ICQ folder
        // loads before any BOS connection. It forwards the real msimg32 exports
        // to system32 and installs the hooks. This job, off unless chosen, puts
        // the DLL in; "Restore original" takes it out (there is no stock
        // msimg32.dll in the folder, so ours is simply removed).
        //
        // The patch does not carry the DLL; it takes Icqe2eProbe-msimg32.dll from
        // next to its exe (gitignored, owner-only test build). Ours is told by
        // its version resource.

        public const string E2eProbeFile = "msimg32.dll";
        // Where the add-on is told the key directory's URL: an ini file next to
        // the client executable, which the patch writes when it puts the add-on
        // in and takes away when it takes it out. The add-on looks for exactly
        // this name beside its own executable (tools\icq-e2e\core\src\config.rs),
        // so it needs no environment variable; ICQE2E_INI only overrides where
        // it looks. Nothing is hardcoded here, the domain is the one this
        // installation was configured with.
        public const string E2eIniFile = E2eIni.FileName;
        // The first line of the ini, which says in as many words that the patch
        // wrote it. It is what tells our own file from one that was in the
        // folder before we came, so that applying again - with another domain -
        // does not copy our own text aside as though it were the user's, and
        // "Restore original" does not put it back. The add-on skips every line
        // beginning with "#" (tools\icq-e2e\core\src\config.rs), so the line
        // costs it nothing.
        const string E2eIniHeader = "# written by the ICQ 6.5 patch; ICQE2E_DIRECTORY overrides it";

        // The key directory's base URL, from the domain of this installation.
        // The port and the path are the same on every ICQ Revival server
        // (deploy/VM-SPEC.md, section 3), so the patch fills them in itself.
        static string E2eDirectoryUrl(string domain)
        {
            return "https://" + domain + ":" + PagesPortHttps + "/e2e/v1/";
        }

        // What goes in the ini, and which lines of it are the patch's own, is
        // E2eIni (in Common): directory, server, and e2e and tls for the two
        // rows; every other line the user put there stays. server = the domain,
        // and only the domain: the add-on resolves it, sends every connection
        // the client makes to it on the plain ports (5190 FLAP, 8082 HTTP
        // sign-in) to the server's TLS 1.3 port instead, and checks the
        // certificate against that name. The TLS port is the add-on's own
        // constant (tools\icq-e2e\core\src\route.rs), so nothing but the domain
        // is asked for here (docs\e2e\STAGE-TLS.md, T4).

        // What the ini file there says, or null when there is none or it cannot
        // be read.
        static string E2eIniAt(string path)
        {
            try { return File.Exists(path) ? PatchFiles.ReadText(path).Text : null; }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                PatchFiles.Error(e.Message);
                return null;
            }
        }

        // Whether the ini there is the one this patch wrote, told by its header.
        bool E2eIniIsOurs()
        {
            string text = E2eIniAt(At(E2eIniFile));
            return text != null && text.StartsWith(E2eIniHeader, StringComparison.Ordinal);
        }

        // Writes the ini next to the client, and keeps whatever was there
        // before under the backup suffix first: the patch takes files out as
        // well as puts them in, and "Restore original" must leave the folder as
        // it found it. A file that is already ours is not backed up again - it
        // is simply overwritten - so the copy beside it stays the user's file,
        // whatever the domain changes to. The lines the user added are kept,
        // only the patch's own are set. Nothing is written when the text is
        // already what would be written, so applying twice in a row changes
        // nothing and reports nothing.
        void WriteE2eIni(string domain, bool e2e, bool tls, bool calls)
        {
            string path = At(E2eIniFile);
            string current = E2eIniAt(path);
            string text = E2eIni.Compose(E2eIniHeader, current, E2eDirectoryUrl(domain), domain, e2e, tls, calls);
            if (current != null && Ps.Ceq(current, text)) return;
            if (current != null && !E2eIniIsOurs()) PatchFiles.BackupOnce(path, Suffix);
            try
            {
                // UTF-8 without a byte order mark: ReadText reads it back byte for
                // byte, so a re-run sees the same text it wrote.
                File.WriteAllText(path, text, new UTF8Encoding(false));
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                PatchFiles.Error(e.Message);
            }
        }

        // Takes the ini away again, leaving the folder as it was found. A copy
        // beside it under a backup suffix is a file that was there before the
        // patch wrote over it - and only ever that, since a file the patch wrote
        // is recognised as its own and not copied aside - so that copy goes
        // back. With no copy the file in place is the patch's own writing and is
        // simply removed. An ini the patch did not write and has no copy of is
        // left alone.
        bool RemoveE2eIni()
        {
            string path = At(E2eIniFile);
            if (!PatchFiles.Exists(path) && !AllSuffixes.Any(x => PatchFiles.Exists(path + x))) return false;
            bool saved = AllSuffixes.Any(x => PatchFiles.Exists(path + x));
            if (saved) RestoreFromBackup(path);
            else if (E2eIniIsOurs()) PatchFiles.Remove(path);
            else return false;
            foreach (string suffix in AllSuffixes) PatchFiles.Remove(path + suffix);
            return !PatchFiles.Exists(path);
        }

        // The state of one of the E2E rows (E2eIni.Jobs): patched when our DLL
        // is in place and current and the ini - ours, for this domain - has the
        // row's setting on; unavailable without our DLL to put in; original
        // otherwise. A file that should be there and is not is "original", not
        // "missing", which folding the rows would drop.
        string E2eRowState(string job, string domain)
        {
            string dll = E2eState();
            if (dll != "patched") return dll;
            string text = E2eIniIsOurs() ? E2eIniAt(At(E2eIniFile)) : null;
            if (text == null || !E2eIni.Points(text, E2eDirectoryUrl(domain), domain)) return "original";
            bool on = job == E2eIni.E2eJob ? E2eIni.E2eOn(text)
                : job == E2eIni.TlsJob ? E2eIni.TlsOn(text)
                : E2eIni.CallsOn(text);
            return on ? "patched" : "original";
        }

        // Our DLL as it is handed out, next to the patch.
        public const string E2eProbeShipped = "Icqe2eProbe-msimg32.dll";
        // What our DLL says in its version resource (tools\icq-e2e\loader-msimg32\resource.rc).
        const string E2eProduct = "ICQ Revival";
        const string E2eInternalName = "ICQ-E2E-Probe";

        // Our DLL to put in: next to the patch unless given.
        public string E2eSource;

        public static string DefaultE2eSource()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, E2eProbeShipped);
        }

        static bool IsOurE2e(string path)
        {
            if (!File.Exists(path)) return false;
            try
            {
                var v = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
                return v.ProductName == E2eProduct && v.InternalName == E2eInternalName;
            }
            catch { return false; }
        }

        // Why our DLL cannot be put in, or null when it can.
        string E2eMissing()
        {
            if (string.IsNullOrEmpty(E2eSource) || !File.Exists(E2eSource))
            {
                return "no " + Path.GetFileName(E2eSource ?? E2eProbeShipped) + " next to the patch";
            }
            if (!IsOurE2e(E2eSource)) return Path.GetFileName(E2eSource) + " is not the E2E add-on";
            return null;
        }

        // patched (ours in place) / original (can be put in) / unavailable.
        string E2eState()
        {
            string path = At(E2eProbeFile);
            if (IsOurE2e(path))
            {
                if (E2eMissing() != null || SameFile(path, E2eSource)) return "patched";
                return Ps.Eq(PatchFiles.Sha256(path), PatchFiles.Sha256(E2eSource)) ? "patched" : "original";
            }
            return E2eMissing() != null ? "unavailable" : "original";
        }

        // Makes msimg32.dll and the ini next to it match the selection. The ini
        // is written only once the DLL is really in place, and taken away with
        // it, so an add-on that could not be put in never leaves one behind. A
        // line for the report when it could not be done, or null.
        //
        // Both rows need the DLL: it goes in when either is ticked, and stays as
        // long as one of them is; the ini then says which of the two it does.
        // The row for calls only adds calls_encrypt= to that, so it does not
        // put the DLL in by itself.
        string SetE2e(bool e2e, bool tls, bool calls, string domain)
        {
            bool wanted = e2e || tls;
            string path = At(E2eProbeFile);
            if (!wanted)
            {
                RemoveE2eIni();
                if (!IsOurE2e(path)) return null;
                // A stock msimg32 is not shipped in the folder, so ours normally
                // has no backup: just remove it. If some foreign file was backed
                // up first, put it back.
                if (PatchFiles.Exists(path + Suffix)) PatchFiles.Copy(path + Suffix, path, true);
                else PatchFiles.Discard(path);
                return null;
            }
            string miss = E2eMissing();
            if (miss != null) return "E2E add-on left out: " + miss;
            if (!IsOurE2e(path))
            {
                if (PatchFiles.Exists(path) && !AllSuffixes.Any(x => PatchFiles.Exists(path + x))) PatchFiles.BackupOnce(path, Suffix);
                PatchFiles.Copy(E2eSource, path, true);
            }
            else if (!SameFile(path, E2eSource) && !Ps.Eq(PatchFiles.Sha256(path), PatchFiles.Sha256(E2eSource)))
            {
                PatchFiles.Copy(E2eSource, path, true);
            }
            if (!IsOurE2e(path)) return E2eProbeFile + " could not be put in - E2E add-on left out";
            WriteE2eIni(domain, e2e, tls, calls);
            return calls && !e2e ? "encryption of calls left out: it needs end-to-end encryption of messages" : null;
        }

        // --- the dropped E2E lock button (CHECKLIST 10.9) -------------------------
        //
        // An earlier build put a lock among the buttons under the input box of
        // the message window, with the E2E add-on. It was tried and dropped:
        // the window's markup does not tell a script which contact a chat is
        // with, so the button could show no state, and sending "/e2e status"
        // from its script was unreliable - it sent the draft instead. Its
        // markup edits go with every Apply, since each file is built again from
        // its original; its script and pictures, files the client never had,
        // are taken out here, by every name a build ever gave them
        // (DroppedFiles, in Common).

        const string DroppedLockImages = Theme + @"\IMAGES\Common\IcqIcons\SpecificIcons\";

        static readonly string[] DroppedLockFiles =
        {
            Content + @"\MUIMessage\e2eLock.js",
            DroppedLockImages + @"MessageDlg\icon-e2e.png",
            DroppedLockImages + @"MessageDlg\icon-e2e-on.png",
            DroppedLockImages + @"MessageDlg\icon-e2e-off.png",
            DroppedLockImages + @"MessageDlg\icon-e2e-none.png",
            DroppedLockImages + @"MessageDlg\icon-e2e-held.png",
            DroppedLockImages + @"GeneralIcons\list-msg-e2e.png",
        };

        // Takes the lock button's files out; how many there were.
        int TakeDroppedLockFiles()
        {
            return DroppedFiles.TakeAll(Root, DroppedLockFiles, AllSuffixes);
        }

        // --- sign-in server --------------------------------------------------------
        //
        // With automatic connection settings ICQ 6.5 signs in to ServerHostName of
        // its ConnectionSettings, and the default for it is not in any
        // configuration file: MCore.dll builds it in code, from a UTF-16 string
        // "login.icq.com" that one instruction pushes before SysAllocString.
        // (ConfigFiles\Defaults\App.xml holds defaults for the App set only; a
        // ServerHostName there is ignored - tried.)
        //
        // The string cannot be replaced in place - thirteen characters is too
        // short for a domain - so the domain goes into the unused tail of .rdata,
        // the section is made to map that tail, and the one push is pointed at it.
        // login.icq.com stays where it was, untouched. The push carries a base
        // relocation, so the loader moves the new address along with the image
        // like the old one. The DLL has no checksum and no signature to keep valid.
        //
        // The STUN server of calls is the same domain. Its default,
        // "turn.oscar.aol.com", is pushed the same way in two places, and both are
        // pointed at the same slot.
        //
        // The port of the sign-in is the default of ServerPort, registered next
        // to ServerHostName in the same function: 5190, an immediate stored on
        // the stack (mov dword [esp+44h], 1446h). With the TLS row ticked as
        // well it becomes E2eIni.TlsPort (5194), where the server speaks TLS
        // only: the E2E add-on maps it to TLS, and a client without the add-on
        // cannot sign in at all instead of signing in in plaintext (fail
        // closed). The BOS host the server hands out next is the plain
        // domain:5190, which the add-on maps to TLS as well; a client without
        // it never gets that far. The other 5190 of MCore.dll is the port of
        // ars.oscar.aol.com, not the sign-in, and stays.

        static class SignIn
        {
            public const string File = "MCore.dll";
            public const long Size = 2349568;
            public const string Sha256From = "939847F9118F8059223729BDFF7FF174C1BF45840CA2BB3A9DD4A415E669587B";
            public const int PushImm = 0x4572;          // push offset "login.icq.com" - its 4-byte operand
            public const uint OldTarget = 0x320B2878;   // where it points out of the box
            public const uint NewTarget = 0x32108664;   // the slot below, at image base 0x31F00000
            public const int Slot = 0x207064;           // file offset of the slot: .rdata, past its data
            public const int SlotEnd = 0x207200;        // end of .rdata in the file
            public const int VSizeAt = 0x258;           // VirtualSize of .rdata in the section table
            public const uint VSizeFrom = 0x57662;
            public const uint VSizeTo = 0x57800;        // all of its raw data; .data starts at 0x209000
            public static readonly int[] StunPushes = { 0x8E2B3, 0x1764CD }; // push offset "turn.oscar.aol.com" - their operands
            public const uint StunTarget = 0x320BB7C8;  // where they point out of the box
            public const int PortImm = 0x464E;          // mov dword [esp+44h], 5190 - the ServerPort default, its operand
            public const uint PortOriginal = 5190;
        }

        static uint PortAt(byte[] bytes)
        {
            return BitConverter.ToUInt32(bytes, SignIn.PortImm);
        }

        // The bytes with the sign-in port set to this one.
        static byte[] WithPort(byte[] bytes, uint port)
        {
            byte[] copy = (byte[])bytes.Clone();
            Array.Copy(BitConverter.GetBytes(port), 0, copy, SignIn.PortImm, 4);
            return copy;
        }

        public string Root;

        public Icq65Client(string root, string player = null, string e2e = null)
        {
            Root = root;
            PlayerSource = string.IsNullOrEmpty(player) ? DefaultPlayerSource() : Path.GetFullPath(player);
            E2eSource = string.IsNullOrEmpty(e2e) ? DefaultE2eSource() : Path.GetFullPath(e2e);
        }

        string At(string relative) { return PatchFiles.Join(Root, relative); }

        static bool StunPushesAt(byte[] bytes, uint target)
        {
            foreach (int at in SignIn.StunPushes)
            {
                if (BitConverter.ToUInt32(bytes, at) != target) return false;
            }
            return true;
        }

        static string ReadSlotDomain(byte[] bytes)
        {
            int end = SignIn.Slot;
            while (end + 1 < SignIn.SlotEnd && (bytes[end] != 0 || bytes[end + 1] != 0)) end += 2;
            return Encoding.Unicode.GetString(bytes, SignIn.Slot, end - SignIn.Slot);
        }

        // original / patched / another server / other version / missing
        string SignInState(string domain)
        {
            string path = At(SignIn.File);
            if (!PatchFiles.Exists(path)) return "missing";
            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length != SignIn.Size) return "other version";
            uint target = BitConverter.ToUInt32(bytes, SignIn.PushImm);
            if (target == SignIn.OldTarget)
            {
                return Ps.Eq(PatchFiles.Sha256(path), SignIn.Sha256From) ? "original" : "other version";
            }
            if (target == SignIn.NewTarget)
            {
                // Patched before calls were: the STUN server is still AOL's.
                return Ps.Eq(ReadSlotDomain(bytes), domain) && StunPushesAt(bytes, SignIn.NewTarget) ? "patched" : "another server";
            }
            return "other version";
        }

        string SignInShown()
        {
            string path = At(SignIn.File);
            if (!PatchFiles.Exists(path)) return "";
            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length != SignIn.Size) return "";
            if (BitConverter.ToUInt32(bytes, SignIn.PushImm) == SignIn.NewTarget) return ReadSlotDomain(bytes);
            return "login.icq.com";
        }

        // The TLS row's part of MCore.dll: patched when the sign-in is ours and
        // its port is the TLS one; missing - not counted in the row - when the
        // sign-in is not ours, since the port follows the sign-in row.
        string SignInPortState(string domain)
        {
            if (SignInState(domain) != "patched") return "missing";
            uint port = PortAt(File.ReadAllBytes(At(SignIn.File)));
            if (port == (uint)E2eIni.TlsPort) return "patched";
            return port == SignIn.PortOriginal ? "original" : "other version";
        }

        // Points the sign-in at the domain, on the TLS-only port when tls is
        // set and on the original one otherwise. Gives a line for the report,
        // or null when there was nothing to do.
        string SetSignIn(string domain, bool tls)
        {
            string state = SignInState(domain);
            if (state == "missing") return null;
            if (state == "other version") return "MCore.dll is not the one from build 2024 - sign-in server left as it is";
            byte[] text = Encoding.Unicode.GetBytes(domain);
            if (text.Length + 2 > SignIn.SlotEnd - SignIn.Slot) return "the domain is too long for MCore.dll - sign-in server left as it is";

            string path = At(SignIn.File);
            byte[] current = File.ReadAllBytes(path);
            byte[] bytes = WithPort(current, tls ? (uint)E2eIni.TlsPort : SignIn.PortOriginal);
            if (state != "patched")
            {
                for (int i = SignIn.Slot; i < SignIn.SlotEnd; i++) bytes[i] = 0;
                Array.Copy(text, 0, bytes, SignIn.Slot, text.Length);
                Array.Copy(BitConverter.GetBytes(SignIn.VSizeTo), 0, bytes, SignIn.VSizeAt, 4);
                foreach (int at in new[] { SignIn.PushImm }.Concat(SignIn.StunPushes))
                {
                    Array.Copy(BitConverter.GetBytes(SignIn.NewTarget), 0, bytes, at, 4);
                }
            }
            if (bytes.SequenceEqual(current)) return null;
            PatchFiles.BackupOnce(path, Suffix);
            File.WriteAllBytes(path, bytes);
            return "the client signs in to " + domain + ":" + PortAt(bytes);
        }

        // --- the edits themselves ---------------------------------------------------

        static Match FindTag(string text, string id)
        {
            return Regex.Match(text, "<[A-Za-z][^<>]*\\bid=\"" + Regex.Escape(id) + "\"[^<>]*>");
        }

        // Gives the changed text, or null when there is nothing to change.
        static string ApplyEdit(MarkupEdit edit, string text)
        {
            switch (edit.Kind)
            {
                case EditKind.Collapse:
                    {
                        Match tag = FindTag(text, edit.Key);
                        if (!tag.Success) return null;
                        string old = tag.Value;
                        if (Ps.Match(old, "\\bcollapsed=\"true\"")) return null;
                        string changed = Regex.Replace(old, "\\bcollapsed=\"[^\"]*\"", "");
                        changed = changed.TrimEnd('>').TrimEnd('/').TrimEnd();
                        changed += " collapsed=\"true\"" + (old.TrimEnd().EndsWith("/>") ? "/>" : ">");
                        return text.Substring(0, tag.Index) + changed + text.Substring(tag.Index + tag.Length);
                    }
                case EditKind.DropLine:
                    {
                        string[] lines = Ps.Split(text, "\n");
                        string[] keep = lines.Where(l => !l.Contains(edit.Key)).ToArray();
                        if (keep.Length == lines.Length) return null;
                        return string.Join("\n", keep);
                    }
                case EditKind.Replace:
                    {
                        int at = text.IndexOf(edit.Key, StringComparison.Ordinal);
                        if (at < 0) return null;
                        return text.Substring(0, at) + edit.New + text.Substring(at + edit.Key.Length);
                    }
            }
            return null;
        }

        string EditState(MarkupEdit edit)
        {
            string path = At(edit.File);
            if (!PatchFiles.Exists(path)) return "missing";
            string text = PatchFiles.ReadText(path).Text;
            switch (edit.Kind)
            {
                case EditKind.Collapse:
                    {
                        Match tag = FindTag(text, edit.Key);
                        if (!tag.Success) return "unknown";
                        return Ps.Match(tag.Value, "\\bcollapsed=\"true\"") ? "patched" : "original";
                    }
                case EditKind.DropLine:
                    return text.Contains(edit.Key) ? "original" : "patched";
                case EditKind.Replace:
                    // The original first: where the change only trims the end of a
                    // line, the new text is a prefix of the old one and is found
                    // inside the untouched file too.
                    if (text.Contains(edit.Key)) return "original";
                    if (text.Contains(edit.New)) return "patched";
                    return "unknown";
            }
            return null;
        }

        string RemovalState(Removal r)
        {
            string path = At(r.Path);
            bool gone = !PatchFiles.Exists(path);
            bool saved = AllSuffixes.Any(s => PatchFiles.Exists(path + s));
            if (gone && saved) return "patched";
            if (!gone) return "original";
            return "missing";
        }

        // The offsets are only right for this build, so the whole file is
        // identified by its checksum before a byte is written.
        string CodeState(CodePatch patch)
        {
            string path = At(patch.File);
            if (!PatchFiles.Exists(path)) return "missing";
            string hash = PatchFiles.Sha256(path);
            if (Ps.Eq(hash, patch.Sha256To)) return "patched";
            if (Ps.Eq(hash, patch.Sha256From)) return "original";
            return "other version";
        }

        // --- configuration state ------------------------------------------------------

        // Whether a host is already on a whitelist. The lists themselves are
        // checked, not the whole file: by the time they are, the links in the
        // same file already point at the host, and a plain search would find
        // those instead.
        static bool IsWhitelisted(string name, string text, string host)
        {
            if (Ps.Eq(name, "XtraConfig.xml"))
            {
                Match m = Regex.Match(text, "Key=\"WhiteDomainList\" Value=\"([^\"]*)\"");
                return m.Success && Ps.Contains(Ps.Split(m.Groups[1].Value, "\\s+"), host);
            }
            Match w = Regex.Match(text, "(?s)<whitelist>(.*?)</whitelist>");
            return w.Success && w.Groups[1].Value.Contains("<u>" + host + "</u>");
        }

        // The file as the client came with it, from this patch's backup (or one
        // left by the older tools); null while the file has not been changed yet.
        static string OriginalText(string path)
        {
            foreach (string suffix in AllSuffixes)
            {
                if (PatchFiles.Exists(path + suffix)) return PatchFiles.ReadText(path + suffix).Text;
            }
            return null;
        }

        string LinkState(string domain)
        {
            string dir = At("ConfigFiles");
            if (!PatchFiles.Exists(dir)) return "missing";
            int other = 0;
            foreach (string f in PatchFiles.FilesWithExtension(dir, ".xml"))
            {
                other += CountStrayLinks(PatchFiles.ReadText(f).Text, domain);
            }
            return other > 0 ? "original" : "patched";
        }

        string WhitelistState(string domain)
        {
            int missing = 0;
            foreach (string name in new[] { "XtraConfig.xml", "tzer.xml" })
            {
                string path = At(@"ConfigFiles\" + name);
                if (!PatchFiles.Exists(path)) continue;
                if (!IsWhitelisted(name, PatchFiles.ReadText(path).Text, domain)) missing++;
            }
            return missing > 0 ? "original" : "patched";
        }

        string StripState(Strip s)
        {
            string path = At(s.File);
            if (!PatchFiles.Exists(path)) return "missing";
            return Regex.IsMatch(PatchFiles.ReadText(path).Text, s.Pattern) ? "original" : "patched";
        }

        // --- applying -----------------------------------------------------------------

        // What a person chooses between: one row per job, whatever number of
        // files and places it takes. Every change of the tables above belongs to
        // one.
        public static readonly PatchJobs Jobs = MakeJobs();

        static PatchJobs MakeJobs()
        {
            var j = new PatchJobs();
            j.Add("xtraz", "Services that are gone", "Xtraz: the strip, the panel, menus, options, sounds and filter");
            j.Add("tzers", "Services that are gone", "tZers: the button, the teasers, the option and the sound");
            j.Add("sms", "Services that are gone", "SMS and phone: buttons, icons, menus, options, sounds, filter");
            j.Add("zlango", "Services that are gone", "the Zlango add-on and its message window buttons");
            j.Add("ads", "Advertising", "advertising: the ad slots of every country, their ad servers, the boxes, the banner and its frame");
            j.Add("fix", "Fixes", "the cut-off \"Advanced\" preferences group; \"Change my picture\" lost after the Xtraz list reloads");
            j.Add("links", "Your server", "the pages the client opens point at your server, over HTTPS; nothing goes to the old ICQ hosts");
            j.Add("sign-in", "Your server", "automatic connection and voice calls use your server");
            // Off until chosen: it needs our DLL next to the patch, and the
            // type library it registers is the user's, not the folder's.
            j.Add("tzers-player", "Your server", "tZers without Flash: our player (" + PlayerShipped + " next to this patch)", off: true);
            j.Rivals("tzers-player", "tzers");
            // Off until chosen: the E2E add-on (tools\icq-e2e), our DLL next to
            // the patch, as two rows. Either puts the DLL in as msimg32.dll, with
            // icq-e2e.ini beside it, which says which of the two the add-on does
            // (e2e= and tls=, see E2eIni in Common). End-to-end encryption of
            // messages uses the key directory of the domain above; the
            // encrypted connection sends every connection to the domain over
            // TLS 1.3, with or without it. Set ICQE2E_LOG to write a log.
            // A third row encrypts calls inside the E2E session (calls_encrypt=);
            // it needs the first.
            j.Add(E2eIni.E2eJob, "Your server", E2eIni.E2eRow, off: true);
            j.Add(E2eIni.TlsJob, "Your server", E2eIni.TlsRow, off: true);
            j.Add(E2eIni.CallsJob, "Your server", E2eIni.CallsRow, off: true);

            j.Assign("the Xtraz strip above the contact list", "xtraz");
            j.Assign("the Xtraz panel below the contact list", "xtraz");
            j.Assign("the \"Xtraz invitations\" option", "xtraz");
            j.Assign("the Xtraz submenu of the contact menu", "xtraz");
            j.Assign("the \"save Xtraz invitations\" option", "xtraz");
            j.Assign("the incoming-Xtraz sound", "xtraz");
            j.Assign("the Xtraz filter of the history search", "xtraz");
            j.Assign("the \"My Xtraz\" item of the main menu", "xtraz");
            j.Assign("the tZers button of the message window", "tzers");
            j.Assign("the \"play tZers automatically\" option", "tzers");
            j.Assign("the incoming-tZer sound", "tzers");
            j.Assign("the teaser strip", "tzers");
            j.Assign("the \"SMS & Phone\" entry of the preferences list", "sms");
            j.Assign("the page of the \"SMS & Phone\" preferences", "sms");
            j.Assign("the SMS button of the message window", "sms");
            j.Assign("the phone button of the message window", "sms");
            j.Assign("the SMS icon on a contact row", "sms");
            j.Assign("the phone icon on a contact row", "sms");
            j.Assign("the auto-SMS line of the contact card", "sms");
            j.Assign("the \"Send SMS\" item of the contact menu", "sms");
            j.Assign("the auto-SMS section of the options", "sms");
            j.Assign("the incoming-SMS sound", "sms");
            j.Assign("the outgoing-SMS sound", "sms");
            j.Assign("the SMS filter of the history search", "sms");
            j.Assign("SMS carriers", "sms");
            j.Assign("the Zlango add-on and its message window buttons", "zlango");
            j.Assign("the banner under the message window", "ads");
            j.Assign("the ad box of the message window", "ads");
            j.Assign("the white frame at the foot of the message window", "ads");
            j.Assign("the ad box of the contact list", "ads");
            j.Assign("advertising slots", "ads");
            j.Assign("ad servers", "ads");
            j.Assign("the advertising of each country", "ads");
            j.Assign("the cut-off bottom of the \"Advanced\" group", "fix");
            j.Assign("Xtraz items lost when the list is read again", "fix");
            // The client refuses content from a host not on its whitelists, so
            // the links are no use without them.
            j.Assign("links", "links");
            j.Assign("whitelist", "links");
            j.Assign("page links", "links");
            foreach (CodeLink c in CodeLinks) j.Assign(c.What, "links");
            j.Assign("sign-in", "sign-in");
            j.Assign("the tZers player", "tzers-player");
            j.Assign("the Flash type library", "tzers-player");
            j.Assign("the tZers list", "tzers-player");
            j.Assign("the E2E add-on: end-to-end encryption", E2eIni.E2eJob);
            j.Assign("the E2E add-on: TLS to the server", E2eIni.TlsJob);
            j.Assign("the E2E add-on: sign-in only over TLS", E2eIni.TlsJob);
            j.Assign("the E2E add-on: encryption of calls", E2eIni.CallsJob);
            return j;
        }

        // Every change with its current state, folded into one row per job. A
        // row's key is its job: what it is chosen by.
        public List<PatchItem> Items(string domain)
        {
            var items = new List<PatchItem>();
            Action<string, string, string> add = (key, where, state) =>
                items.Add(new PatchItem { Group = "", Key = key, What = key, Where = where, State = state });
            foreach (CodePatch p in CodePatches) add(p.What, p.File, CodeState(p));
            foreach (MarkupEdit e in MarkupEdits) add(e.What, PatchFiles.Leaf(e.File), EditState(e));
            foreach (Removal r in Removals) add(r.What, PatchFiles.Leaf(r.Path), RemovalState(r));
            add("links", "ConfigFiles", LinkState(domain));
            add("whitelist", "XtraConfig.xml", WhitelistState(domain));
            foreach (var d in DtdStates(domain)) add("page links", d.Key.Substring(Ver1.Length + 1), d.Value);
            foreach (CodeLink c in CodeLinks) add(c.What, c.File, CodeLinkState(c, domain));
            foreach (Strip st in Strips) add(st.What, PatchFiles.Leaf(st.File), StripState(st));
            add("sign-in", "MCore.dll, now " + SignInShown(), SignInState(domain));
            add("the E2E add-on: sign-in only over TLS", SignIn.File, SignInPortState(domain));
            string player = PlayerState();
            add("the tZers player", PlayerFile, player);
            add("the Flash type library", PlayerFile, TypeLibState());
            add("the tZers list", PatchFiles.Leaf(TzerList), TzerListState(domain));
            string e2e = E2eState();
            add("the E2E add-on: end-to-end encryption", E2eProbeFile + ", " + E2eIniFile, E2eRowState(E2eIni.E2eJob, domain));
            add("the E2E add-on: TLS to the server", E2eProbeFile + ", " + E2eIniFile, E2eRowState(E2eIni.TlsJob, domain));
            add("the E2E add-on: encryption of calls", E2eProbeFile + ", " + E2eIniFile, E2eRowState(E2eIni.CallsJob, domain));
            List<PatchItem> rows = Jobs.Merge(items);
            // Without our DLL there is nothing to put in: the row says why.
            if (player == "unavailable")
            {
                foreach (PatchItem row in rows.Where(r => r.Key == "tzers-player"))
                {
                    row.State = "unavailable";
                    row.Where = PlayerMissing();
                }
            }
            if (e2e == "unavailable")
            {
                foreach (PatchItem row in rows.Where(r => Ps.Contains(E2eIni.Jobs, r.Key)))
                {
                    row.State = "unavailable";
                    row.Where = E2eMissing();
                }
            }
            return rows;
        }

        // Puts back a whole file from its backup; the backup stays, as the original.
        static bool RestoreFromBackup(string path)
        {
            foreach (string suffix in AllSuffixes)
            {
                if (PatchFiles.Exists(path + suffix))
                {
                    PatchFiles.Copy(path + suffix, path, true);
                    return true;
                }
            }
            return false;
        }

        // The whitelist of one configuration file with the host added, if it has one.
        static string AddWhitelisted(string name, string text, string host)
        {
            if (Ps.Eq(name, "XtraConfig.xml"))
            {
                if (IsWhitelisted(name, text, host)) return text;
                return Regex.Replace(text, "(Key=\"WhiteDomainList\" Value=\")([^\"]*)(\")",
                    m => m.Groups[1].Value + m.Groups[2].Value + " " + host + m.Groups[3].Value, RegexOptions.None);
            }
            if (Ps.Eq(name, "tzer.xml"))
            {
                if (IsWhitelisted(name, text, host)) return text;
                int at = text.IndexOf("</whitelist>", StringComparison.Ordinal);
                if (at < 0) return text;
                return text.Substring(0, at) + "   <u>" + host + "</u>\n   " + text.Substring(at);
            }
            return text;
        }

        // Makes the client match the selection and gives what changed, one line
        // per change. Throws, before anything is written, when a file that
        // would be patched in code is not the one from build 2024.
        public List<string> ApplyAll(string domain, ICollection<string> skip)
        {
            var notes = new List<string>();
            // The tZers player without our DLL to put in is left out, and then
            // does not stand in the way of taking the tZers out either.
            var asked = new HashSet<string>();
            if (skip != null) foreach (string k in skip) asked.Add(k);
            if (Jobs.IsWanted(asked, "tzers-player") && PlayerState() == "unavailable")
            {
                notes.Add("tZers player left out: " + PlayerMissing());
                asked.Add("tzers-player");
            }
            if (E2eIni.Jobs.Any(k => Jobs.IsWanted(asked, k)) && E2eState() == "unavailable")
            {
                notes.Add("E2E add-on left out: " + E2eMissing());
                foreach (string k in E2eIni.Jobs) asked.Add(k);
            }
            skip = Jobs.Settle(asked);
            bool player = Jobs.IsWanted(skip, "tzers-player");

            foreach (CodePatch p in CodePatches)
            {
                if (Jobs.IsWanted(skip, p.What) && CodeState(p) == "other version")
                {
                    throw new InvalidOperationException(p.File + " is not the one from ICQ 6.5 build 2024; nothing was changed.");
                }
            }
            string dir = At("ConfigFiles");
            List<string> configs = PatchFiles.FilesWithExtension(dir, ".xml");
            // Group-Object File: the edits of one file together, in the order
            // the files first come up.
            var groups = MarkupEdits.GroupBy(e => e.File, Ps.Keys).ToList();
            PatchSteps.Start(7 + CodePatches.Length + groups.Count + Removals.Length + configs.Count + CodeLinks.Length);
            PatchSteps.Step("Checking the client...");
            List<PatchItem> before = Items(domain);

            foreach (CodePatch p in CodePatches)
            {
                PatchSteps.Step("Building " + p.File + "...");
                string path = At(p.File);
                string state = CodeState(p);
                if (Jobs.IsWanted(skip, p.What))
                {
                    if (state != "original") continue;
                    PatchFiles.BackupOnce(path, Suffix);
                    byte[] bytes = File.ReadAllBytes(path);
                    foreach (ByteEdit e in p.Edits) Array.Copy(e.To, 0, bytes, e.Offset, e.To.Length);
                    File.WriteAllBytes(path, bytes);
                }
                else if (state == "patched")
                {
                    RestoreFromBackup(path);
                }
            }

            // Each file is built again from the original with the wanted edits.
            foreach (IGrouping<string, MarkupEdit> group in groups)
            {
                PatchSteps.Step("Interface: " + PatchFiles.Leaf(group.Key) + "...");
                string path = At(group.Key);
                if (!PatchFiles.Exists(path)) continue;
                TextFile file = PatchFiles.ReadText(path);
                string original = OriginalText(path);
                string text = original ?? file.Text;
                foreach (MarkupEdit edit in group)
                {
                    if (!Jobs.IsWanted(skip, edit.What)) continue;
                    string changed = ApplyEdit(edit, text);
                    if (changed != null) text = changed;
                }
                if (!Ps.Ceq(text, file.Text))
                {
                    PatchFiles.BackupOnce(path, Suffix);
                    file.Text = text;
                    PatchFiles.WriteText(path, file);
                }
            }

            foreach (Removal r in Removals)
            {
                PatchSteps.Step("Interface: " + PatchFiles.Leaf(r.Path) + "...");
                string path = At(r.Path);
                string state = RemovalState(r);
                if (Jobs.IsWanted(skip, r.What))
                {
                    // A reinstall puts it back next to the copy kept the first
                    // time; that copy already holds the original.
                    if (state == "original" && PatchFiles.Exists(path + Suffix)) PatchFiles.Discard(path);
                    else if (state == "original") PatchFiles.Rename(path, PatchFiles.Leaf(path) + Suffix);
                }
                else if (state == "patched")
                {
                    foreach (string suffix in AllSuffixes)
                    {
                        if (PatchFiles.Exists(path + suffix))
                        {
                            PatchFiles.Rename(path + suffix, PatchFiles.Leaf(path));
                            break;
                        }
                    }
                }
            }

            // The configuration files the same way: the original, then the links,
            // the whitelists and the emptied lists that are wanted. A server let
            // in before is gone with that too - the original never had it.
            //
            // The client refuses content from a host that is not on the
            // whitelists, and drops the part of the interface that host would
            // have fed; so the links and the whitelists go together.
            bool links = Jobs.IsWanted(skip, "links");
            bool white = Jobs.IsWanted(skip, "whitelist");
            foreach (string f in configs)
            {
                string name = Path.GetFileName(f);
                PatchSteps.Step("Configuration: " + name + "...");
                TextFile file = PatchFiles.ReadText(f);
                string original = OriginalText(f);
                string text = original ?? file.Text;
                if (player && Ps.Eq(name, PatchFiles.Leaf(TzerList))) text = BuildTzerList(text, domain);
                if (links)
                {
                    text = Regex.Replace(text, LinkPattern, m => PagesBase(domain), RegexOptions.IgnoreCase);
                    text = NoDeadHosts(text);
                }
                if (white) text = AddWhitelisted(name, text, domain);
                foreach (Strip s in Strips)
                {
                    if (Ps.Eq(PatchFiles.Leaf(s.File), name) && Jobs.IsWanted(skip, s.What))
                    {
                        text = Regex.Replace(text, s.Pattern, s.With);
                    }
                }
                if (!Ps.Ceq(text, file.Text))
                {
                    PatchFiles.BackupOnce(f, Suffix);
                    file.Text = text;
                    PatchFiles.WriteText(f, file);
                }
            }

            // The links of the interface go with the others: each DTD and DLL
            // is built from its original, so leaving the links out takes them
            // back.
            PatchSteps.Step("Interface: links in the DTDs...");
            SetDtdLinks(domain, Jobs.IsWanted(skip, "page links"));
            foreach (CodeLink c in CodeLinks)
            {
                PatchSteps.Step("Links: " + c.File + "...");
                string note = SetCodeLink(c, domain, Jobs.IsWanted(skip, c.What));
                if (note != null) notes.Add(note);
            }

            PatchSteps.Step("tZers player...");
            string playerNote = SetPlayer(player);
            if (playerNote != null) notes.Add(playerNote);

            PatchSteps.Step("E2E add-on...");
            string e2eNote = SetE2e(Jobs.IsWanted(skip, E2eIni.E2eJob), Jobs.IsWanted(skip, E2eIni.TlsJob), Jobs.IsWanted(skip, E2eIni.CallsJob), domain);
            if (e2eNote != null) notes.Add(e2eNote);
            // Whatever the selection: the lock button is gone for good.
            TakeDroppedLockFiles();

            PatchSteps.Step("Sign-in server...");
            if (Jobs.IsWanted(skip, "sign-in"))
            {
                // With the TLS row as well, on the port only the add-on reaches.
                SetSignIn(domain, Jobs.IsWanted(skip, E2eIni.TlsJob));
            }
            else if (Ps.Contains(new[] { "patched", "another server" }, SignInState(domain)))
            {
                RestoreFromBackup(At(SignIn.File));
            }

            // Last, once every file is as it stays: the client's update
            // manifests list them so, and it does not put the originals back
            // from update.icq.com (see UpdateManifests, in Common).
            PatchSteps.Step("Update manifests...");
            UpdateManifests.Sync(Root, AllSuffixes, Suffix);

            var report = new List<string>();
            PatchSteps.Step("Checking the result...");
            List<PatchItem> after = Items(domain);
            for (int i = 0; i < after.Count; i++)
            {
                if (Ps.Eq(after[i].State, before[i].State)) continue;
                if (Ps.Eq(after[i].State, "patched")) report.Add("applied: " + after[i].What);
                else report.Add("taken out: " + after[i].What);
            }
            report.AddRange(notes);
            return report;
        }

        // Puts every backup back where it came from and gives how many.
        public int RestoreAll()
        {
            // The registration first, while our DLL is still there to take it
            // back; the original then comes back with the other files.
            string note = UnregisterPlayer();
            if (note != null) PatchFiles.Error(note);
            int count = 0;
            // Our msimg32.dll proxy has no stock to back up (ICQ 6.5 ships none),
            // so the backup sweep below would not remove it: take it out here.
            string e2ePath = At(E2eProbeFile);
            if (IsOurE2e(e2ePath) && !AllSuffixes.Any(x => PatchFiles.Exists(e2ePath + x)))
            {
                PatchFiles.Discard(e2ePath);
                count++;
            }
            // The ini the patch wrote for the add-on goes with it, and the
            // backup of what was there before it goes away with the backup, so
            // the sweep below does not count it again: that copy comes back in
            // its place, or, when there is none, the file is the patch's own
            // writing and is removed.
            if (RemoveE2eIni()) count++;
            // The script and pictures of the dropped lock button, which the
            // client never had, go the same way.
            count += TakeDroppedLockFiles();
            Func<string, string> suffixOf = name => AllSuffixes.FirstOrDefault(s => name.EndsWith(s));
            List<FileSystemInfo> items = PatchFiles.Tree(Root).Where(i => suffixOf(i.Name) != null).ToList();
            PatchSteps.Start(items.Count);
            foreach (FileSystemInfo item in items)
            {
                string s = suffixOf(item.Name);
                PatchSteps.Step("Restoring " + item.Name.Substring(0, item.Name.Length - s.Length) + "...");
                string orig = item.FullName.Substring(0, item.FullName.Length - s.Length);
                if (item is DirectoryInfo)
                {
                    if (!PatchFiles.Exists(orig))
                    {
                        PatchFiles.Rename(item.FullName, PatchFiles.Leaf(orig));
                        count++;
                    }
                }
                else
                {
                    PatchFiles.Copy(item.FullName, orig, true);
                    PatchFiles.Remove(item.FullName);
                    count++;
                }
            }
            return count;
        }

        // --- finding the client ---------------------------------------------------------

        public static bool IsClientFolder(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !PatchFiles.Exists(path)) return false;
            foreach (string f in new[] { "ICQ.exe", "MUICore.dll", Content })
            {
                if (!PatchFiles.Exists(PatchFiles.Join(path, f))) return false;
            }
            return true;
        }

        public static string FindRoot()
        {
            return ClientFolder.Find(new ClientSearch
            {
                AppPathsExe = "ICQ.exe",
                TrimQuotes = true,
                DisplayName = "(?i)^icq\\s*6",
                UseUninstallString = false,
                StandardFolder = "ICQ6.5",
                IsClient = IsClientFolder,
            });
        }

        // Older versions saved host:port here; only the domain is kept now.
        public static string SavedServer()
        {
            string value = PatchSettings.Read(SettingsKey, "Server");
            return value == null ? null : Domain.Of(value);
        }

        public static void SaveServer(string value)
        {
            PatchSettings.Save(SettingsKey, "Server", value);
        }
    }
}
