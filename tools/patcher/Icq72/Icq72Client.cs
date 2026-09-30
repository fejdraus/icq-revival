// What the patch for ICQ 7.2 (build 3143) changes in the client's folder.
//
// Build 3143 is what the installer puts in; on its first start the client
// updates itself to build 3525 from update.icq.com, which still answers. The
// patch takes either.
//
// ICQ 7.2 is the same Boxely client as ICQ 6.5 in another layout: the
// interface under imApp (content, theme, resources), the configuration under
// packages\ICQ\ConfigFiles, add-ons and translations under packages. Unlike
// 6.5 it keeps its sign-in server and nearly all of its page addresses in
// plain configuration files, so this patch changes text only - markup,
// configuration, DTDs - and renames one DLL; only when asked for does it put
// a DLL of ours in place of the client's Flash wrapper. No code is patched.
//
//   1. Interface. SMS, the games and Zones buttons, Xtraz, the tab strip of
//      the main window with its Lifestream and "My box" tabs, and the
//      advertising frames are taken out of the client's own markup: an
//      element is marked collapsed="true" - how the client hides its own
//      optional parts - a style is given no size, or a tab is dropped from
//      the list the main window builds its tabs from.
//   2. Links. The pages the client opens on ICQ.com - help, search, "My
//      page", About, the legal notice, registration and password, the add-on
//      galleries, the Xtraz pages - are pointed at our server, which is also
//      let in by the client's content whitelists; the Xtraz list with them.
//   3. Sign-in. The default ACC connection settings (AppConfig.xml) are
//      pointed at our server's web API: the web login, the BOS redirect and
//      the STUN server of calls.
//   4. Fixes. The AOL Diagnostics module, tbdiag.dll, which ICQ.exe loads
//      from its own folder when aolload.exe is there and which takes ICQ 7
//      down, is renamed out of the way.
//   5. tZers and Flash avatars, only when asked for: our Flash-free
//      FlashPlayerControl.dll is put in and registered for the user, and the
//      tZer lists are pointed at the server (see "tZers without Flash").
//
// Every file is identified by its checksum before the first change, backed
// up next to itself, and "Restore original" puts them all back. Apply makes
// the client match the selection: each file is rebuilt from its original with
// the wanted changes only. The user's profile is never touched.
//
// The client puts back from update.icq.com every file its update manifests
// list with another checksum - the configuration files, the translations of
// its language packages - so the manifests are kept listing the files as the
// patch leaves them (UpdateManifests, in Common). A file the client has put
// back before that is an original again: it becomes the backup.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace IcqRevival.Patch
{
    internal sealed class Icq72Client
    {
        public const string Suffix = ".icq72patch-backup";

        // Only the server's domain is asked for. Ports and paths are the same on
        // every ICQ Revival server (deploy/VM-SPEC.md, section 3), so the patch
        // fills them in itself.
        const int PagesPortHttps = 8102;  // pages the client opens in a window or the browser
        const int PagesPortHttp = 8101;   // what the client fetches with its own loader
        const int WebApiPort = 8082;      // the web API ICQ 7 signs in through; no TLS in its ACC
        public const string SettingsKey = @"Software\OpenOSCAR\Icq72Patch";

        public const string Content = @"imApp\content";
        const string Theme = @"imApp\theme";
        public const string Config = @"packages\ICQ\ConfigFiles";
        const string AppConfig = Config + @"\AppConfig.xml";
        const string OwnerTabs = Config + @"\UIOwnerPanelConfig.xml";
        const string LinksXml = Config + @"\links.xml";
        const string DataDtd = Content + @"\data.dtd";
        // The translations: the ones the client comes with, and the language
        // packages, each a folder under packages with language\<locale>.
        const string ClientLanguages = @"imApp\resources\*";
        const string PackageLanguages = @"packages\*\language\*";

        // --- identity ------------------------------------------------------------
        //
        // The files this patch changes, by their checksum as they come with
        // build 3143 and, where 3525 changed them, as build 3525 and the
        // configuration update of update.icq.com have them. Before anything is
        // written, the original of every file to change - its backup once
        // changed - has to be one of them; another build is refused rather
        // than patched where its markup may differ. The translations of
        // language packages are not listed: they come in versions of their
        // own, and only addresses inside their sentences are changed there.

        static readonly Dictionary<string, string[]> Originals = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { @"imApp\content\data.dtd", new[] { "FA3E177B9BBE096922AFCA5F11DCA347D14E62C6B2D76E83AE1724E88EAB8685" } },
            { @"imApp\content\MUICore\MainDlg.box", new[] { "AC16E8131AAD78B82ECBE502C0B10A0223204F50C7F83FA7529BC5844BF795DE" } },
            { @"imApp\content\MUICore\MainDlgPanelOwner.box", new[] { "B499DE0AB43F61738760838CCAB061D2C799C9D0ABBF206FDA39678C6E503FD6" } },
            { @"imApp\content\MUICore\PopupMenus.box", new[] { "121C60DB9922BE901A109673686808476A874A1183A923B1DC03239660F8392D" } },
            { @"imApp\content\MUICore\HistorySearchDlg.box", new[] {
                "A4BDD3630F4DA954B2E5E0765C9042B68498D3150CCE800EF6BF0CAF88F00285",
                "0F8A8710088F173924381C385A76D8980EE1C772DCF48CF92610A7449FCA7E84" } },
            { @"imApp\content\MUICore\ContactList\MiniUserProfileDlg.gadgets.box", new[] { "BFF7BD00E07F0CD6C3842EAC048F430C3C4C67D7AAC7F4C5AE12A1C971A8A04A" } },
            { @"imApp\content\MUICore\Preferences\OPrefsPanelAdvanced.box", new[] { "54F27DB04DD0FE24D08C775B7A0ADBD1791424F1B98D9CA579809DAF57475C95" } },
            { @"imApp\content\MUICore\Preferences\OPrefsPanelNotifications.box", new[] { "F9C3BA5A0C8B51F020057E6BFB8CC0D6C2DFA0C2E41BB0E409F4ED2A0D70FB08" } },
            { @"imApp\content\MUICore\Preferences\OPrefsPanelHistory.box", new[] { "D01350E6CE40DDCD6DFEA9E0EFD1DF3146379D5595C4C015F4DDBA5042FC818F" } },
            { @"imApp\content\MUICore\Preferences\OPrefsPanelSkin.box", new[] { "5E968717120B8FFBD1F0779CC64481F3D3D48A0221FA5F36CC7D27FCF227DD8F" } },
            { @"imApp\content\MUIMessage\MsgSessionPanel.box", new[] { "92849D6782F57B5E05F88FDA2AA7B499F48FF88545BBF70ABFF4FC942B73BC0D" } },
            { @"imApp\theme\MUICore\MainDlgPanelOwner.style.box", new[] {
                "1F75401091A588573BAA1B167C58D826A9F9A9398708EE442C4CA568A52FE1D6",
                "EF8E145DC0AAC5DAE986858D4C7B496EF2B59961FD5CA15C5BBFFDA9E5BFF1C5" } },
            { @"imApp\theme\MUIMessage\MsgSessionDlg.style.box", new[] {
                "B101615D74BC8B51B42CC494C129806062165E8F17D72E36F3235C5970D247B9",
                "DB92ED81A527695FAE2265C0CF54E42E27B4AC9C78364F49F6757B9B4DFDE91C" } },
            { @"packages\ICQ\ConfigFiles\AppConfig.xml", new[] {
                "34CB955EFAE0268EC76FEA4C0EF8C4A18C5A5C145BC58DEA2F31531A0D7662E8",
                "935B596B51DD057667B4A4B9B0A6DC055F4DAC1F51628EECFBAFE7F2469EAB49" } },
            { @"packages\ICQ\ConfigFiles\links.xml", new[] {
                "8E9E685E516C778F26830162C5EC684B7409D5341F0E61ECB2D1E5E55F80D8B4",
                "ADBC1C006E64FC8CF8F4D27C476070EC3206F27543BC3B4E3BF3D3FC30B5207A" } },
            { @"packages\ICQ\ConfigFiles\System.xml", new[] { "D9F222A2B989B6FEE31D3CEF277A2B1575C446B0621B1DC06E16052AC3E11C37" } },
            { @"packages\ICQ\ConfigFiles\XtraConfig.xml", new[] { "D23E528686726B5C38DD1DC056CCDD5B860681480BA3C3C382D0E05F24161A2C" } },
            { @"packages\ICQ\ConfigFiles\SMSConfig.xml", new[] {
                "892182B0206EDD193A88CDDF50F7FB2587A1FF82FC185EC1451ED086D0320BAE",
                "9B79ED8455091CFB6B4D0BD68B7B51DE8BFA129EBBD40CBD2CEEA3162CDC7779" } },
            { @"packages\ICQ\ConfigFiles\tzer.xml", new[] {
                "C423F7ED899E71DA064837C6C38F4E8FBCFCB300143FAA2573C06AFB5DB9021D",
                "3ABB143649100F76A156DDA0B6B548D8822A5506928175C555F7237011163A8B" } },
            { @"packages\ICQ\ConfigFiles\tzerDe.xml", new[] {
                "71BB9ABC59F4FFC50952AF1B9EA5B260E78C7034EDC78C3F77BEEA8D03139638",
                "2630FA4F6D1BE0216BB01F704615226FAD02EECB9A7CD7F7B17FEC7EE368F37A" } },
            { @"packages\ICQ\ConfigFiles\adConfig.xml", new[] {
                "33EA75F797723F893FAA5FF04C0E8605716B41098A3DE366CCDE95BCB8421B10",
                "6D879322E28560AC663A7D9F9A0370AB7526683932AE219103B9D41A65CB1F50" } },
            { @"packages\ICQ\ConfigFiles\UIOwnerPanelConfig.xml", new[] { "01F398318EBE909419B66A4F36E7BF834F9168A734E54FE0C682C041E2C763BE" } },
            { @"imApp\resources\en-US\AboutDlg.dtd", new[] {
                "4C1227E5F07C1A8D77005AC88440743BBC0210A9EC9C6290EF89F96561DE085A",
                "A801CF979BABD80AF5CA9DEDEA96DDBBC2DF8FF999C597F213A595261BAA1F5F" } },
            { @"imApp\resources\en-US\MsgSessionPanel.dtd", new[] {
                "5EF756E965508FFAF20250B3BB573888D0C53A7580DBAF0CA3DA55758C53760C",
                "CA4124D6354F50633B23C1745BB5BF0C2CA830FB44154FC8A8D4D06941A48A99" } },
            { @"imApp\resources\en-US\SMS.dtd", new[] { "917D549E4BEB72E70F178C1494ABF6A1FC4AF2FF6C78117D681E22BB8B6EFBA7" } },
            { @"imApp\resources\en-US\Errors.dtd", new[] {
                "E516C9A97F980A617C665907A72E4B573B20A2EB2E98D4D333FFE0C2E05EDD9B",
                "A776AFA6E1558DF57B0538EF72127CF72459463D8CC587A2F9C499DE6EC5BD30" } },
            { @"imApp\resources\en-US\common.dtd", new[] { "94D6F7034666D77D467891BA63086698E008D7DF4FCF3D3DF96627B1829588D5" } },
        };

        // --- changes -----------------------------------------------------------------
        //
        // A change is one edit of one text file: given the text and the domain,
        // the text with the edit made, or the same text when there is nothing to
        // do - so the edit of an edited file changes nothing, which is how its
        // state is read. Each belongs to a part, a line of the report that a job
        // claims; a change without a part only follows the others (When).

        sealed class Change
        {
            public string File;                      // relative; a "*" segment stands for every folder there
            public string Part;                      // what it is chosen by; null: When alone decides
            public Func<string, string, string> Edit;
            public Func<Func<string, bool>, bool> When;
        }

        static Change On(string file, string part, Func<string, string> edit)
        {
            return new Change { File = file, Part = part, Edit = (text, domain) => edit(text) };
        }

        static Change Linked(string file, string part, Func<string, string, string> edit)
        {
            return new Change { File = file, Part = part, Edit = edit };
        }

        static Change Follows(string file, Func<Func<string, bool>, bool> when, Func<string, string> edit)
        {
            return new Change { File = file, When = when, Edit = (text, domain) => edit(text) };
        }

        // The element with this id, outside comments: the markup keeps old
        // versions of some elements commented out, under the same id.
        static Match FindTag(string text, string id)
        {
            var comments = Regex.Matches(text, "<!--.*?-->", RegexOptions.Singleline).Cast<Match>().ToList();
            foreach (Match m in Regex.Matches(text, "<[A-Za-z][^<>]*\\bid=\"" + Regex.Escape(id) + "\"[^<>]*>"))
            {
                if (!comments.Any(c => m.Index >= c.Index && m.Index < c.Index + c.Length)) return m;
            }
            return Match.Empty;
        }

        // Marks the element collapsed="true".
        static Func<string, string> Collapse(string id)
        {
            return text =>
            {
                Match tag = FindTag(text, id);
                if (!tag.Success) return text;
                string old = tag.Value;
                if (Ps.Match(old, "\\bcollapsed=\"true\"")) return text;
                string changed = Regex.Replace(old, "\\s*\\bcollapsed=\"[^\"]*\"", "");
                changed = changed.TrimEnd('>').TrimEnd('/').TrimEnd();
                changed += " collapsed=\"true\"" + (old.TrimEnd().EndsWith("/>") ? "/>" : ">");
                return text.Substring(0, tag.Index) + changed + text.Substring(tag.Index + tag.Length);
            };
        }

        // Swaps one exact piece of text, wherever it is, for another.
        static Func<string, string> Replace(string from, string to)
        {
            return text => text.Replace(from, to);
        }

        // Takes out whatever the pattern finds.
        static Func<string, string> Drop(string pattern)
        {
            return text => Regex.Replace(text, pattern, "");
        }

        // A tab of the main window. The window builds its tabs from this list,
        // so a tab left out of it is never made.
        static Func<string, string> DropTab(string id)
        {
            return Drop("\\s*<content\\s+id=\"" + Regex.Escape(id) + "\"[^>]*/>");
        }

        // The games button and the Zones ("Z") button share a pill at the right
        // end of the tab strip, and a smaller one for when the tabs fill the
        // strip; each shows one or the other, bound to that. With one of the
        // buttons gone the pills are narrowed to the other, with both - or with
        // the strip - they are given no size.
        const string MainDlgPanel = Content + @"\MUICore\MainDlgPanelOwner.box";
        const string MainDlgPanelStyle = Theme + @"\MUICore\MainDlgPanelOwner.style.box";
        const string BigPill = "<part name=\"idGamesZonesBtn\" fill=\"url(#imgTranslucentBtn)\" fillSlice=\"7\" fillSize=\"both\" width=\"61\" height=\"26\"";
        const string SmallPill = "<part name=\"idSmallGamesZonesBtn\" fill=\"url(#imgTranslucentBtn)\" fillSlice=\"5 5 5 5\" fillSize=\"both\" width=\"15\" height=\"31\"";

        // Without the tab strip the pills go with it, whatever is in them.
        static bool OneOf(Func<string, bool> wanted) { return wanted("games") != wanted("xtraz") && !wanted("tabs"); }
        static bool Both(Func<string, bool> wanted) { return wanted("games") && wanted("xtraz") || wanted("tabs"); }
        static bool Either(Func<string, bool> wanted) { return wanted("games") || wanted("xtraz"); }

        const string MsgPanel = Content + @"\MUIMessage\MsgSessionPanel.box";
        const string MsgStyle = Theme + @"\MUIMessage\MsgSessionDlg.style.box";

        // The link at the foot of the "is offline" notice of the message
        // window, which switches the window to SMS; the sentence before it
        // stays.
        const string SendSmsLink = "&lt;br&gt;&lt;a class=&quot;d-2-link&quot; href=&quot;http://sendsms&quot;&gt;*MsgSessionPanel.MessageSentOfflineString3*&lt;/a&gt;";

        static readonly Change[] Changes =
        {
            // SMS. The prefs list entry "SMS" is built in code (MUICore.dll) and
            // stays; see the README.
            On(OwnerTabs, "the SMS tab of the main window", DropTab("SMS")),
            On(MsgPanel, "the SMS tab of the message window", Collapse("msgWinSmsTab")),
            On(Content + @"\MUICore\PopupMenus.box", "the \"SMS\" item of the contact menu", Collapse("idCommSendSMS")),
            // Shown by a binding; the binding is put out of use the way the
            // markup does it elsewhere, by the name of its property.
            On(Content + @"\MUICore\ContactList\MiniUserProfileDlg.gadgets.box", "the SMS button of the contact card",
                t => Collapse("idSMS")(t.Replace("targetProperty=\"collapsed\" path=\"isShowSms\"", "targetProperty=\"notActive_collapsed\" path=\"isShowSms\""))),
            On(Content + @"\MUICore\Preferences\OPrefsPanelSkin.box", "the SMS sounds",
                t => Collapse("OutgoingSMS")(Collapse("IncomingSMS")(t))),
            On(Content + @"\MUICore\HistorySearchDlg.box", "the SMS filter of the history search", Collapse("idMsgTypeSMS")),
            On(DataDtd, "the \"Send SMS\" link of the offline notice", Replace(SendSmsLink, "")),
            On(Config + @"\SMSConfig.xml", "SMS carriers", Drop("(?m)^[ \\t]*<i n=\"[^\"]*\"[^>]*/>[ \\t]*\\r?\\n?")),

            // Games and Zones.
            On(MainDlgPanel, "the games button", t => Collapse("idGamesSmallButton")(Collapse("idGamesBigButton")(t))),
            On(MainDlgPanel, "the Zones button", t => Collapse("idZonesSmallButton")(Collapse("idZonesBigButton")(t))),
            Follows(MainDlgPanel, Either, t => Collapse("idGamesZonesSmallSeparator")(Collapse("idGamesZonesBigSeparator")(t))),
            Follows(MainDlgPanelStyle, OneOf, t => t
                .Replace(BigPill, BigPill.Replace("width=\"61\"", "width=\"35\""))
                .Replace("<part name=\"idBigGamesZonesBtn\"\twidth=\"45\" />", "<part name=\"idBigGamesZonesBtn\"\twidth=\"25\" />")
                .Replace(SmallPill, SmallPill.Replace("height=\"31\"", "height=\"17\""))),
            Follows(MainDlgPanelStyle, Both, t => t
                .Replace(BigPill, "<part name=\"idGamesZonesBtn\" width=\"0\" height=\"0\"")
                .Replace(SmallPill, "<part name=\"idSmallGamesZonesBtn\" width=\"0\" height=\"0\"")),

            // Xtraz.
            On(Content + @"\MUICore\MainDlg.box", "the \"Zones\" item of the ICQ menu", Collapse("idOpenZones")),
            On(Content + @"\MUICore\PopupMenus.box", "the Xtraz submenu of the contact menu", Collapse("idXtrazMenu")),
            On(Content + @"\MUICore\Preferences\OPrefsPanelNotifications.box", "the \"Xtraz invitation\" option", Collapse("idXtrazInvitation")),
            On(Content + @"\MUICore\Preferences\OPrefsPanelHistory.box", "the \"save Xtraz invitations\" option", Collapse("idSaveXtrazInvitations")),
            On(Content + @"\MUICore\HistorySearchDlg.box", "the Xtraz filter of the history search", Collapse("idMsgTypeXtrazInvitation")),

            // Zlango, writing with its picture words. The message window's box
            // for it is filled with its buttons by the code, so it stays -
            // collapsed.
            On(MsgPanel, "the Zlango buttons of the message window", Collapse("idZlangoBox")),
            On(Content + @"\MUICore\Preferences\OPrefsPanelAdvanced.box", "the \"Always convert text to Zlango\" option", Collapse("idAutoConvertTextToZlango")),

            // The tab strip of the main window: the Lifestream and "My box"
            // (mail) tabs are not made, and the strip - with the contacts tab
            // alone on it - is collapsed, so the contact list under it takes
            // its place. The strip stays in the markup, as the code fills and
            // selects it; its panels show the contact list as before. The
            // games and Zones pill sits on the strip: its buttons go with it
            // (the pill itself is given no size above), the big pair by their
            // box, the small pair each, so the games and Zones rows keep
            // their own state.
            On(OwnerTabs, "the Lifestream tab", DropTab("LifeStream")),
            On(OwnerTabs, "the \"My box\" tab", DropTab("MeTab")),
            On(MainDlgPanel, "the tab strip of the main window", Collapse("idMainTabs")),
            Follows(MainDlgPanel, w => w("tabs"), t => Collapse("idBigGamesZonesBtn")(
                Collapse("idGamesSmallButton")(Collapse("idZonesSmallButton")(Collapse("idGamesZonesSmallSeparator")(t))))),
            // The contact list's box reaches a few pixels up, under the tabs;
            // with no tabs it would go over the owner's picture and status
            // message, so it is moved down, and the panels' background, drawn
            // 4px up, is put back in line.
            Follows(MainDlgPanelStyle, w => w("tabs"), t => t
                .Replace("<style id=\"imgTabBackground\" marginTop=\"-4\"", "<style id=\"imgTabBackground\" marginTop=\"0\"")
                .Replace("<part name=\"mainDlgBoxContacts\" />", "<part name=\"mainDlgBoxContacts\" marginTop=\"8\" />")),

            // Advertising. The ad element of the message window and its
            // container are looked up by the code, so they stay - collapsed and
            // with no size; the band under the message window keeps the
            // features panel, so it only loses its fixed height.
            On(MainDlgPanel, "the ad band of the main window", Collapse("idAdBoxPlace")),
            On(MainDlgPanelStyle, "the ad box of the main window",
                Replace("<style id=\"adBoxStyle\" width=\"234\" height=\"60\"  />", "<style id=\"adBoxStyle\" width=\"0\" height=\"0\"  />")),
            On(MsgPanel, "the banner under the message window", Collapse("idBottomBannerContainer")),
            On(MsgStyle, "the ad box of the message window", t => t
                .Replace("<part name=\"idBottomBannerContainer\"    height=\"68\"", "<part name=\"idBottomBannerContainer\"    height=\"0\"")
                .Replace("<part name=\"idAdBox\"                    width=\"468\" height=\"60\" />", "<part name=\"idAdBox\"                    width=\"0\" height=\"0\" />")),
            On(MsgStyle, "the empty band under the message window",
                Replace("<part name=\"idBottomBox\" height=\"68\" paddingTop=\"6\"/>", "<part name=\"idBottomBox\" paddingTop=\"6\"/>")),
            On(Config + @"\adConfig.xml", "advertising slots", Drop("[ \\t]*<spot\\b[^>]*/>[ \\t]*\\r?\\n?")),

            // Your server.
            Linked(AppConfig, "sign-in", SetSignIn),
            Linked(LinksXml, "page links", RetargetLinksXml),
            Linked(Config + @"\System.xml", "links", RetargetByPath),
            Linked(Config + @"\XtraConfig.xml", "links", RetargetByPath),
            Linked(Config + @"\SMSConfig.xml", "links", RetargetByPath),
            Linked(Config + @"\XtraConfig.xml", "whitelist", (t, d) => AddWhitelisted("XtraConfig.xml", t, d)),
            Linked(Config + @"\tzer.xml", "whitelist", (t, d) => AddWhitelisted("tzer.xml", t, d)),
            // The tZer lists, with the player only (see "tZers without Flash").
            Linked(TzerList, "the tZers list", BuildTzerList),
            Linked(TzerListDe, "the tZers list", BuildTzerList),
            Linked(DataDtd, "page links", (t, d) => InEntity(t, "MsgSessionPanel.BirthdayMessageHTML", "http://greetings\\.icq\\.com", LinkTo(d, "/icq/greetings"))),
            Linked(DataDtd, "page links", (t, d) => InEntity(t, "ContentPanelSms.LearnMoreUrl", null, LinkTo(d, "/icq/stub/sms.html"))),
        };

        // --- links ---------------------------------------------------------------------
        //
        // The pages the client opens are listed in links.xml, by the same names
        // ICQ 6.5 gave them as DTD entities; each is pointed at the page the 6.5
        // patch points it at, with the client's own placeholders - %ScreenName%,
        // %Locale%, %PartnerId%, %s - kept, since it fills them in. A link the
        // client opened through the ICQ.com single sign-on (a="icqOpenAuth")
        // is opened directly: our server has no such login in front of it.
        //
        // Left as they are: the sign-on itself (ICQ.IcqOpenAuth), the Lifestream
        // and Facebook addresses, the WIM buddy list API, AIM profiles, the ICQ
        // chat page, the Zlango tips, the feedback form, the mobile download,
        // Google search, and the Xtraz install counter the client fetches itself.

        const string XtrazStub = "/icq/stub/xtraz.html";

        static readonly KeyValuePair<string, string>[] PageLinks =
        {
            new KeyValuePair<string, string>("DetailsDlg.IcqHomePageLink", "/icq/whitepages?icq=%ScreenName%"),
            new KeyValuePair<string, string>("Search.SearchLink", "/icq/search?q=%s"),
            new KeyValuePair<string, string>("Password.ForgotPassword", "/icq/password"),
            new KeyValuePair<string, string>("Password.ChangePassword", "/icq/password"),
            new KeyValuePair<string, string>("LoginDlg.NewAccountLink", "/icq/register"),
            new KeyValuePair<string, string>("MainDlg.HelpLink", "/icq/help/"),
            new KeyValuePair<string, string>("Brand.HomePage", "/icq/about"),
            new KeyValuePair<string, string>("AboutDlg.icqSite_URL", "/icq/about"),
            new KeyValuePair<string, string>("AboutDlg.icqSite_Legal", "/icq/legal/"),
            new KeyValuePair<string, string>("AboutDlg.icqSite_ViewTerms", "/icq/terms?lspid=%PartnerId%&amp;lang=%Locale%"),
            new KeyValuePair<string, string>("OPrefsPanelSkin.MoreSkinsLink", "/icq/addons/skins/"),
            new KeyValuePair<string, string>("OPrefsPanelSkin.MoreLangsLink", "/icq/addons/languages/"),
            new KeyValuePair<string, string>("MsgSessionDlg.MoreLexiconsLink", "/icq/addons/dictionaries/"),
            new KeyValuePair<string, string>("MoodsGallery.MoreMoodsLink", "/icq/addons/moods"),
            new KeyValuePair<string, string>("Emoticons.Galleries", "/icq/addons/emoticons"),
            new KeyValuePair<string, string>("XtraController.UserXtraDetailsUrl", XtrazStub + "?xtra_id=%XtraID%"),
            new KeyValuePair<string, string>("XtraController.UserXtraTermsOfServiceUrl", XtrazStub),
            new KeyValuePair<string, string>("XtraController.UserXtraTermsOfServiceMoreDetailsUrl", XtrazStub),
            new KeyValuePair<string, string>("MyXtraz.XtrazGalleryURL", XtrazStub),
            new KeyValuePair<string, string>("MyXtraz.DevelopersSiteURL", XtrazStub),
            new KeyValuePair<string, string>("XtraController.XtraNotAvailableUrl",
                XtrazStub + "?xtra_id=%XtraID%&amp;client_id=%ClientId%&amp;client_lsp_id=%PartnerId%&amp;build=%BuildNum%"),
        };

        static string LinkTo(string domain, string path)
        {
            return "https://" + domain + ":" + PagesPortHttps + path;
        }

        static string RetargetLinksXml(string text, string domain)
        {
            foreach (var link in PageLinks)
            {
                string to = LinkTo(domain, link.Value);
                text = Regex.Replace(text, "<i\\s+c=\"" + Regex.Escape(link.Key) + "\"[^>]*>", m =>
                {
                    string tag = Regex.Replace(m.Value, "\\s+a=\"icqOpenAuth\"", "");
                    return Regex.Replace(tag, "(\\bd=\")[^\"]*(\")", d => d.Groups[1].Value + to + d.Groups[2].Value);
                });
            }
            return text;
        }

        // The other configuration files hold addresses of ICQ.com services the
        // client fetches or opens by path, as in ICQ 6.5, whose table this is:
        // what it opens in a window works over HTTPS, what it fetches with its
        // own loader stays on plain HTTP. Any host in front of those paths is
        // taken, so moving to another server is applying again.
        static readonly KeyValuePair<string, bool>[] PathLinkList =
        {
            new KeyValuePair<string, bool>("/xtraz2/global/", true),              // the Xtraz list and its strings
            new KeyValuePair<string, bool>("/download/icq6/", true),              // the emoticon download page
            new KeyValuePair<string, bool>("/xtraz/srv/", false),                 // country lookup the client fetches itself
            new KeyValuePair<string, bool>("/register/email_activation/", false), // the client posts the activation itself
            new KeyValuePair<string, bool>("/sms", false),                        // SMS carriers (their entries are removed)
            new KeyValuePair<string, bool>("/ibs/icq6/", false),                  // SMS number check
        };
        static readonly Dictionary<string, bool> PathLinks = PathLinkList.ToDictionary(p => p.Key, p => p.Value, Ps.Keys);

        static readonly string PathLinkPattern = "https?://[A-Za-z0-9.-]+(?::\\d+)?" +
            "(?=(?<path>" + string.Join("|", PathLinkList.Select(p => Regex.Escape(p.Key))) + "))";

        static string RetargetByPath(string text, string domain)
        {
            return Regex.Replace(text, PathLinkPattern, m =>
            {
                bool https;
                if (PathLinks.TryGetValue(m.Groups["path"].Value, out https) && https) return "https://" + domain + ":" + PagesPortHttps;
                return "http://" + domain + ":" + PagesPortHttp;
            }, RegexOptions.IgnoreCase);
        }

        // An address inside one entity of a DTD: the whole value, or what the
        // pattern finds in it.
        static string InEntity(string text, string entity, string find, string to)
        {
            string head = "<!ENTITY " + entity + " \"";
            int at = text.IndexOf(head, StringComparison.Ordinal);
            if (at < 0) return text;
            int from = at + head.Length;
            int end = text.IndexOf('"', from);
            if (end < 0) return text;
            string value = text.Substring(from, end - from);
            string changed = find == null ? to : Regex.Replace(value, find, m => to);
            return text.Substring(0, from) + changed + text.Substring(end);
        }

        // Addresses written into translated sentences: only the address, not
        // the words or the punctuation after it. In the translations the client
        // comes with and in every language package.
        sealed class SentenceLink
        {
            public string Name;   // the DTD, in each language folder
            public string Find;
            public string To;
        }

        static readonly SentenceLink[] SentenceLinks =
        {
            new SentenceLink { Name = "AboutDlg.dtd", Find = "http://www\\.icq\\.com/legal\\b/?", To = "/icq/legal/" },
            new SentenceLink { Name = "MsgSessionPanel.dtd", Find = "(?i)http://www\\.icq\\.(?:com/download(?:[\\w/-]|\\.(?=[\\w/]))*|rambler\\.ru\\b/?)", To = "/icq/download" },
            new SentenceLink { Name = "SMS.dtd", Find = "http://www\\.icq\\.com/sms\\b", To = "/icq/stub/sms.html" },
            new SentenceLink { Name = "Errors.dtd", Find = "http://www\\.icq\\.com/sms\\b", To = "/icq/stub/sms.html" },
            new SentenceLink { Name = "common.dtd", Find = "http://www\\.icq\\.com/legal/privacy\\.html", To = "/icq/legal/" },
        };

        static IEnumerable<Change> SentenceChanges()
        {
            foreach (string languages in new[] { ClientLanguages, PackageLanguages })
            {
                foreach (SentenceLink s in SentenceLinks)
                {
                    SentenceLink link = s;
                    yield return Linked(languages + @"\" + link.Name, "page links",
                        (t, d) => Regex.Replace(t, link.Find, m => LinkTo(d, link.To)));
                }
            }
        }

        static IEnumerable<Change> AllChanges() { return Changes.Concat(SentenceChanges()); }

        // Whether a host is already on a whitelist.
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

        // The whitelist of one configuration file with the host added. The
        // client refuses content from a host that is not on them.
        static string AddWhitelisted(string name, string text, string host)
        {
            if (IsWhitelisted(name, text, host)) return text;
            if (Ps.Eq(name, "XtraConfig.xml"))
            {
                return Regex.Replace(text, "(Key=\"WhiteDomainList\" Value=\")([^\"]*)(\")",
                    m => m.Groups[1].Value + m.Groups[2].Value + " " + host + m.Groups[3].Value);
            }
            int at = text.IndexOf("</whitelist>", StringComparison.Ordinal);
            if (at < 0) return text;
            return text.Substring(0, at) + "   <u>" + host + "</u>\r\n   " + text.Substring(at);
        }

        // --- sign-in -------------------------------------------------------------------
        //
        // ICQ 7 signs in through the web API (ACC, "aimcc"): a web login on
        // host.address, then the BOS redirect, both plain HTTP on our web API
        // port - its ACC has no TLS, so aimcc.connect.secure stays 0. These are
        // the defaults of the ACC preferences, which the client starts from; a
        // server typed in its own connection settings stays the user's. The
        // STUN server of calls is the same domain, on its standard port.

        static string SetAcc(string text, string name, string value)
        {
            return Regex.Replace(text, "(<p\\s+name=\"" + Regex.Escape(name) + "\"\\s+value=\")[^\"]*(\")",
                m => m.Groups[1].Value + value + m.Groups[2].Value);
        }

        static string ReadAcc(string text, string name)
        {
            Match m = Regex.Match(text, "<p\\s+name=\"" + Regex.Escape(name) + "\"\\s+value=\"([^\"]*)\"");
            return m.Success ? m.Groups[1].Value : "";
        }

        static string SetSignIn(string text, string domain)
        {
            text = SetAcc(text, "aimcc.connect.host.address", domain);
            text = SetAcc(text, "aimcc.connect.host.port", WebApiPort.ToString());
            text = SetAcc(text, "aimcc.connect.bossRedirect.address", domain);
            text = SetAcc(text, "aimcc.connect.bossRedirect.port", WebApiPort.ToString());
            return SetAcc(text, "aimcc.connect.stun.address", domain);
        }

        // --- tZers without Flash ---------------------------------------------------------
        //
        // ICQ 7.2 plays tZers through FlashPlayerControl.dll, the same wrapper
        // around the Adobe Flash ActiveX control as ICQ 6.5 (MUIMessage.dll
        // delay-loads it), and shows Flash avatars in the "devil" picture of
        // the message window by hosting the ShockwaveFlash control itself
        // (MUICoreLib, MUIUtils) - both are gone with Flash. The job puts
        // three things in place, and takes them out again:
        //
        //   1. Our FlashPlayerControl.dll (tools\icq65\flashplayer, on Ruffle)
        //      over the original, as for ICQ 6.5. The patch does not carry it
        //      but takes FlashPlayerControl-Ruffle.dll from next to its exe, or
        //      -Player: under its own name, so a patch dropped into the ICQ
        //      folder does not find it in place of the original. Ours is told
        //      by its version resource, the original by its checksum.
        //   2. Its registration for the user, by its own DllRegisterServer:
        //      the Flash type library, which the tZer window's event sink looks
        //      up (LoadRegTypeLib), and the ShockwaveFlash control class, which
        //      the avatar picture creates - the client checks for Flash by
        //      creating it. The DLL is 32-bit and the patch may run as 64-bit,
        //      so the 32-bit regsvr32 does it. It writes HKCU only, with the
        //      DLL's full path; there is one such registration per user, so
        //      the ICQ 6.5 patch's player and this one take it from each other.
        //   3. tzer.xml - and tzerDe.xml, which the client reads instead in
        //      Germany (ConfigRedirect.xml) - pointed at the tZers the server
        //      has (/icq/tzers/), with only those listed, and the server let
        //      in by the list's whitelist. Plain HTTP: the list has one base
        //      for thumbnails and movies, and our DLL fetches the movie.
        //
        // Unlike ICQ 6.5, ICQ 7.2 keeps no still pictures of Flash avatars
        // (its MCore.dll does not load the player), so there is no such cache
        // to clear when the player changes.

        public const string PlayerFile = "FlashPlayerControl.dll";
        // Our DLL as it is handed out, next to the patch.
        public const string PlayerShipped = "FlashPlayerControl-Ruffle.dll";
        // FlashPlayerControl 2.1.8.1 as build 3143 comes with it.
        const string PlayerSha256Original = "C294A60155614AD81BF749F3BE8734A66ED4286AACA943F5C490269BBCA066B9";
        // What our DLL says in its version resource (typelib\resource.rc).
        const string PlayerProduct = "ICQ Revival";
        const string PlayerInternalName = "FlashPlayerControl-Ruffle";
        const string TzerList = Config + @"\tzer.xml";
        const string TzerListDe = Config + @"\tzerDe.xml";
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

        static string TzerBase(string domain)
        {
            return "http://" + domain + ":" + PagesPortHttp + TzersPath;
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

        public static string DefaultPlayerSource()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, PlayerShipped);
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
        // user, as the 32-bit client sees it, or null.
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
        bool RegistrationIsOurs()
        {
            string dll = RegisteredTypeLib();
            string cls = RegisteredFlashClass();
            return !string.IsNullOrEmpty(dll) && SameFile(dll, At(PlayerFile))
                && !string.IsNullOrEmpty(cls) && SameFile(cls, At(PlayerFile));
        }

        string RegistrationState()
        {
            if (!PatchFiles.Exists(At(PlayerFile))) return "missing";
            return IsOurPlayer(At(PlayerFile)) && RegistrationIsOurs() ? "patched" : "original";
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

        // Takes the registration away from our DLL, if it is ours and
        // registered there. A line for the report when that failed, or null.
        string UnregisterPlayer()
        {
            string path = At(PlayerFile);
            string dll = RegisteredTypeLib(), cls = RegisteredFlashClass();
            bool ours = (!string.IsNullOrEmpty(dll) && SameFile(dll, path)) || (!string.IsNullOrEmpty(cls) && SameFile(cls, path));
            if (!IsOurPlayer(path) || !ours) return null;
            int code = Regsvr32(path, true);
            return code == 0 ? null : "the Flash registration could not be taken out (regsvr32 exit code " + code + ")";
        }

        // Makes the DLL and its registration match the selection (the lists
        // are done with the other configuration files). A line for the report
        // when something could not be done, or null.
        string SetPlayer(bool wanted)
        {
            string path = At(PlayerFile);
            string state = PlayerState();
            if (!wanted)
            {
                // Ours without a backup was not put there by the patch: it
                // stays, registered or not.
                if (!IsOurPlayer(path) || !PatchFiles.Exists(path + Suffix)) return null;
                string note = UnregisterPlayer();
                PatchFiles.Copy(path + Suffix, path, true);
                return note;
            }
            if (state == "missing") return PlayerFile + " is not in the client - tZers player left out";
            if (state == "other version") return PlayerFile + " is neither the one from build 3143 nor the tZers player - tZers player left out";
            if (state == "original")
            {
                if (!IsOurPlayer(path)) PatchFiles.BackupOnce(path, Suffix);
                PatchFiles.Copy(PlayerSource, path, true);
            }
            if (!IsOurPlayer(path)) return PlayerFile + " could not be put in - tZers player left out";
            if (!RegistrationIsOurs())
            {
                int code = Regsvr32(path, false);
                if (code != 0) return "the player could not be registered (regsvr32 exit code " + code + ") - tZers will not play";
            }
            return null;
        }

        // --- E2E observer (Phase 0, log-only) -------------------------------------------
        //
        // The end-to-end-encryption add-on's first phase is an observer: a DLL
        // that hooks the client's own Winsock send/recv in coolcore59.dll,
        // reassembles FLAP, parses ICBM/offline messages and writes the decoded
        // text to a log (the file named by the ICQE2E_LOG environment variable).
        // Every byte reaches the client and the server unchanged; there is no
        // crypto and no rewriting in this phase. See tools\icq-e2e.
        //
        // ICQ.exe (3525) loads tbdiag.dll from its own folder at startup, so the
        // observer ships as tbdiag.dll - the same slot the "fix" job frees by
        // renaming the stock AOL Diagnostics module aside. This job, off unless
        // chosen, puts our DLL in that slot:
        //   - with "fix" on, the stock is already renamed aside; ours goes in the
        //     empty slot.
        //   - with "fix" off, the stock is backed up first, then ours goes over
        //     it. The stock crashes ICQ 7; ours does not.
        // "Restore original" puts the stock tbdiag.dll back from its backup.
        //
        // The patch does not carry the DLL; it takes Icqe2eProbe.dll from next to
        // its exe (gitignored, owner-only test build). Ours is told from the
        // stock by its version resource.

        public const string E2eProbeFile = "tbdiag.dll";
        // Our DLL as it is handed out, next to the patch.
        public const string E2eProbeShipped = "Icqe2eProbe.dll";
        // What our DLL says in its version resource (tools\icq-e2e\loader-tbdiag\resource.rc).
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
            if (!IsOurE2e(E2eSource)) return Path.GetFileName(E2eSource) + " is not the E2E observer";
            return null;
        }

        // patched (ours in place) / original (can be put in) / unavailable
        // (our DLL not next to the patch).
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

        // Makes tbdiag.dll match the selection, cooperating with the "fix"
        // removal (which runs first and may already have renamed the stock
        // aside). A line for the report when it could not be done, or null.
        string SetE2e(bool wanted)
        {
            string path = At(E2eProbeFile);
            if (!wanted)
            {
                if (!IsOurE2e(path)) return null;
                // Put the stock back from its backup, or, with none known, just
                // remove ours.
                if (PatchFiles.Exists(path + Suffix)) PatchFiles.Copy(path + Suffix, path, true);
                else PatchFiles.Discard(path);
                return null;
            }
            string miss = E2eMissing();
            if (miss != null) return "E2E observer left out: " + miss;
            if (!IsOurE2e(path))
            {
                // Save the stock only if it is still there (fix off); with fix on
                // it is already the backup.
                if (PatchFiles.Exists(path) && !PatchFiles.Exists(path + Suffix)) PatchFiles.BackupOnce(path, Suffix);
                PatchFiles.Copy(E2eSource, path, true);
            }
            else if (!SameFile(path, E2eSource) && !Ps.Eq(PatchFiles.Sha256(path), PatchFiles.Sha256(E2eSource)))
            {
                PatchFiles.Copy(E2eSource, path, true);
            }
            if (!IsOurE2e(path)) return E2eProbeFile + " could not be put in - E2E observer left out";
            return null;
        }

        // --- files taken out of the way -------------------------------------------------

        sealed class Removal
        {
            public string Path;
            public string What;
        }

        static readonly Removal[] Removals =
        {
            // ICQ.exe loads it from its own folder whenever aolload.exe is there;
            // it takes ICQ 7 down. Renamed with the backup suffix.
            new Removal { Path = "tbdiag.dll", What = "the AOL Diagnostics module (tbdiag.dll)" },
        };

        // --- jobs -------------------------------------------------------------------------

        // What a person chooses between: one row per job, whatever number of
        // files and places it takes.
        public static readonly PatchJobs Jobs = MakeJobs();

        static PatchJobs MakeJobs()
        {
            var j = new PatchJobs();
            j.Add("sms", "Services that are gone", "SMS: the tab, the buttons, the menu item, the sounds and the filter");
            j.Add("games", "Services that are gone", "the games button of the main window");
            j.Add("xtraz", "Services that are gone", "Xtraz: the Zones (\"Z\") button, menus, options and filter");
            j.Add("zlango", "Services that are gone", "Zlango: writing with its picture words - the message window buttons and the option");
            j.Add("tabs", "Services that are gone", "the tab strip of the main window, with the Lifestream and \"My box\" mail tabs: only the contact list stays");
            j.Add("ads", "Advertising", "advertising: the ad slots, boxes and the empty bands they leave");
            j.Add("fix", "Fixes", "the AOL Diagnostics module that crashes ICQ 7 (tbdiag.dll)");
            j.Add("links", "Your server", "the pages the client opens point at your server");
            j.Add("sign-in", "Your server", "automatic connection and voice calls use your server");
            // Off until chosen: it needs our DLL next to the patch, and the
            // registration it makes is the user's, not the folder's.
            j.Add("tzers-player", "Your server", "tZers and Flash avatars without Flash: our player (" + PlayerShipped + " next to this patch)", off: true);
            // Off until chosen: the E2E observer (Phase 0, log-only). Needs our
            // DLL next to the patch and ICQE2E_LOG set to write a log.
            j.Add("e2e-probe", "Your server", "E2E encryption observer (Phase 0, log-only): our " + E2eProbeShipped + " as tbdiag.dll; set ICQE2E_LOG to log", off: true);

            j.Assign("the SMS tab of the main window", "sms");
            j.Assign("the Zlango buttons of the message window", "zlango");
            j.Assign("the \"Always convert text to Zlango\" option", "zlango");
            j.Assign("the SMS tab of the message window", "sms");
            j.Assign("the \"SMS\" item of the contact menu", "sms");
            j.Assign("the SMS button of the contact card", "sms");
            j.Assign("the SMS sounds", "sms");
            j.Assign("the SMS filter of the history search", "sms");
            j.Assign("the \"Send SMS\" link of the offline notice", "sms");
            j.Assign("SMS carriers", "sms");
            j.Assign("the games button", "games");
            j.Assign("the Zones button", "xtraz");
            j.Assign("the \"Zones\" item of the ICQ menu", "xtraz");
            j.Assign("the Xtraz submenu of the contact menu", "xtraz");
            j.Assign("the \"Xtraz invitation\" option", "xtraz");
            j.Assign("the \"save Xtraz invitations\" option", "xtraz");
            j.Assign("the Xtraz filter of the history search", "xtraz");
            j.Assign("the Lifestream tab", "tabs");
            j.Assign("the \"My box\" tab", "tabs");
            j.Assign("the tab strip of the main window", "tabs");
            j.Assign("the ad band of the main window", "ads");
            j.Assign("the ad box of the main window", "ads");
            j.Assign("the banner under the message window", "ads");
            j.Assign("the ad box of the message window", "ads");
            j.Assign("the empty band under the message window", "ads");
            j.Assign("advertising slots", "ads");
            j.Assign("the AOL Diagnostics module (tbdiag.dll)", "fix");
            // The client refuses content from a host not on its whitelists, so
            // the links are no use without them.
            j.Assign("links", "links");
            j.Assign("page links", "links");
            j.Assign("whitelist", "links");
            j.Assign("sign-in", "sign-in");
            j.Assign("the tZers player", "tzers-player");
            j.Assign("the Flash registration", "tzers-player");
            j.Assign("the tZers list", "tzers-player");
            j.Assign("the E2E observer (tbdiag.dll)", "e2e-probe");
            return j;
        }

        // --- state ------------------------------------------------------------------------

        public string Root;
        // Our DLL to put in: next to the patch unless given.
        public string PlayerSource;

        public Icq72Client(string root, string player = null, string e2e = null)
        {
            Root = root;
            PlayerSource = string.IsNullOrEmpty(player) ? DefaultPlayerSource() : Path.GetFullPath(player);
            E2eSource = string.IsNullOrEmpty(e2e) ? DefaultE2eSource() : Path.GetFullPath(e2e);
        }

        string At(string relative) { return PatchFiles.Join(Root, relative); }

        // Every file a relative path with "*" segments stands for that is
        // there, as relative paths.
        List<string> Expand(string file)
        {
            var result = new List<string> { "" };
            string[] parts = file.Split('\\');
            for (int i = 0; i < parts.Length; i++)
            {
                bool last = i == parts.Length - 1;
                var next = new List<string>();
                foreach (string prefix in result)
                {
                    if (parts[i] == "*")
                    {
                        string dir = At(prefix.TrimEnd('\\'));
                        if (!Directory.Exists(dir)) continue;
                        foreach (string d in Directory.GetDirectories(dir).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                        {
                            next.Add(prefix + Path.GetFileName(d) + (last ? "" : "\\"));
                        }
                    }
                    else
                    {
                        next.Add(prefix + parts[i] + (last ? "" : "\\"));
                    }
                }
                result = next;
            }
            return file.Contains("*") ? result.Where(p => PatchFiles.Exists(At(p))).ToList() : result;
        }

        // Whether the client has put a changed file back from its update
        // server since: it is what the client's update manifest - as it came,
        // before the patch listed its changes there - says, and the backup is
        // not. That file is the original then, newer than the backup.
        bool PutBackByClient(string relative)
        {
            string path = At(relative);
            if (!File.Exists(path) || !File.Exists(path + Suffix)) return false;
            string listed = UpdateManifests.Listed(Root, relative, Suffix);
            return listed != null && PatchFiles.Md5(path) == listed && PatchFiles.Md5(path + Suffix) != listed;
        }

        // Where the original of a file is: the file itself until the patch
        // changes it, its backup after that - unless the client has put an
        // original back since.
        string OriginalPath(string relative)
        {
            string path = At(relative);
            return PatchFiles.Exists(path + Suffix) && !PutBackByClient(relative) ? path + Suffix : path;
        }

        // The file as the client came with it.
        string OriginalText(string relative)
        {
            return PatchFiles.ReadText(OriginalPath(relative)).Text;
        }

        // Whether the original of a listed file is not one of the known ones.
        bool IsOtherVersion(string relative)
        {
            string[] known;
            if (!Originals.TryGetValue(relative, out known)) return false;
            string source = OriginalPath(relative);
            return PatchFiles.Exists(source) && !Ps.Contains(known, PatchFiles.Sha256(source));
        }

        // original / patched / other version / unknown (nothing to change:
        // the markup is not what the change expects) / missing
        string ChangeState(Change c, string relative, string domain)
        {
            string path = At(relative);
            if (!PatchFiles.Exists(path)) return "missing";
            if (IsOtherVersion(relative)) return "other version";
            string current = PatchFiles.ReadText(path).Text;
            string original = OriginalText(relative);
            if (Ps.Ceq(c.Edit(original, domain), original)) return "unknown";
            return Ps.Ceq(c.Edit(current, domain), current) ? "patched" : "original";
        }

        string RemovalState(Removal r)
        {
            string path = At(r.Path);
            bool gone = !PatchFiles.Exists(path);
            bool saved = PatchFiles.Exists(path + Suffix);
            if (gone && saved) return "patched";
            if (!gone) return "original";
            return "missing";
        }

        // The sign-in server the client starts from now.
        string SignInShown()
        {
            string path = At(AppConfig);
            return PatchFiles.Exists(path) ? ReadAcc(PatchFiles.ReadText(path).Text, "aimcc.connect.host.address") : "";
        }

        // Every change with its current state, folded into one row per job.
        public List<PatchItem> Items(string domain)
        {
            var items = new List<PatchItem>();
            Action<string, string, string> add = (key, where, state) =>
                items.Add(new PatchItem { Group = "", Key = key, What = key, Where = where, State = state });
            foreach (Change c in AllChanges())
            {
                if (c.Part == null) continue;
                foreach (string relative in Expand(c.File))
                {
                    string state = ChangeState(c, relative, domain);
                    // A translation that says nothing about ICQ.com is not listed.
                    if (c.File.Contains("*") && state == "unknown") continue;
                    string where = c.Part == "sign-in" ? PatchFiles.Leaf(relative) + ", now " + SignInShown() : PatchFiles.Leaf(relative);
                    add(c.Part, where, state);
                }
            }
            foreach (Removal r in Removals) add(r.What, r.Path, RemovalState(r));
            string player = PlayerState();
            add("the tZers player", PlayerFile, player);
            add("the Flash registration", PlayerFile, RegistrationState());
            string e2e = E2eState();
            add("the E2E observer (tbdiag.dll)", E2eProbeFile, e2e);
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
                foreach (PatchItem row in rows.Where(r => r.Key == "e2e-probe"))
                {
                    row.State = "unavailable";
                    row.Where = E2eMissing();
                }
            }
            return rows;
        }

        // --- applying ---------------------------------------------------------------------

        // Makes the client match the selection and gives what changed, one line
        // per job. Throws, before anything is written, when a file to change is
        // not one of the known originals.
        public List<string> ApplyAll(string domain, ICollection<string> skip)
        {
            var notes = new List<string>();
            // The tZers player without our DLL to put in is left out, its
            // lists with it.
            var asked = new HashSet<string>();
            if (skip != null) foreach (string k in skip) asked.Add(k);
            if (Jobs.IsWanted(asked, "tzers-player") && PlayerState() == "unavailable")
            {
                notes.Add("tZers player left out: " + PlayerMissing());
                asked.Add("tzers-player");
            }
            if (Jobs.IsWanted(asked, "e2e-probe") && E2eState() == "unavailable")
            {
                notes.Add("E2E observer left out: " + E2eMissing());
                asked.Add("e2e-probe");
            }
            skip = asked;
            Func<string, bool> wanted = key => Jobs.IsWanted(skip, key);
            Func<Change, bool> isWanted = c => c.When != null ? c.When(wanted) : wanted(c.Part);

            // The changes of each file together, in the order the files first
            // come up and the changes are listed.
            var files = new List<KeyValuePair<string, List<Change>>>();
            var index = new Dictionary<string, List<Change>>(StringComparer.OrdinalIgnoreCase);
            foreach (Change c in AllChanges())
            {
                foreach (string relative in Expand(c.File))
                {
                    List<Change> list;
                    if (!index.TryGetValue(relative, out list))
                    {
                        list = new List<Change>();
                        index[relative] = list;
                        files.Add(new KeyValuePair<string, List<Change>>(relative, list));
                    }
                    list.Add(c);
                }
            }

            foreach (var f in files)
            {
                if (PatchFiles.Exists(At(f.Key)) && IsOtherVersion(f.Key))
                {
                    throw new InvalidOperationException(f.Key + " is not the one from ICQ 7.2 build 3143 or 3525; nothing was changed.");
                }
            }

            PatchSteps.Start(5 + files.Count + Removals.Length);
            PatchSteps.Step("Checking the client...");
            List<PatchItem> before = Items(domain);

            // Each file is built again from the original with the wanted changes.
            foreach (var f in files)
            {
                PatchSteps.Step("Building " + PatchFiles.Leaf(f.Key) + "...");
                string path = At(f.Key);
                if (!PatchFiles.Exists(path)) continue;
                // The client has put an original back: it is the backup now.
                if (PutBackByClient(f.Key)) PatchFiles.Copy(path, path + Suffix, true);
                TextFile file = PatchFiles.ReadText(path);
                string text = OriginalText(f.Key);
                foreach (Change c in f.Value)
                {
                    if (isWanted(c)) text = c.Edit(text, domain);
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
                PatchSteps.Step("Renaming " + PatchFiles.Leaf(r.Path) + "...");
                string path = At(r.Path);
                string state = RemovalState(r);
                if (wanted(r.What))
                {
                    // A reinstall puts the file back next to the copy kept the
                    // first time; that copy already holds the original.
                    if (state == "original" && PatchFiles.Exists(path + Suffix)) PatchFiles.Discard(path);
                    else if (state == "original") PatchFiles.Rename(path, PatchFiles.Leaf(path) + Suffix);
                }
                else if (state == "patched")
                {
                    PatchFiles.Rename(path + Suffix, PatchFiles.Leaf(path));
                }
            }

            PatchSteps.Step("tZers player...");
            string playerNote = SetPlayer(wanted("tzers-player"));
            if (playerNote != null) notes.Add(playerNote);

            // The E2E observer after the fix removal, so ours goes into a freed
            // slot or over the stock, as the two selections require.
            PatchSteps.Step("E2E observer...");
            string e2eNote = SetE2e(wanted("e2e-probe"));
            if (e2eNote != null) notes.Add(e2eNote);

            // Last, once every file is as it stays: the client's update
            // manifests list them so, and it does not put the originals back.
            PatchSteps.Step("Update manifests...");
            UpdateManifests.Sync(Root, new[] { Suffix }, Suffix);

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
            List<FileSystemInfo> items = PatchFiles.Tree(Root).Where(i => i is FileInfo && i.Name.EndsWith(Suffix)).ToList();
            PatchSteps.Start(items.Count);
            foreach (FileSystemInfo item in items)
            {
                PatchSteps.Step("Restoring " + item.Name.Substring(0, item.Name.Length - Suffix.Length) + "...");
                string orig = item.FullName.Substring(0, item.FullName.Length - Suffix.Length);
                PatchFiles.Copy(item.FullName, orig, true);
                PatchFiles.Remove(item.FullName);
                count++;
            }
            return count;
        }

        // --- finding the client -------------------------------------------------------------

        // ICQ 7.2 by its layout and the version of ICQ.exe; ICQ 6.5 keeps its
        // interface under services\icqApp instead.
        public static bool IsClientFolder(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !PatchFiles.Exists(path)) return false;
            foreach (string f in new[] { "ICQ.exe", Content, AppConfig })
            {
                if (!PatchFiles.Exists(PatchFiles.Join(path, f))) return false;
            }
            try
            {
                string version = System.Diagnostics.FileVersionInfo.GetVersionInfo(PatchFiles.Join(path, "ICQ.exe")).FileVersion ?? "";
                return version.StartsWith("7.2", StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        public static string FindRoot()
        {
            return ClientFolder.Find(new ClientSearch
            {
                AppPathsExe = "ICQ.exe",
                TrimQuotes = true,
                DisplayName = "(?i)^icq\\s*7",
                UseUninstallString = false,
                StandardFolder = "ICQ7.2",
                IsClient = IsClientFolder,
            });
        }

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
