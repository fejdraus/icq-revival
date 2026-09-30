// What the patch for ICQ 7.2 (build 3143) changes in the client's folder.
//
// ICQ 7.2 is the same Boxely client as ICQ 6.5 in another layout: the
// interface under imApp (content, theme, resources), the configuration under
// packages\ICQ\ConfigFiles, add-ons and translations under packages. Unlike
// 6.5 it keeps its sign-in server and nearly all of its page addresses in
// plain configuration files, so this patch changes text only - markup,
// configuration, DTDs - and renames one DLL. No code is patched.
//
//   1. Interface. SMS, the games and Zones buttons, Xtraz, the Lifestream and
//      "My box" tabs, and the advertising frames are taken out of the
//      client's own markup: an element is marked collapsed="true" - how the
//      client hides its own optional parts - a style is given no size, or a
//      tab is dropped from the list the main window builds its tabs from.
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
//
// Every file is identified by its checksum before the first change, backed
// up next to itself, and "Restore original" puts them all back. Apply makes
// the client match the selection: each file is rebuilt from its original with
// the wanted changes only. The user's profile is never touched.

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
        // The files of build 3143 this patch changes, by their checksum as they
        // come with the client. Before anything is written, the original of
        // every file to change - its backup once changed - has to match;
        // another build is refused rather than patched where its markup may
        // differ. The translations of language packages are not listed: they
        // come in versions of their own, and only addresses inside their
        // sentences are changed there.

        static readonly Dictionary<string, string> Originals = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { @"imApp\content\data.dtd", "FA3E177B9BBE096922AFCA5F11DCA347D14E62C6B2D76E83AE1724E88EAB8685" },
            { @"imApp\content\MUICore\MainDlg.box", "AC16E8131AAD78B82ECBE502C0B10A0223204F50C7F83FA7529BC5844BF795DE" },
            { @"imApp\content\MUICore\MainDlgPanelOwner.box", "B499DE0AB43F61738760838CCAB061D2C799C9D0ABBF206FDA39678C6E503FD6" },
            { @"imApp\content\MUICore\PopupMenus.box", "121C60DB9922BE901A109673686808476A874A1183A923B1DC03239660F8392D" },
            { @"imApp\content\MUICore\HistorySearchDlg.box", "A4BDD3630F4DA954B2E5E0765C9042B68498D3150CCE800EF6BF0CAF88F00285" },
            { @"imApp\content\MUICore\ContactList\MiniUserProfileDlg.gadgets.box", "BFF7BD00E07F0CD6C3842EAC048F430C3C4C67D7AAC7F4C5AE12A1C971A8A04A" },
            { @"imApp\content\MUICore\Preferences\OPrefsPanelNotifications.box", "F9C3BA5A0C8B51F020057E6BFB8CC0D6C2DFA0C2E41BB0E409F4ED2A0D70FB08" },
            { @"imApp\content\MUICore\Preferences\OPrefsPanelHistory.box", "D01350E6CE40DDCD6DFEA9E0EFD1DF3146379D5595C4C015F4DDBA5042FC818F" },
            { @"imApp\content\MUICore\Preferences\OPrefsPanelSkin.box", "5E968717120B8FFBD1F0779CC64481F3D3D48A0221FA5F36CC7D27FCF227DD8F" },
            { @"imApp\content\MUIMessage\MsgSessionPanel.box", "92849D6782F57B5E05F88FDA2AA7B499F48FF88545BBF70ABFF4FC942B73BC0D" },
            { @"imApp\theme\MUICore\MainDlgPanelOwner.style.box", "1F75401091A588573BAA1B167C58D826A9F9A9398708EE442C4CA568A52FE1D6" },
            { @"imApp\theme\MUIMessage\MsgSessionDlg.style.box", "B101615D74BC8B51B42CC494C129806062165E8F17D72E36F3235C5970D247B9" },
            { @"packages\ICQ\ConfigFiles\AppConfig.xml", "34CB955EFAE0268EC76FEA4C0EF8C4A18C5A5C145BC58DEA2F31531A0D7662E8" },
            { @"packages\ICQ\ConfigFiles\links.xml", "8E9E685E516C778F26830162C5EC684B7409D5341F0E61ECB2D1E5E55F80D8B4" },
            { @"packages\ICQ\ConfigFiles\System.xml", "D9F222A2B989B6FEE31D3CEF277A2B1575C446B0621B1DC06E16052AC3E11C37" },
            { @"packages\ICQ\ConfigFiles\XtraConfig.xml", "D23E528686726B5C38DD1DC056CCDD5B860681480BA3C3C382D0E05F24161A2C" },
            { @"packages\ICQ\ConfigFiles\SMSConfig.xml", "892182B0206EDD193A88CDDF50F7FB2587A1FF82FC185EC1451ED086D0320BAE" },
            { @"packages\ICQ\ConfigFiles\tzer.xml", "C423F7ED899E71DA064837C6C38F4E8FBCFCB300143FAA2573C06AFB5DB9021D" },
            { @"packages\ICQ\ConfigFiles\adConfig.xml", "33EA75F797723F893FAA5FF04C0E8605716B41098A3DE366CCDE95BCB8421B10" },
            { @"packages\ICQ\ConfigFiles\UIOwnerPanelConfig.xml", "01F398318EBE909419B66A4F36E7BF834F9168A734E54FE0C682C041E2C763BE" },
            { @"imApp\resources\en-US\AboutDlg.dtd", "4C1227E5F07C1A8D77005AC88440743BBC0210A9EC9C6290EF89F96561DE085A" },
            { @"imApp\resources\en-US\MsgSessionPanel.dtd", "5EF756E965508FFAF20250B3BB573888D0C53A7580DBAF0CA3DA55758C53760C" },
            { @"imApp\resources\en-US\SMS.dtd", "917D549E4BEB72E70F178C1494ABF6A1FC4AF2FF6C78117D681E22BB8B6EFBA7" },
            { @"imApp\resources\en-US\Errors.dtd", "E516C9A97F980A617C665907A72E4B573B20A2EB2E98D4D333FFE0C2E05EDD9B" },
            { @"imApp\resources\en-US\common.dtd", "94D6F7034666D77D467891BA63086698E008D7DF4FCF3D3DF96627B1829588D5" },
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
        // buttons gone the pills are narrowed to the other, with both they are
        // given no size.
        const string MainDlgPanel = Content + @"\MUICore\MainDlgPanelOwner.box";
        const string MainDlgPanelStyle = Theme + @"\MUICore\MainDlgPanelOwner.style.box";
        const string BigPill = "<part name=\"idGamesZonesBtn\" fill=\"url(#imgTranslucentBtn)\" fillSlice=\"7\" fillSize=\"both\" width=\"61\" height=\"26\"";
        const string SmallPill = "<part name=\"idSmallGamesZonesBtn\" fill=\"url(#imgTranslucentBtn)\" fillSlice=\"5 5 5 5\" fillSize=\"both\" width=\"15\" height=\"31\"";

        static bool OneOf(Func<string, bool> wanted) { return wanted("games") != wanted("xtraz"); }
        static bool Both(Func<string, bool> wanted) { return wanted("games") && wanted("xtraz"); }
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

            // The Lifestream and "My box" (mail) tabs, each a job of its own.
            On(OwnerTabs, "the Lifestream tab", DropTab("LifeStream")),
            On(OwnerTabs, "the \"My box\" tab", DropTab("MeTab")),

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
            j.Add("lifestream", "Services that are gone", "the Lifestream tab (feeds from friends)");
            j.Add("mailbox", "Services that are gone", "the \"My box\" mail tab");
            j.Add("ads", "Advertising", "advertising: the ad slots, boxes and the empty bands they leave");
            j.Add("fix", "Fixes", "the AOL Diagnostics module that crashes ICQ 7 (tbdiag.dll)");
            j.Add("links", "Your server", "the pages the client opens point at your server");
            j.Add("sign-in", "Your server", "automatic connection and voice calls use your server");

            j.Assign("the SMS tab of the main window", "sms");
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
            j.Assign("the Lifestream tab", "lifestream");
            j.Assign("the \"My box\" tab", "mailbox");
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
            return j;
        }

        // --- state ------------------------------------------------------------------------

        public string Root;

        public Icq72Client(string root)
        {
            Root = root;
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

        // The file as the client came with it, from this patch's backup; null
        // while the file has not been changed yet.
        static string OriginalText(string path)
        {
            return PatchFiles.Exists(path + Suffix) ? PatchFiles.ReadText(path + Suffix).Text : null;
        }

        // Whether the original of a listed file - its backup once changed - is
        // not the one from build 3143.
        bool IsOtherVersion(string relative)
        {
            string known;
            if (!Originals.TryGetValue(relative, out known)) return false;
            string path = At(relative);
            string source = PatchFiles.Exists(path + Suffix) ? path + Suffix : path;
            return PatchFiles.Exists(source) && !Ps.Eq(PatchFiles.Sha256(source), known);
        }

        // original / patched / other version / unknown (nothing to change:
        // the markup is not what the change expects) / missing
        string ChangeState(Change c, string relative, string domain)
        {
            string path = At(relative);
            if (!PatchFiles.Exists(path)) return "missing";
            if (IsOtherVersion(relative)) return "other version";
            string current = PatchFiles.ReadText(path).Text;
            string original = OriginalText(path) ?? current;
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
            return Jobs.Merge(items);
        }

        // --- applying ---------------------------------------------------------------------

        // Makes the client match the selection and gives what changed, one line
        // per job. Throws, before anything is written, when a file to change is
        // not the one from build 3143.
        public List<string> ApplyAll(string domain, ICollection<string> skip)
        {
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
                    throw new InvalidOperationException(f.Key + " is not the one from ICQ 7.2 build 3143; nothing was changed.");
                }
            }

            PatchSteps.Start(2 + files.Count + Removals.Length);
            PatchSteps.Step("Checking the client...");
            List<PatchItem> before = Items(domain);

            // Each file is built again from the original with the wanted changes.
            foreach (var f in files)
            {
                PatchSteps.Step("Building " + PatchFiles.Leaf(f.Key) + "...");
                string path = At(f.Key);
                if (!PatchFiles.Exists(path)) continue;
                TextFile file = PatchFiles.ReadText(path);
                string text = OriginalText(path) ?? file.Text;
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
                    if (state == "original") PatchFiles.Rename(path, PatchFiles.Leaf(path) + Suffix);
                }
                else if (state == "patched")
                {
                    PatchFiles.Rename(path + Suffix, PatchFiles.Leaf(path));
                }
            }

            var report = new List<string>();
            PatchSteps.Step("Checking the result...");
            List<PatchItem> after = Items(domain);
            for (int i = 0; i < after.Count; i++)
            {
                if (Ps.Eq(after[i].State, before[i].State)) continue;
                if (Ps.Eq(after[i].State, "patched")) report.Add("applied: " + after[i].What);
                else report.Add("taken out: " + after[i].What);
            }
            return report;
        }

        // Puts every backup back where it came from and gives how many.
        public int RestoreAll()
        {
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
