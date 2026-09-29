// ---------------------------------------------------------------------------80
//                ICQ plugin for Miranda Instant Messenger
//                ________________________________________
//
// Copyright © 2000-2001 Richard Hughes, Roland Rabien, Tristan Van de Vreede
// Copyright © 2001-2002 Jon Keating, Richard Hughes
// Copyright © 2002-2004 Martin Öberg, Sam Kothari, Robert Rainwater
// Copyright © 2004-2010 Joe Kucera
// Copyright © 2012-2018 Miranda NG team
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
// -----------------------------------------------------------------------------

#include "stdafx.h"

#include "m_extraicons.h"
#include "m_icolib.h"

BOOL bPopupService = FALSE;

HANDLE hExtraXStatus;

/////////////////////////////////////////////////////////////////////////////////////////

static PLUGININFOEX pluginInfoEx = {
	sizeof(PLUGININFOEX),
	__PLUGIN_NAME,
	PLUGIN_MAKE_VERSION(__MAJOR_VERSION, __MINOR_VERSION, __RELEASE_NUM, __BUILD_NUM),
	__DESCRIPTION,
	__AUTHOR,
	__COPYRIGHT,
	__AUTHORWEB,
	UNICODE_AWARE,   //doesn't replace anything built-in
	{ 0xa5b4a32d, 0xd2a8, 0x4925, { 0xae, 0x3e, 0x14, 0x80, 0xe4, 0x1a, 0x7, 0xb3 } } // {A5B4A32D-D2A8-4925-AE3E-1480E41A07B3}
};

CMPlugin::CMPlugin() :
	ACCPROTOPLUGIN<CIcqProto>(ICQ_PROTOCOL_NAME, pluginInfoEx)
{
	SetUniqueId(UNIQUEIDSETTING);
}

/////////////////////////////////////////////////////////////////////////////////////////

extern "C" __declspec(dllexport) const MUUID MirandaInterfaces[] = { MIID_PROTOCOL, MIID_LAST };

/////////////////////////////////////////////////////////////////////////////////////////

CMPlugin g_plugin;

/////////////////////////////////////////////////////////////////////////////////////////

int ModuleLoad(WPARAM, LPARAM)
{
	bPopupService = ServiceExists(MS_POPUP_ADDPOPUPW);
	return 0;
}

IconItem iconList[] =
{
	{ LPGEN("Expand string edit"), "ICO_EXPANDSTRINGEDIT", IDI_EXPANDSTRINGEDIT }
};

/////////////////////////////////////////////////////////////////////////////////////////
// PluginUpdater compares every file it knows by name with the list of its
// update server and replaces it with the server's copy, or deletes it when a
// server rule says so. The Miranda NG list knows nothing of this port, so
// against it our files are left out of both by the hidden setting
// PluginUpdaterFiles/<path relative to the Miranda folder, lower case> = 2.
//
// Our sign-in server hands out the same list with our files in it (the legacy
// web pages, /miranda/stable/x32 and /x64), so PluginUpdater is pointed there:
// custom mode, https://<sign-in host>:8102/miranda/stable/x%platform%, where
// PluginUpdater puts 32 or 64 in place of %platform%. Only when the user has
// not chosen an address of their own: the one written here is remembered in
// IcqRevival/UpdateURL, and once PluginUpdater's differs from it, it is the
// user's and stays. The hidden IcqRevival/UpdateBase (a full base address,
// without /x..) replaces the derived one, for a test setup.
//
// While PluginUpdater takes our list, the marks are taken back so that it
// updates our files too; otherwise they stay. Every start, written only when
// they change.

#define REVIVAL_MODULE "IcqRevival"
#define UPDATE_PORT    8102
#define UPDATE_PATH    "/miranda/stable"
#define OUR_MODULE     L"Plugins\\IcqOscarJ.dll"

// Our other files the list names; IcqRevivalFlash marks its own as well.
static const wchar_t *g_arOurFiles[] =
{
	L"Plugins\\IcqRevivalFlash.dll",
	L"Libs\\FlashPlayerControl.dll",
	L"Languages\\langpack_russian_icq.txt",
	L"Languages\\langpack_russian_icqrevivalflash.txt",
	L"Languages\\langpack_ukrainian_icq.txt",
	L"Languages\\langpack_ukrainian_icqrevivalflash.txt"
};

// The Flash plugin was FlashAvatars.dll up to 1.0: Miranda NG's list deletes
// that name (the plugin it removed in 2014), ours moves it to the new one.
// A mark left on an old file would keep that move from happening, so it goes
// while our list is used or once the file is gone; an old file still in place
// under the Miranda NG list keeps it, or that list would delete the file.
static const wchar_t *g_arOldFiles[] =
{
	L"Plugins\\FlashAvatars.dll",
	L"Languages\\langpack_russian_flashavatars.txt"
};

static void ClearOldMark(const wchar_t *pwszRelPath, bool bOurList)
{
	if (!bOurList) {
		wchar_t wszPath[MAX_PATH];
		if (!GetModuleFileNameW(nullptr, wszPath, MAX_PATH))
			return;
		wchar_t *p = wcsrchr(wszPath, '\\');
		if (p == nullptr)
			return;
		wcsncpy_s(p + 1, MAX_PATH - (p + 1 - wszPath), pwszRelPath, _TRUNCATE);
		if (GetFileAttributesW(wszPath) != INVALID_FILE_ATTRIBUTES)
			return;
	}

	CMStringA szKey(pwszRelPath);
	szKey.MakeLower();
	db_unset(0, "PluginUpdaterFiles", szKey);
}

static void MarkForUpdater(const wchar_t *pwszRelPath, bool bProtect)
{
	CMStringA szKey(pwszRelPath);
	szKey.MakeLower();
	int iMark = db_get_b(0, "PluginUpdaterFiles", szKey, 1);
	if (bProtect && iMark != 2)
		db_set_b(0, "PluginUpdaterFiles", szKey, 2);
	else if (!bProtect && iMark == 2)
		db_unset(0, "PluginUpdaterFiles", szKey);
}

// The module under the name the list gives it is updated from our list; under
// any other name (ICQ.dll, say) the list would bring a stranger's file, so it
// stays protected.
static void MarkModuleForUpdater(HINSTANCE hInst, bool bOurList)
{
	wchar_t wszExe[MAX_PATH], wszDll[MAX_PATH];
	if (!GetModuleFileNameW(nullptr, wszExe, MAX_PATH) || !GetModuleFileNameW(hInst, wszDll, MAX_PATH))
		return;
	wchar_t *p = wcsrchr(wszExe, '\\');
	if (p == nullptr)
		return;
	size_t cbBase = p - wszExe + 1;
	if (!_wcsnicmp(wszExe, wszDll, cbBase)) {
		const wchar_t *pwszRel = wszDll + cbBase;
		MarkForUpdater(pwszRel, !bOurList || mir_wstrcmpi(pwszRel, OUR_MODULE));
	}
}

static bool UpdaterUsesOurList()
{
	if (db_get_b(0, "PluginUpdater", "UpdateMode", 0xFF) != 0)
		return false;
	ptrA szCur(db_get_sa(0, "PluginUpdater", "UpdateURL")), szOurs(db_get_sa(0, REVIVAL_MODULE, "UpdateURL"));
	return szCur && szOurs && *szOurs && !mir_strcmp(szCur, szOurs);
}

static CMStringA OurUpdateUrl()
{
	CMStringA szBase(ptrA(db_get_sa(0, REVIVAL_MODULE, "UpdateBase")));
	szBase.Trim();
	while (!szBase.IsEmpty() && szBase[szBase.GetLength() - 1] == '/')
		szBase.Truncate(szBase.GetLength() - 1);
	if (!_strnicmp(szBase, "http://", 7) || !_strnicmp(szBase, "https://", 8))
		return szBase + "/x%platform%";

	// the sign-in server of the first account that has one of its own
	for (auto &pa : Accounts()) {
		if (mir_strcmp(pa->szProtoName, ICQ_PROTOCOL_NAME) || !pa->bIsEnabled)
			continue;
		CMStringA szHost(ptrA(db_get_sa(0, pa->szModuleName, "OscarServer")));
		szHost.Trim();
		int iColon = szHost.Find(':');
		if (iColon != -1)
			szHost.Truncate(iColon);
		if (szHost.IsEmpty() || !mir_strcmpi(szHost, DEFAULT_SERVER_HOST) || !mir_strcmpi(szHost, DEFAULT_SERVER_HOST_SSL))
			continue;
		return CMStringA(FORMAT, "https://%s:%d" UPDATE_PATH "/x%%platform%%", szHost.c_str(), UPDATE_PORT);
	}
	return CMStringA();
}

static void PointUpdaterAtServer()
{
	CMStringA szUrl(OurUpdateUrl());
	if (szUrl.IsEmpty())
		return;

	int iMode = db_get_b(0, "PluginUpdater", "UpdateMode", 0xFF);
	ptrA szCur(db_get_sa(0, "PluginUpdater", "UpdateURL")), szLast(db_get_sa(0, REVIVAL_MODULE, "UpdateURL"));
	bool bCustom = (iMode == 0 && szCur && *szCur);
	if (szLast && *szLast) {
		// set up before and changed since: the user's choice
		if (!bCustom || mir_strcmp(szCur, szLast))
			return;
		// ours and up to date
		if (!mir_strcmp(szLast, szUrl))
			return;
	}
	else if (bCustom)
		return; // an address of the user's own

	db_set_b(0, "PluginUpdater", "UpdateMode", 0);
	db_set_ws(0, "PluginUpdater", "UpdateURL", _A2T(szUrl));
	db_set_s(0, REVIVAL_MODULE, "UpdateURL", szUrl);
}

static int OnModulesLoaded(WPARAM, LPARAM)
{
	// the accounts are known only now
	PointUpdaterAtServer();

	bool bOurList = UpdaterUsesOurList();
	MarkModuleForUpdater(g_plugin.getInst(), bOurList);
	for (auto &it : g_arOurFiles)
		MarkForUpdater(it, !bOurList);
	for (auto &it : g_arOldFiles)
		ClearOldMark(it, bOurList);
	return 0;
}

int CMPlugin::Load()
{
	bool bOurList = UpdaterUsesOurList();
	MarkModuleForUpdater(g_plugin.getInst(), bOurList);
	MarkForUpdater(L"Languages\\langpack_russian_icq.txt", !bOurList);
	MarkForUpdater(L"Languages\\langpack_ukrainian_icq.txt", !bOurList);
	HookEvent(ME_SYSTEM_MODULESLOADED, OnModulesLoaded);

	srand(time(0));
	_tzset();

	// Initialize charset conversion routines
	InitI18N();

	// Register static services
	CreateServiceFunction(ICQ_DB_GETEVENTTEXT_MISSEDMESSAGE, icq_getEventTextMissedMessage);

	// Init extra statuses
	InitXStatusIcons();
	HookEvent(ME_SKIN_ICONSCHANGED, OnReloadIcons);

	HookEvent(ME_SYSTEM_MODULELOAD, ModuleLoad);
	HookEvent(ME_SYSTEM_MODULEUNLOAD, ModuleLoad);

	hExtraXStatus = ExtraIcon_RegisterIcolib("xstatus", LPGEN("ICQ xStatus"), "icq_xstatus13");

	g_plugin.registerIcon("Protocols/ICQ", iconList);

	g_MenuInit();
	return 0;
}

int CMPlugin::Unload()
{
	// destroying contact menu
	g_MenuUninit();
	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////
// UpdateGlobalSettings event

void CIcqProto::UpdateGlobalSettings()
{
	char szServer[MAX_PATH] = "";
	getSettingStringStatic(NULL, "OscarServer", szServer, MAX_PATH);

	m_bSecureConnection = getByte("SecureConnection", DEFAULT_SECURE_CONNECTION);
	if (szServer[0]) {
		if (strstr(szServer, "aol.com"))
			setString("OscarServer", m_bSecureConnection ? DEFAULT_SERVER_HOST_SSL : DEFAULT_SERVER_HOST);

		if (m_bSecureConnection && !_strnicmp(szServer, "login.", 6)) {
			setString("OscarServer", DEFAULT_SERVER_HOST_SSL);
			setWord("OscarPort", DEFAULT_SERVER_PORT_SSL);
		}
	}

	if (m_hNetlibUser) {
		NETLIBUSERSETTINGS nlus = { sizeof(NETLIBUSERSETTINGS) };
		if (!m_bSecureConnection && Netlib_GetUserSettings(m_hNetlibUser, &nlus)) {
			if (nlus.useProxy && nlus.proxyType == PROXYTYPE_HTTP)
				m_bGatewayMode = 1;
			else
				m_bGatewayMode = 0;
		}
		else m_bGatewayMode = 0;
	}

	m_bSecureLogin = getByte("SecureLogin", DEFAULT_SECURE_LOGIN);
	m_bLegacyFix = getByte("LegacyFix", DEFAULT_LEGACY_FIX);
	m_wAnsiCodepage = getWord("AnsiCodePage", DEFAULT_ANSI_CODEPAGE);
	m_bDCMsgEnabled = getByte("DirectMessaging", DEFAULT_DCMSG_ENABLED);
	m_bTempVisListEnabled = getByte("TempVisListEnabled", DEFAULT_TEMPVIS_ENABLED);
	m_bSsiEnabled = getByte("UseServerCList", DEFAULT_SS_ENABLED);
	m_bSsiSimpleGroups = FALSE; /// TODO: enable, after server-list revolution is over
	m_bAvatarsEnabled = getByte("AvatarsEnabled", DEFAULT_AVATARS_ENABLED);
	m_bXStatusEnabled = getByte("XStatusEnabled", DEFAULT_XSTATUS_ENABLED);
	m_bMoodsEnabled = getByte("MoodsEnabled", DEFAULT_MOODS_ENABLED);
}
