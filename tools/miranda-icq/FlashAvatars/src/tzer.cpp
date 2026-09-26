/*
FlashAvatars: tZers, the short animations with sound ICQ 6 sends, played over
the message window by the same engine as the avatars.

Receiving: our IcqOscarJ port turns a tZer into a message in the history
("tZer: <name>") and fires ME_ICQ_TZER with the movie's address; this module
plays the movie over the contact's message window, or when that window next
opens. Sending: a button of the message window offers the twelve tZers our
server has; IcqOscarJ sends the one picked the way ICQ 6.5 does
(PS_ICQ_SENDTZER), and it plays here too, as in ICQ 6.5.

The movies are played as ICQ 6.5 plays them: in a layered popup window of the
engine's own FlashPlayerControl class (FPC_* exports), with sound. It closes
when the movie ends (fscommand "animEnd", FPC_IsPlaying false), on a click, or
after 40 seconds.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation version 2
of the License.
*/

#include "stdafx.h"

// ICQ's tZers capability, {B2EC8F16-7C6F-451B-BD79-DC58497888B9}: ICQ 6
// offers tZers to contacts that announce it.
static const BYTE capTzers[0x10] = {
	0xB2, 0xEC, 0x8F, 0x16, 0x7C, 0x6F, 0x45, 0x1B, 0xBD, 0x79, 0xDC, 0x58, 0x49, 0x78, 0x88, 0xB9
};

// The tZers of our server (deploy/oscar-legacy-web/tzers), with the ids ICQ
// 6.5 gives them in ConfigFiles\tzer.xml (sic: "sorry " with a space) and
// the titles of its English TzerLabels.dtd.
static const struct
{
	const char *id, *file;
	const wchar_t *name;
}
g_tzers[] =
{
	{ "gangSh",  "gangsta",   LPGENW("Gangsta'") },
	{ "cantH",   "canthearu", LPGENW("Can't Hear U") },
	{ "scratch", "skratch",   LPGENW("Scratch") },
	{ "boo",     "boo",       LPGENW("Booooo") },
	{ "kisses",  "kisses",    LPGENW("Kisses") },
	{ "rasta",   "chillout",  LPGENW("Chill Out") },
	{ "arakiri", "akitaka",   LPGENW("Akitaka") },
	{ "laugh",   "laugh",     LPGENW("Hilaaarious") },
	{ "da",      "duh",       LPGENW("Like Duh!") },
	{ "beback",  "beback",    LPGENW("L8R") },
	{ "ilikeu",  "likeu",     LPGENW("Like U!") },
	{ "sorry ",  "sorry",     LPGENW("I'm Sorry") },
};

#define TZER_BUTTON   1
#define TZER_TIMER    0x545A
#define TZER_TICK     200
#define TZER_GRACE    1500   // FPC_IsPlaying is true while the movie loads, but give it time
#define TZER_TIMEOUT  40000
#define TZER_PENDING  120    // seconds a received tZer waits for its window

static IconItem iconList[] =
{
	{ LPGEN("tZers"), "tzer", IDI_TZER }
};

/////////////////////////////////////////////////////////////////////////////////////////
// Where the account's tZers are, as ICQ 6.5 addresses them: the legacy web
// pages of the server it signs in to, http://<host>:8101/icq/tzers/, so that
// every recipient can fetch them. Nothing to fill in by hand. The hidden
// setting ICQ/TzerBase (a full base URL) overrides it for a test setup;
// ICQ/WebBase (the web pages address) is used only without a sign-in server,
// as it may be a local address others cannot reach.

#define TZER_PORT 8101
#define TZER_PATH "/icq/tzers/"

static CMStringA CleanBase(const char *szBase)
{
	CMStringA ret(szBase ? szBase : "");
	ret.Trim();
	while (!ret.IsEmpty() && ret[ret.GetLength() - 1] == '/')
		ret.Truncate(ret.GetLength() - 1);
	if (_strnicmp(ret, "http://", 7) && _strnicmp(ret, "https://", 8))
		return CMStringA();
	return ret;
}

static CMStringA TzerBase(const char *szProto)
{
	CMStringA ret(CleanBase(ptrA(db_get_sa(0, szProto, "TzerBase"))));
	if (!ret.IsEmpty())
		return ret + "/";

	// the sign-in server, without a port
	CMStringA szHost(ptrA(db_get_sa(0, szProto, "OscarServer")));
	szHost.Trim();
	int iColon = szHost.Find(':');
	if (iColon != -1)
		szHost.Truncate(iColon);
	if (!szHost.IsEmpty())
		return CMStringA(FORMAT, "http://%s:%d" TZER_PATH, szHost.c_str(), TZER_PORT);

	ret = CleanBase(ptrA(db_get_sa(0, szProto, "WebBase")));
	return ret.IsEmpty() ? ret : ret + TZER_PATH;
}

static bool CanSendTzers(MCONTACT hContact)
{
	const char *szProto = Proto_GetBaseAccountName(hContact);
	return szProto && ProtoServiceExists(szProto, PS_ICQ_SENDTZER);
}

/////////////////////////////////////////////////////////////////////////////////////////
// What was played last per contact, for the replay, and what waits for a window

struct TzerEntry
{
	MCONTACT hContact;
	CMStringA szUrl, szName;
	time_t tm;
	bool bPending;
};

static std::vector<TzerEntry> g_last; // main thread only

static TzerEntry* FindEntry(MCONTACT hContact)
{
	for (auto &it : g_last)
		if (it.hContact == hContact)
			return &it;
	return nullptr;
}

/////////////////////////////////////////////////////////////////////////////////////////
// The player

typedef BOOL(WINAPI *pfnRegisterClass)();
typedef HRESULT(WINAPI *pfnLoadMovie)(HWND, int, LPCWSTR);
typedef HRESULT(WINAPI *pfnHwnd)(HWND);
typedef HRESULT(WINAPI *pfnIsPlaying)(HWND, short *);

static pfnRegisterClass pRegisterClass;
static pfnLoadMovie pLoadMovie;
static pfnHwnd pPlay, pUpdateWindow;
static pfnIsPlaying pIsPlaying;

static HWND g_hwndTzer;
static WNDPROC g_origTzerProc;
static DWORD g_dwTzerStart;

static bool LoadPlayer()
{
	if (pLoadMovie)
		return true;

	HMODULE hEngine = LoadEngine();
	if (hEngine == nullptr)
		return false;

	pRegisterClass = (pfnRegisterClass)GetProcAddress(hEngine, "RegisterFlashWindowClass");
	pLoadMovie = (pfnLoadMovie)GetProcAddress(hEngine, "FPC_LoadMovieW");
	pPlay = (pfnHwnd)GetProcAddress(hEngine, "FPC_Play");
	pUpdateWindow = (pfnHwnd)GetProcAddress(hEngine, "FPC_UpdateWindow");
	pIsPlaying = (pfnIsPlaying)GetProcAddress(hEngine, "FPC_IsPlaying");
	if (!pRegisterClass || !pLoadMovie || !pPlay || !pUpdateWindow || !pIsPlaying) {
		Log("tZers: the engine lacks the FPC_* exports");
		pLoadMovie = nullptr;
		return false;
	}
	return pRegisterClass() != 0;
}

static void StopTzer()
{
	if (g_hwndTzer) {
		HWND hwnd = g_hwndTzer;
		g_hwndTzer = nullptr;
		DestroyWindow(hwnd);
	}
}

static LRESULT CALLBACK TzerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_TIMER:
		if (wParam == TZER_TIMER) {
			DWORD dwElapsed = GetTickCount() - g_dwTzerStart;
			short playing = -1;
			if (dwElapsed > TZER_GRACE)
				pIsPlaying(hwnd, &playing);
			if (!playing || dwElapsed > TZER_TIMEOUT) {
				Log("tZer done after %d ms (%s)", dwElapsed, playing ? "timeout" : "end of movie");
				KillTimer(hwnd, TZER_TIMER);
				PostMessage(hwnd, WM_CLOSE, 0, 0);
			}
			return 0;
		}
		break;

	case WM_LBUTTONDOWN:
	case WM_RBUTTONDOWN:
		PostMessage(hwnd, WM_CLOSE, 0, 0);
		return 0;

	case WM_CLOSE:
		if (g_hwndTzer == hwnd)
			g_hwndTzer = nullptr;
		DestroyWindow(hwnd);
		return 0;

	case WM_NCDESTROY:
		{
			LRESULT res = CallWindowProc(g_origTzerProc, hwnd, msg, wParam, lParam);
			if (g_hwndTzer == hwnd)
				g_hwndTzer = nullptr;
			return res;
		}
	}
	return CallWindowProc(g_origTzerProc, hwnd, msg, wParam, lParam);
}

// Plays the movie (a cached file) over the message window hwndMsg.
static void PlayFile(HWND hwndMsg, const CMStringW &file)
{
	if (!LoadPlayer())
		return;

	StopTzer();

	// over the window the message window is in (tabSRMM: its container)
	HWND hwndOwner = hwndMsg ? GetAncestor(hwndMsg, GA_ROOT) : nullptr;
	RECT rc;
	if (hwndOwner && IsWindowVisible(hwndOwner) && !IsIconic(hwndOwner))
		GetWindowRect(hwndOwner, &rc);
	else
		SystemParametersInfo(SPI_GETWORKAREA, 0, &rc, 0);

	// the movies are 755x560; as large as fits, at most their own size
	int cx = rc.right - rc.left, cy = rc.bottom - rc.top;
	int w = min(755, cx * 9 / 10), h = w * 560 / 755;
	if (h > cy * 9 / 10) {
		h = cy * 9 / 10;
		w = h * 755 / 560;
	}
	int x = rc.left + (cx - w) / 2, y = rc.top + (cy - h) / 2;

	// as ICQ 6.5 creates it: a layered, non-activating tool popup; with an
	// owner, so that it plays its sound
	HWND hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST, L"FlashPlayerControl", nullptr,
		WS_POPUP | WS_VISIBLE, x, y, w, h, hwndOwner, nullptr, GetModuleHandle(nullptr), nullptr);
	if (hwnd == nullptr) {
		Log("tZers: cannot create the player window (%d)", GetLastError());
		return;
	}

	g_origTzerProc = (WNDPROC)SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)TzerWndProc);
	g_hwndTzer = hwnd;
	g_dwTzerStart = GetTickCount();

	HRESULT hr = pLoadMovie(hwnd, 0, file);
	pPlay(hwnd);
	pUpdateWindow(hwnd);
	SetTimer(hwnd, TZER_TIMER, TZER_TICK, nullptr);
	Log("tZer %S playing at %d,%d %dx%d: %08X", file.c_str(), x, y, w, h, hr);
}

/////////////////////////////////////////////////////////////////////////////////////////
// Playing a tZer: the movie is fetched once, then played over the window.

struct PlayJob
{
	MCONTACT hContact;
	CMStringA szUrl;
	CMStringW file;
	bool ok;
};

static void MIR_SYSCALL PlayJobDone(void *param)
{
	PlayJob *job = (PlayJob *)param;
	if (job->ok)
		PlayFile(Srmm_FindWindow(job->hContact), job->file);
	delete job;
}

static void __cdecl FetchThread(void *param)
{
	PlayJob *job = (PlayJob *)param;
	job->ok = DownloadFile(job->szUrl, job->file, true);
	CallFunctionAsync(PlayJobDone, job);
}

static void PlayTzer(MCONTACT hContact, const CMStringA &szUrl)
{
	CMStringW file = MovieFile(szUrl, L".swf");
	if (!_waccess(file, 0)) {
		PlayFile(Srmm_FindWindow(hContact), file);
		return;
	}

	PlayJob *job = new PlayJob();
	job->hContact = hContact;
	job->szUrl = szUrl;
	job->file = file;
	mir_forkthread(FetchThread, job);
}

/////////////////////////////////////////////////////////////////////////////////////////
// ME_ICQ_TZER: a tZer arrived or was sent (any thread)

struct TzerJob
{
	MCONTACT hContact;
	CMStringA szUrl, szName;
	bool bSent;
};

static void MIR_SYSCALL TzerJobProc(void *param)
{
	TzerJob *job = (TzerJob *)param;

	TzerEntry *e = FindEntry(job->hContact);
	if (e == nullptr) {
		g_last.push_back(TzerEntry());
		e = &g_last.back();
		e->hContact = job->hContact;
	}
	e->szUrl = job->szUrl;
	e->szName = job->szName;
	e->tm = time(0);

	HWND hwnd = Srmm_FindWindow(job->hContact);
	if (job->bSent || (hwnd && IsWindowVisible(GetAncestor(hwnd, GA_ROOT)))) {
		e->bPending = false;
		PlayTzer(job->hContact, job->szUrl);
	}
	else e->bPending = true; // when its window opens

	delete job;
}

static int OnTzer(WPARAM hContact, LPARAM lParam)
{
	ICQ_TZER *tz = (ICQ_TZER *)lParam;
	if (tz == nullptr || tz->cbSize < (int)sizeof(ICQ_TZER) || tz->szUrl == nullptr)
		return 0;

	TzerJob *job = new TzerJob();
	job->hContact = hContact;
	job->szUrl = tz->szUrl;
	job->szName = tz->szName ? tz->szName : "";
	job->bSent = tz->bSent != 0;
	CallFunctionAsync(TzerJobProc, job);
	return 0;
}

// A message window opens: a tZer that came meanwhile plays now.
static void MIR_SYSCALL PlayPending(void *param)
{
	MCONTACT hContact = (MCONTACT)(INT_PTR)param;
	TzerEntry *e = FindEntry(hContact);
	if (e && e->bPending) {
		e->bPending = false;
		if (time(0) - e->tm < TZER_PENDING)
			PlayTzer(hContact, e->szUrl);
	}
}

static int OnWindowEvent(WPARAM uType, LPARAM lParam)
{
	auto *pDlg = (CSrmmBaseDialog *)lParam;
	if (pDlg == nullptr || pDlg->m_hContact == 0)
		return 0;

	if (uType == MSG_WINDOW_EVT_OPENING && !CanSendTzers(pDlg->m_hContact)) {
		BBButton bbd = {};
		bbd.pszModuleName = MODULENAME;
		bbd.dwButtonID = TZER_BUTTON;
		bbd.bbbFlags = BBSF_HIDDEN | BBSF_DISABLED;
		Srmm_SetButtonState(pDlg->m_hContact, &bbd);
	}
	else if (uType == MSG_WINDOW_EVT_OPEN)
		CallFunctionAsync(PlayPending, (void *)(INT_PTR)pDlg->m_hContact);
	else if (uType == MSG_WINDOW_EVT_CLOSING && g_hwndTzer && GetWindow(g_hwndTzer, GW_OWNER) == GetAncestor(pDlg->GetHwnd(), GA_ROOT))
		StopTzer();
	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////
// Sending: the button of the message window and its menu of tZers

static HBITMAP g_thumbs[_countof(g_tzers)];
static bool g_bThumbsFetching;

struct ThumbJob
{
	CMStringA szBase;
};

static void __cdecl ThumbThread(void *param)
{
	ThumbJob *job = (ThumbJob *)param;
	for (auto &it : g_tzers) {
		CMStringA szUrl(job->szBase + it.file + ".png");
		CMStringW file = MovieFile(szUrl, L".png");
		if (_waccess(file, 0))
			DownloadFile(szUrl, file, false);
	}
	delete job;
	g_bThumbsFetching = false;
}

static HBITMAP Thumb(int i, const CMStringA &szBase)
{
	if (g_thumbs[i])
		return g_thumbs[i];

	CMStringW file = MovieFile(szBase + g_tzers[i].file + ".png", L".png");
	if (_waccess(file, 0))
		return nullptr;

	HBITMAP hbm = Image_Load(file);
	if (hbm) {
		HBITMAP hbmSmall = Image_Resize(hbm, RESIZEBITMAP_KEEP_PROPORTIONS, 40, 30);
		if (hbmSmall != hbm)
			DeleteObject(hbm);
		g_thumbs[i] = hbmSmall;
	}
	return g_thumbs[i];
}

static void SendTzer(MCONTACT hContact, int i, const CMStringA &szBase)
{
	const char *szProto = Proto_GetBaseAccountName(hContact);
	if (szProto == nullptr)
		return;

	CMStringA szUrl(szBase + g_tzers[i].file + ".swf"), szThumb(szBase + g_tzers[i].file + ".png");
	T2Utf szName(TranslateW_LP(g_tzers[i].name, &g_plugin));

	ICQ_TZER tz = { sizeof(tz), g_tzers[i].id, szName, szUrl, szThumb, 1 };
	if (CallProtoService(szProto, PS_ICQ_SENDTZER, hContact, (LPARAM)&tz))
		MessageBoxW(nullptr, TranslateT("The tZer could not be sent: the account is offline or the contact is not an ICQ contact."), TranslateT("tZers"), MB_OK | MB_ICONINFORMATION);
}

static int OnButtonPressed(WPARAM hContact, LPARAM lParam)
{
	auto *cbcd = (CustomButtonClickData *)lParam;
	if (mir_strcmp(cbcd->pszModule, MODULENAME) || cbcd->dwButtonId != TZER_BUTTON)
		return 0;

	const char *szProto = Proto_GetBaseAccountName(hContact);
	if (szProto == nullptr)
		return 0;

	CMStringA szBase(TzerBase(szProto));
	if (szBase.IsEmpty()) {
		Log("tZers: account %s has no sign-in server set", szProto);
		return 0;
	}

	// the thumbnails: fetched once, in the background
	bool bMissing = false;
	for (int i = 0; i < _countof(g_tzers); i++)
		if (!Thumb(i, szBase))
			bMissing = true;
	if (bMissing && !g_bThumbsFetching) {
		g_bThumbsFetching = true;
		ThumbJob *job = new ThumbJob();
		job->szBase = szBase;
		mir_forkthread(ThumbThread, job);
	}

	HMENU hMenu = CreatePopupMenu();
	for (int i = 0; i < _countof(g_tzers); i++) {
		AppendMenuW(hMenu, MF_STRING | ((i && i % 6 == 0) ? MF_MENUBARBREAK : 0), i + 1, TranslateW_LP(g_tzers[i].name, &g_plugin));
		if (HBITMAP hbm = Thumb(i, szBase)) {
			MENUITEMINFOW mii = { sizeof(mii) };
			mii.fMask = MIIM_BITMAP;
			mii.hbmpItem = hbm;
			SetMenuItemInfoW(hMenu, i + 1, FALSE, &mii);
		}
	}


	int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, cbcd->pt.x, cbcd->pt.y, 0, cbcd->hwndFrom, nullptr);
	if (cmd == 0)
		Log("tZers: menu at %d,%d closed without a choice (%d)", cbcd->pt.x, cbcd->pt.y, GetLastError());
	DestroyMenu(hMenu);

	if (cmd >= 1 && cmd <= _countof(g_tzers))
		SendTzer(hContact, cmd - 1, szBase);

	return 0;
}

static int OnToolbarLoaded(WPARAM, LPARAM)
{
	BBButton bbd = {};
	bbd.pszModuleName = MODULENAME;
	bbd.dwButtonID = TZER_BUTTON;
	bbd.pwszTooltip = LPGENW("Send a tZer");
	bbd.dwDefPos = 310;
	bbd.bbbFlags = BBBF_ISIMBUTTON | BBBF_CANBEHIDDEN;
	bbd.hIcon = iconList[0].hIcolib;
	g_plugin.addButton(&bbd);
	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////

void Tzers_ModulesLoaded()
{
	g_plugin.registerIcon(LPGEN("Flash avatars"), iconList, MODULENAME);

	// every ICQ account of our port: its tZers, and tell servers we play them
	for (auto &pa : Accounts()) {
		if (!ProtoServiceExists(pa->szModuleName, PS_ICQ_SENDTZER))
			continue;
		HookEvent(CMStringA(pa->szModuleName) + ME_ICQ_TZER, OnTzer);
		if (LoadEngine())
			AddIcqCapability(pa->szModuleName, capTzers, "tZers");
	}

	HookTemporaryEvent(ME_MSG_TOOLBARLOADED, OnToolbarLoaded);
	HookEvent(ME_MSG_BUTTONPRESSED, OnButtonPressed);
	HookEvent(ME_MSG_WINDOWEVENT, OnWindowEvent);
}

void Tzers_Unload()
{
	StopTzer();
	for (auto &hbm : g_thumbs)
		if (hbm) {
			DeleteObject(hbm);
			hbm = nullptr;
		}
}
