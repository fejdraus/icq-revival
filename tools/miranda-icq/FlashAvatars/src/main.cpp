/*
FlashAvatars: ICQ 6 animated avatars in Miranda NG, played by the Ruffle-based
Flash engine (tools/icq65/flashplayer).

Based on the FlashAvatars plugin (C) 2006 Big Muscle, removed from Miranda NG
in 2014. That plugin offered services ("FlashAvatar/Make", ...) which the
avatar control of AVS, the message windows and the contact list called. None
of them call these services any more, so this one does not offer them: it
takes over the window procedure of the avatar control class instead
(AVATAR_CONTROL_CLASS, AVS) and draws the movie in place of the picture. Every
component that shows avatars through that control shows Flash avatars then:
tabSRMM (the avatar under the message log and the one in the info panel),
Scriver, the plain message window, the user info window.

Where the movie comes from: our IcqOscarJ port keeps the ICQ 6 Flash avatar
(BART type 8) apart from the picture and writes the address of its movie to
the contact's "FlashAvatarUrl" setting in the account's module. The picture
remains the avatar everywhere else (contact list, popups) and under the movie
until the movie has loaded.

Which engine plays it: FlashPlayerControl.dll from the Libs folder, our
drop-in ShockwaveFlash control (tools/icq65/flashplayer), created through its
own DllGetClassObject. No registration is needed or used, so the per-user
registration of ICQ 6.5 is never touched. Without that file the plugin falls
back to whatever ShockwaveFlash control is registered in the system.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation version 2
of the License.
*/

#include "stdafx.h"

CMPlugin g_plugin;

PLUGININFOEX pluginInfoEx =
{
	sizeof(PLUGININFOEX),
	__PLUGIN_NAME,
	PLUGIN_MAKE_VERSION(__MAJOR_VERSION, __MINOR_VERSION, __RELEASE_NUM, __BUILD_NUM),
	__DESCRIPTION,
	__AUTHOR,
	__COPYRIGHT,
	__AUTHORWEB,
	UNICODE_AWARE,
	// {3E5C9A2B-7D41-4F08-B6E2-91A4C7D3F5E8}
	// The original plugin's {72765A6F-B017-42F1-B30F-5E0941273A3F} is on the
	// core's banned list (newplugins.cpp), which unloads it silently.
	{ 0x3e5c9a2b, 0x7d41, 0x4f08, { 0xb6, 0xe2, 0x91, 0xa4, 0xc7, 0xd3, 0xf5, 0xe8 } }
};

CMPlugin::CMPlugin() :
	PLUGIN<CMPlugin>(MODULENAME, pluginInfoEx)
{}

/////////////////////////////////////////////////////////////////////////////////////////
// The ICQ capability announced while this plugin is loaded, so that a server
// knows this client plays Flash avatars and relays the Flash avatar item
// (BART type 8) to it: {B9E03A0C-B33E-4B18-BC0B-7BB5903129AE}, "ICQ Revival:
// Flash avatars". Open OSCAR Server: wire.CapFlashAvatarPlayer.

static const BYTE capFlashAvatars[0x10] = {
	0xB9, 0xE0, 0x3A, 0x0C, 0xB3, 0x3E, 0x4B, 0x18, 0xBC, 0x0B, 0x7B, 0xB5, 0x90, 0x31, 0x29, 0xAE
};

/////////////////////////////////////////////////////////////////////////////////////////
// Logging: the network log (Options - Network - Log), the debugger, and the
// file named by the FLASHAVATARS_LOG environment variable.

HNETLIBUSER g_hNetlib;

void Log(const char *fmt, ...)
{
	char buf[1024];
	va_list va;
	va_start(va, fmt);
	mir_vsnprintf(buf, _countof(buf), fmt, va);
	va_end(va);

	if (g_hNetlib)
		Netlib_Log(g_hNetlib, buf);

	char line[1100];
	mir_snprintf(line, "FlashAvatars: %s\n", buf);
	OutputDebugStringA(line);

	wchar_t path[MAX_PATH];
	if (GetEnvironmentVariableW(L"FLASHAVATARS_LOG", path, _countof(path))) {
		FILE *f = _wfopen(path, L"ab");
		if (f) {
			SYSTEMTIME st;
			GetLocalTime(&st);
			fprintf(f, "%02d:%02d:%02d.%03d %s", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, line);
			fclose(f);
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////////////
// Emotions: the avatar movies have a clip "face" whose "emotion" property
// plays the matching animation (ICQ 6's "devil" gadget sets them the same way).

enum
{
	FACE_STAM, FACE_SMILE, FACE_SAD, FACE_LAUGH, FACE_MAD, FACE_CRY, FACE_LOVE, FACE_BUSY, FACE_OFFLINE
};

static const wchar_t *g_faces[] = { L"stam", L"smile", L"sad", L"laugh", L"mad", L"cry", L"love", L"busy", L"offline" };

static int FaceForStatus(int status)
{
	switch (status) {
	case ID_STATUS_OFFLINE:
		return FACE_OFFLINE;
	case ID_STATUS_ONLINE:
	case ID_STATUS_INVISIBLE:
	case ID_STATUS_FREECHAT:
		return FACE_STAM;
	default:
		return FACE_BUSY;
	}
}

// Smiley codes, compared with the upper-cased message text. The first group
// that has a match wins. After the original plugin, plus a few common codes.
static const struct
{
	int face;
	const wchar_t *codes[12];
}
g_smileys[] =
{
	{ FACE_CRY,   { L":'(", L":'-(", L":`(", L";-(", L";(" } },
	{ FACE_LOVE,  { L":-*", L":*", L":-[", L"*KISSED*", L"*KISSING*", L"@}->--", L"*IN LOVE*", L"<3" } },
	{ FACE_MAD,   { L">:O", L":-@", L":@", L"*STOP*", L"]:->", L"@=" } },
	{ FACE_LAUGH, { L":-D", L":D", L"*JOKINGLY*", L"*ROFL*", L"*LOL*", L"XD" } },
	{ FACE_SAD,   { L":-(", L":(", L":-$", L":-!", L":-X" } },
	{ FACE_SMILE, { L":-)", L":)", L";)", L";-)", L"*THUMBS UP*", L"O:-)", L":P", L":-P", L"*DRINK*", L"=)", L":]" } },
};

static int FaceForText(const wchar_t *text)
{
	CMStringW upper(text);
	upper.MakeUpper();
	for (auto &it : g_smileys)
		for (auto *code : it.codes)
			if (code && wcsstr(upper, code))
				return it.face;
	return -1;
}

/////////////////////////////////////////////////////////////////////////////////////////
// The engine

static HMODULE g_hEngine;
static bool g_bEngineTried;

HMODULE LoadEngine()
{
	if (!g_bEngineTried) {
		g_bEngineTried = true;
		wchar_t path[MAX_PATH];
		PathToAbsoluteW(L"Libs\\FlashPlayerControl.dll", path);
		g_hEngine = LoadLibraryExW(path, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
		Log("engine %S: %s", path, g_hEngine ? "loaded" : "not found, using the registered ShockwaveFlash control");
	}
	return g_hEngine;
}

static IUnknown* CreateFlashObject()
{
	LoadEngine();

	IUnknown *pUnk = nullptr;
	HRESULT hr;
	if (g_hEngine) {
		typedef HRESULT(STDAPICALLTYPE *pfnGetClassObject)(REFCLSID, REFIID, void **);
		auto pGetClassObject = (pfnGetClassObject)GetProcAddress(g_hEngine, "DllGetClassObject");
		if (pGetClassObject == nullptr)
			return nullptr;

		IClassFactory *pFactory = nullptr;
		hr = pGetClassObject(CLSID_ShockwaveFlash, IID_IClassFactory, (void **)&pFactory);
		if (FAILED(hr)) {
			Log("DllGetClassObject: %08X", hr);
			return nullptr;
		}
		hr = pFactory->CreateInstance(nullptr, IID_IUnknown, (void **)&pUnk);
		pFactory->Release();
	}
	else hr = CoCreateInstance(CLSID_ShockwaveFlash, nullptr, CLSCTX_INPROC_SERVER, IID_IUnknown, (void **)&pUnk);

	if (FAILED(hr)) {
		Log("cannot create the Flash control: %08X", hr);
		return nullptr;
	}
	return pUnk;
}

class BStr
{
	BSTR m_p;

public:
	BStr(const wchar_t *s) : m_p(SysAllocString(s)) {}
	~BStr() { SysFreeString(m_p); }
	operator BSTR() const { return m_p; }
};

// Tells the avatar control to repaint when the movie has a new frame.
class CViewSink : public IAdviseSink
{
	LONG m_refs = 1;
	HWND m_hwnd;

public:
	CViewSink(HWND hwnd) : m_hwnd(hwnd) {}
	void Detach() { m_hwnd = nullptr; }

	STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override
	{
		if (riid == IID_IUnknown || riid == IID_IAdviseSink) {
			*ppv = this;
			AddRef();
			return S_OK;
		}
		*ppv = nullptr;
		return E_NOINTERFACE;
	}
	STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_refs); }
	STDMETHODIMP_(ULONG) Release() override
	{
		LONG r = InterlockedDecrement(&m_refs);
		if (r == 0)
			delete this;
		return r;
	}

	STDMETHODIMP_(void) OnDataChange(FORMATETC *, STGMEDIUM *) override {}
	STDMETHODIMP_(void) OnViewChange(DWORD, LONG) override
	{
		if (m_hwnd)
			InvalidateRect(m_hwnd, nullptr, FALSE);
	}
	STDMETHODIMP_(void) OnRename(IMoniker *) override {}
	STDMETHODIMP_(void) OnSave() override {}
	STDMETHODIMP_(void) OnClose() override {}
};

/////////////////////////////////////////////////////////////////////////////////////////
// One per avatar control

#define VIEW_PROP     L"FlashAvatars.View"
#define LOAD_TIMER    0x4641   // AVS uses timer 0 for animated GIFs
#define LOAD_TICK     100
#define LOAD_TIMEOUT  20000

struct FlashView
{
	HWND hwnd;
	MCONTACT hContact = 0;
	char szProto[64] = "";     // own avatar of this account when hContact == 0

	CMStringA szUrl;           // address of the movie shown (or waited for)
	IUnknown *pUnk = nullptr;
	IShockwaveFlash *pFlash = nullptr;
	IViewObject *pView = nullptr;
	CViewSink *pSink = nullptr;
	bool bReady = false;       // the movie draws in place of the picture
	bool bFailed = false;      // the movie at szUrl cannot be shown
	bool bDead = false;        // its contact was deleted: show nothing more
	HBITMAP hbmBack = nullptr; // what is behind the control, see PaintFlash()
	SIZE sizeBack = {};
	int iFace = FACE_STAM;     // the face it should show
	int iFaceSet = -1;         // the face it was told to show
	DWORD dwLoadStart = 0;

	FlashView(HWND h) : hwnd(h) {}
};

static WNDPROC g_origProc;
static std::vector<FlashView *> g_views; // main thread only

static void DestroyFlash(FlashView *v)
{
	KillTimer(v->hwnd, LOAD_TIMER);
	if (v->pView) {
		v->pView->SetAdvise(DVASPECT_CONTENT, 0, nullptr);
		v->pView->Release();
		v->pView = nullptr;
	}
	if (v->pFlash) {
		v->pFlash->Release();
		v->pFlash = nullptr;
	}
	if (v->pUnk) {
		IOleObject *pOle = nullptr;
		if (SUCCEEDED(v->pUnk->QueryInterface(IID_IOleObject, (void **)&pOle))) {
			pOle->Close(OLECLOSE_NOSAVE);
			pOle->Release();
		}
		v->pUnk->Release();
		v->pUnk = nullptr;
	}
	if (v->pSink) {
		v->pSink->Detach();
		v->pSink->Release();
		v->pSink = nullptr;
	}
	if (v->hbmBack) {
		DeleteObject(v->hbmBack);
		v->hbmBack = nullptr;
	}
	if (v->bReady) {
		v->bReady = false;
		if (!v->bDead)
			InvalidateRect(v->hwnd, nullptr, TRUE);
	}
	v->iFaceSet = -1;
}

// The account the control shows: the contact's, or the one it was given for
// an own avatar. An own avatar control with no account (the global avatar, as
// the owner's user info window shows it) goes by the first account that has
// an own Flash avatar.
static const char* ViewProto(FlashView *v)
{
	if (v->hContact)
		return Proto_GetBaseAccountName(v->hContact);
	if (v->szProto[0])
		return v->szProto;

	for (auto &pa : Accounts()) {
		if (!pa->IsEnabled())
			continue;
		ptrA szUrl(db_get_sa(0, pa->szModuleName, "FlashAvatarUrl"));
		if (szUrl != nullptr)
			return pa->szModuleName;
	}
	return nullptr;
}

static CMStringA ViewUrl(FlashView *v)
{
	const char *szProto = ViewProto(v);
	if (szProto == nullptr || *szProto == 0)
		return CMStringA();

	ptrA szUrl(db_get_sa(v->hContact, szProto, "FlashAvatarUrl"));
	if (szUrl == nullptr || (_strnicmp(szUrl, "http://", 7) && _strnicmp(szUrl, "https://", 8)))
		return CMStringA();
	return CMStringA(szUrl);
}

static int ViewStatus(FlashView *v)
{
	const char *szProto = ViewProto(v);
	if (szProto == nullptr || *szProto == 0)
		return ID_STATUS_OFFLINE;
	if (v->hContact)
		return db_get_w(v->hContact, szProto, "Status", ID_STATUS_OFFLINE);
	return Proto_GetStatus(szProto);
}

static void ApplyFace(FlashView *v)
{
	if (!v->bReady || v->pFlash == nullptr || v->iFaceSet == v->iFace)
		return;

	HRESULT hr = v->pFlash->SetVariable(BStr(L"face.emotion"), BStr(g_faces[v->iFace]));
	Log("%p: face %S -> %08X", v->hwnd, g_faces[v->iFace], hr);
	if (SUCCEEDED(hr))
		v->iFaceSet = v->iFace;
}

static void SetFace(FlashView *v, int face)
{
	v->iFace = face;
	v->iFaceSet = -1; // the same emotion again plays it again
	ApplyFace(v);
}

/////////////////////////////////////////////////////////////////////////////////////////
// Movies are downloaded once (through Netlib, so proxy settings apply) into
// <avatar cache>\Flash\<md5 of the address>.swf

#define MAX_MOVIE_SIZE (4 * 1024 * 1024)

static std::vector<CMStringA> g_downloads; // main thread only

CMStringW MovieFile(const CMStringA &url, const wchar_t *wszExt)
{
	uint8_t digest[16];
	mir_md5_hash((const uint8_t *)url.c_str(), url.GetLength(), digest);

	CMStringW ret(VARSW(L"%miranda_avatarcache%\\Flash\\"));
	for (auto b : digest)
		ret.AppendFormat(L"%02x", b);
	ret.Append(wszExt);
	return ret;
}

struct DownloadJob
{
	CMStringA url;
	CMStringW file;
	bool ok;
};

static void RefreshAll();

static void MIR_SYSCALL DownloadDone(void *param)
{
	DownloadJob *job = (DownloadJob *)param;
	for (size_t i = 0; i < g_downloads.size(); i++)
		if (g_downloads[i] == job->url) {
			g_downloads.erase(g_downloads.begin() + i);
			break;
		}

	if (!job->ok) { // do not try again on every repaint
		for (auto *v : g_views)
			if (v->szUrl == job->url)
				v->bFailed = true;
	}
	delete job;
	RefreshAll();
}

// Fetches url into file (on a worker thread): http(s) only, at most 4 MB, a Flash
// movie when bFlash (a signature FWS, CWS or ZWS), else a PNG, GIF or JPEG.
bool DownloadFile(const CMStringA &url, const CMStringW &file, bool bFlash)
{
	if (_strnicmp(url, "http://", 7) && _strnicmp(url, "https://", 8))
		return false;

	MHttpRequest req(REQUEST_GET);
	req.m_szUrl = url;
	req.flags = NLHRF_HTTP11 | NLHRF_REDIRECT | NLHRF_NODUMP;
	NLHR_PTR resp(Netlib_HttpTransaction(g_hNetlib, &req));
	if (resp == nullptr) {
		Log("download %s: no response", url.c_str());
		return false;
	}
	if (resp->resultCode != 200) {
		Log("download %s: HTTP %d", url.c_str(), resp->resultCode);
		return false;
	}
	int len = resp->body.GetLength();
	if (len < 8 || len > MAX_MOVIE_SIZE) {
		Log("download %s: %d bytes, refused", url.c_str(), len);
		return false;
	}

	const char *sig = resp->body.c_str();
	bool bValid = bFlash
		? (!memcmp(sig + 1, "WS", 2) && (sig[0] == 'F' || sig[0] == 'C' || sig[0] == 'Z'))
		: (!memcmp(sig, "\x89PNG", 4) || !memcmp(sig, "GIF8", 4) || !memcmp(sig, "\xFF\xD8", 2));
	if (!bValid) {
		Log("download %s: not a %s", url.c_str(), bFlash ? "Flash movie" : "picture");
		return false;
	}

	CreatePathToFileW(file);
	CMStringW tmp(file + L".part");
	bool ok = false;
	FILE *f = _wfopen(tmp, L"wb");
	if (f) {
		bool written = fwrite(sig, 1, len, f) == (size_t)len;
		fclose(f);
		ok = written && MoveFileExW(tmp, file, MOVEFILE_REPLACE_EXISTING);
		if (!ok)
			DeleteFileW(tmp);
	}
	Log("download %s: %d bytes -> %S (%s)", url.c_str(), len, file.c_str(), ok ? "ok" : "cannot write");
	return ok;
}

static void __cdecl DownloadThread(void *param)
{
	DownloadJob *job = (DownloadJob *)param;
	job->ok = DownloadFile(job->url, job->file, true);
	CallFunctionAsync(DownloadDone, job);
}

static void StartDownload(const CMStringA &url, const CMStringW &file)
{
	for (auto &it : g_downloads)
		if (it == url)
			return;

	g_downloads.push_back(url);
	DownloadJob *job = new DownloadJob();
	job->url = url;
	job->file = file;
	mir_forkthread(DownloadThread, job);
}

/////////////////////////////////////////////////////////////////////////////////////////

// The engine renders frames at the size it was last given (IOleObject::SetExtent,
// in HIMETRIC); without one it renders nothing. The control's client size.
static void SetFlashSize(FlashView *v)
{
	if (v->pUnk == nullptr)
		return;

	RECT rc;
	GetClientRect(v->hwnd, &rc);
	if (rc.right <= 0 || rc.bottom <= 0)
		return;

	HDC hdc = GetDC(nullptr);
	int dpiX = GetDeviceCaps(hdc, LOGPIXELSX), dpiY = GetDeviceCaps(hdc, LOGPIXELSY);
	ReleaseDC(nullptr, hdc);

	SIZEL size = { MulDiv(rc.right, 2540, dpiX), MulDiv(rc.bottom, 2540, dpiY) };
	IOleObject *pOle = nullptr;
	if (SUCCEEDED(v->pUnk->QueryInterface(IID_IOleObject, (void **)&pOle))) {
		pOle->SetExtent(DVASPECT_CONTENT, &size);
		pOle->Release();
	}
}

static void CreateFlash(FlashView *v, const CMStringW &file)
{
	v->pUnk = CreateFlashObject();
	if (v->pUnk == nullptr) {
		v->bFailed = true;
		return;
	}
	if (FAILED(v->pUnk->QueryInterface(IID_IShockwaveFlash, (void **)&v->pFlash)) ||
		FAILED(v->pUnk->QueryInterface(IID_IViewObject, (void **)&v->pView))) {
		Log("%p: the Flash control lacks IShockwaveFlash or IViewObject", v->hwnd);
		DestroyFlash(v);
		v->bFailed = true;
		return;
	}

	// as ICQ 6 shows them: transparent, filling the box
	v->pFlash->put_WMode(BStr(L"transparent"));
	v->pFlash->put_Scale(BStr(L"noborder"));

	v->pSink = new CViewSink(v->hwnd);
	v->pView->SetAdvise(DVASPECT_CONTENT, 0, v->pSink);
	SetFlashSize(v);

	HRESULT hr = v->pFlash->LoadMovie(0, BStr(file));
	v->pFlash->Play();
	Log("%p: contact %d (%s), movie %s -> %S: LoadMovie %08X", v->hwnd, v->hContact, ViewProto(v), v->szUrl.c_str(), file.c_str(), hr);

	v->iFace = FaceForStatus(ViewStatus(v));
	v->dwLoadStart = GetTickCount();
	SetTimer(v->hwnd, LOAD_TIMER, LOAD_TICK, nullptr);
}

// Shows what the control's contact or account has now: its movie, or the picture.
static void UpdateView(FlashView *v)
{
	if (v->bDead)
		return;

	CMStringA url = ViewUrl(v);
	if (url != v->szUrl) {
		DestroyFlash(v);
		v->szUrl = url;
		v->bFailed = false;
	}

	if (url.IsEmpty() || v->bFailed || v->pUnk)
		return;

	CMStringW file = MovieFile(url, L".swf");
	if (_waccess(file, 0))
		StartDownload(url, file);
	else
		CreateFlash(v, file);
}

static void RefreshAll()
{
	for (auto *v : g_views)
		UpdateView(v);
}

static void OnLoadTimer(FlashView *v)
{
	if (v->pFlash == nullptr) {
		KillTimer(v->hwnd, LOAD_TIMER);
		return;
	}

	if (!v->bReady) {
		long state = 0;
		v->pFlash->get_ReadyState(&state);
		if (state != 4) {
			if (GetTickCount() - v->dwLoadStart > LOAD_TIMEOUT) {
				Log("%p: movie %s did not load, showing the picture", v->hwnd, v->szUrl.c_str());
				DestroyFlash(v);
				v->bFailed = true;
			}
			return;
		}
		v->bReady = true;
		Log("%p: movie ready after %d ms", v->hwnd, GetTickCount() - v->dwLoadStart);
		InvalidateRect(v->hwnd, nullptr, TRUE);
	}

	// the face clip may appear a frame or two after the movie has loaded
	ApplyFace(v);
	if (v->iFaceSet == v->iFace || GetTickCount() - v->dwLoadStart > LOAD_TIMEOUT)
		KillTimer(v->hwnd, LOAD_TIMER);
}

// The background is what the parent shows behind the control. It is asked for
// (DrawThemeParentBackground, which makes the parent paint into our DC) once
// per size, not on every frame: a message window's parent controls end up in
// its own erase handler, and TabSRMM's does not survive being run for a
// window whose contact was just deleted.
static HBITMAP CaptureBackground(FlashView *v, HDC hdc, const RECT &rc)
{
	HDC hdcMem = CreateCompatibleDC(hdc);
	HBITMAP hbm = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
	HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbm);
	FillRect(hdcMem, &rc, GetSysColorBrush(COLOR_3DFACE));
	DrawThemeParentBackground(v->hwnd, hdcMem, &rc);
	SelectObject(hdcMem, hbmOld);
	DeleteDC(hdcMem);
	return hbm;
}

static void PaintFlash(FlashView *v)
{
	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(v->hwnd, &ps);
	if (hdc == nullptr)
		return;

	RECT rc;
	GetClientRect(v->hwnd, &rc);
	if (rc.right > 0 && rc.bottom > 0) {
		if (v->hbmBack == nullptr || v->sizeBack.cx != rc.right || v->sizeBack.cy != rc.bottom) {
			if (v->hbmBack)
				DeleteObject(v->hbmBack);
			v->hbmBack = CaptureBackground(v, hdc, rc);
			v->sizeBack = { rc.right, rc.bottom };
		}

		HDC hdcBack = CreateCompatibleDC(hdc);
		HBITMAP hbmBackOld = (HBITMAP)SelectObject(hdcBack, v->hbmBack);
		HDC hdcMem = CreateCompatibleDC(hdc);
		HBITMAP hbm = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
		HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbm);

		BitBlt(hdcMem, 0, 0, rc.right, rc.bottom, hdcBack, 0, 0, SRCCOPY);
		RECTL bounds = { 0, 0, rc.right, rc.bottom };
		v->pView->Draw(DVASPECT_CONTENT, -1, nullptr, nullptr, nullptr, hdcMem, &bounds, nullptr, nullptr, 0);
		BitBlt(hdc, 0, 0, rc.right, rc.bottom, hdcMem, 0, 0, SRCCOPY);

		SelectObject(hdcMem, hbmOld);
		DeleteObject(hbm);
		DeleteDC(hdcMem);
		SelectObject(hdcBack, hbmBackOld);
		DeleteDC(hdcBack);
	}
	EndPaint(v->hwnd, &ps);
}

static void DetachView(FlashView *v)
{
	DestroyFlash(v);
	RemovePropW(v->hwnd, VIEW_PROP);
	for (size_t i = 0; i < g_views.size(); i++)
		if (g_views[i] == v) {
			g_views.erase(g_views.begin() + i);
			break;
		}
	delete v;
}

static LRESULT CALLBACK AvatarControlProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	FlashView *v = (FlashView *)GetPropW(hwnd, VIEW_PROP);

	switch (msg) {
	case WM_NCCREATE:
		{
			LRESULT res = CallWindowProc(g_origProc, hwnd, msg, wParam, lParam);
			if (res) {
				v = new FlashView(hwnd);
				SetPropW(hwnd, VIEW_PROP, v);
				g_views.push_back(v);
			}
			return res;
		}

	case WM_NCDESTROY:
		if (v)
			DetachView(v);
		break;

	case AVATAR_SETCONTACT:
	case AVATAR_SETPROTOCOL:
		{
			LRESULT res = CallWindowProc(g_origProc, hwnd, msg, wParam, lParam);
			if (v && (msg == AVATAR_SETPROTOCOL || lParam != 0)) {
				if (msg == AVATAR_SETCONTACT)
					v->hContact = (MCONTACT)lParam;
				else {
					v->hContact = 0;
					strncpy_s(v->szProto, lParam ? (const char *)lParam : "", _TRUNCATE);
				}
				UpdateView(v);
			}
			return res;
		}

	case WM_TIMER:
		if (wParam == LOAD_TIMER) {
			if (v)
				OnLoadTimer(v);
			return 0;
		}
		break;

	case WM_SIZE:
		if (v)
			SetFlashSize(v);
		// fall through
	case WM_MOVE:
	case WM_SHOWWINDOW:
	case WM_THEMECHANGED:
	case WM_SYSCOLORCHANGE:
		if (v && v->hbmBack) {
			DeleteObject(v->hbmBack);
			v->hbmBack = nullptr;
		}
		break;

	case WM_ERASEBKGND:
		if (v && v->bReady)
			return TRUE; // painted with the movie
		break;

	case WM_PAINT:
		if (v && v->bReady && v->pView && !v->bDead) {
			PaintFlash(v);
			return 0;
		}
		break;
	}
	return CallWindowProc(g_origProc, hwnd, msg, wParam, lParam);
}

/////////////////////////////////////////////////////////////////////////////////////////
// Events arrive on any thread; the controls live on the main one.

struct FaceJob
{
	MCONTACT hContact;
	char szProto[64];
	int face;
};

static void MIR_SYSCALL ApplyFaceJob(void *param)
{
	FaceJob *job = (FaceJob *)param;
	for (auto *v : g_views) {
		if (!v->pFlash)
			continue;
		if (job->hContact ? v->hContact == job->hContact : (v->hContact == 0 && !mir_strcmp(ViewProto(v), job->szProto)))
			SetFace(v, job->face);
	}
	delete job;
}

static void PostFace(MCONTACT hContact, const char *szProto, int face)
{
	FaceJob *job = new FaceJob();
	job->hContact = hContact;
	strncpy_s(job->szProto, szProto ? szProto : "", _TRUNCATE);
	job->face = face;
	CallFunctionAsync(ApplyFaceJob, job);
}

static void MIR_SYSCALL RefreshJob(void *)
{
	RefreshAll();
}

// A message with a smiley: the sender's avatar shows the emotion.
static int OnEventAdded(WPARAM hContact, LPARAM hDbEvent)
{
	DB::EventInfo dbei(hDbEvent);
	if (!dbei || dbei.eventType != EVENTTYPE_MESSAGE)
		return 0;

	// history being fetched or imported is not news
	if (dbei.getUnixtime() + 300 < (uint32_t)time(0))
		return 0;

	ptrW text(dbei.getText());
	if (text == nullptr)
		return 0;

	int face = FaceForText(text);
	if (face < 0)
		return 0;

	if (dbei.bSent)
		PostFace(0, Proto_GetBaseAccountName(hContact), face);
	else
		PostFace(hContact, nullptr, face);
	return 0;
}

// A contact is being deleted. Its avatar controls stop at once; and its
// message window is hidden right away. TabSRMM clears the window's contact
// data here and closes the window only later (a posted WM_CLOSE): any repaint
// of it in between, even one it starts itself while closing the tab, reads
// that data and crashes. A hidden window is not painted.
static DWORD g_dwMainThread;

static void MIR_SYSCALL StopDeletedContact(void *param)
{
	MCONTACT hContact = (MCONTACT)(INT_PTR)param;
	for (auto *v : g_views) {
		if (v->hContact != hContact)
			continue;
		v->bDead = true;
		DestroyFlash(v);
	}
}

static int OnContactDeleted(WPARAM hContact, LPARAM)
{
	if (hContact == 0)
		return 0;

	HWND hwnd = Srmm_FindWindow(hContact);
	if (GetCurrentThreadId() == g_dwMainThread) {
		if (hwnd)
			ShowWindow(hwnd, SW_HIDE);
		StopDeletedContact((void *)(INT_PTR)hContact);
	}
	else {
		if (hwnd)
			ShowWindowAsync(hwnd, SW_HIDE);
		CallFunctionAsync(StopDeletedContact, (void *)(INT_PTR)hContact);
	}
	return 0;
}

// A contact's status (its face) or Flash avatar changed.
static int OnSettingChanged(WPARAM hContact, LPARAM lParam)
{
	auto *cws = (DBCONTACTWRITESETTING *)lParam;
	if (!strcmp(cws->szSetting, "FlashAvatarUrl"))
		CallFunctionAsync(RefreshJob, nullptr);
	else if (hContact && !strcmp(cws->szSetting, "Status")) {
		const char *szProto = Proto_GetBaseAccountName(hContact);
		if (szProto && !strcmp(cws->szModule, szProto))
			PostFace(hContact, nullptr, FaceForStatus(cws->value.type == DBVT_WORD ? cws->value.wVal : ID_STATUS_OFFLINE));
	}
	return 0;
}

// Own status: the own avatar's face.
static int OnStatusModeChange(WPARAM wParam, LPARAM lParam)
{
	const char *szProto = (const char *)lParam;
	if (szProto)
		PostFace(0, szProto, FaceForStatus((int)wParam));
	else
		for (auto &pa : Accounts())
			PostFace(0, pa->szModuleName, FaceForStatus((int)wParam));
	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////

static bool HookAvatarControlClass()
{
	HWND hwnd = CreateWindowExW(0, AVATAR_CONTROL_CLASS, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, nullptr, nullptr);
	if (hwnd == nullptr) {
		Log("no avatar control class (is AVS loaded?)");
		return false;
	}
	g_origProc = (WNDPROC)SetClassLongPtrW(hwnd, GCLP_WNDPROC, (LONG_PTR)AvatarControlProc);
	DestroyWindow(hwnd);
	return g_origProc != nullptr;
}

static void UnhookAvatarControlClass()
{
	if (g_origProc == nullptr)
		return;

	HWND hwnd = CreateWindowExW(0, AVATAR_CONTROL_CLASS, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, nullptr, nullptr);
	if (hwnd) {
		SetClassLongPtrW(hwnd, GCLP_WNDPROC, (LONG_PTR)g_origProc);
		DestroyWindow(hwnd);
	}

	// controls created meanwhile keep our procedure as their own
	while (!g_views.empty()) {
		FlashView *v = g_views.back();
		HWND h = v->hwnd;
		DetachView(v);
		SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)g_origProc);
		InvalidateRect(h, nullptr, TRUE);
	}
}

void AddIcqCapability(const char *szModule, const BYTE caps[0x10], const char *szName)
{
	if (!ProtoServiceExists(szModule, PS_ICQ_ADDCAPABILITY))
		return;

	ICQ_CUSTOMCAP cap = {};
	cap.cbSize = sizeof(cap);
	memcpy(cap.caps, caps, sizeof(cap.caps));
	strncpy_s(cap.name, szName, _TRUNCATE);
	CallProtoService(szModule, PS_ICQ_ADDCAPABILITY, 0, (LPARAM)&cap);
	Log("capability \"%s\" announced for account %s", szName, szModule);
}

static int OnModulesLoaded(WPARAM, LPARAM)
{
	NETLIBUSER nlu = {};
	nlu.flags = NUF_OUTGOING | NUF_HTTPCONNS | NUF_UNICODE;
	nlu.szSettingsModule = MODULENAME;
	nlu.szDescriptiveName.w = TranslateT("Flash avatars");
	g_hNetlib = Netlib_RegisterUser(&nlu);

	Tzers_ModulesLoaded();

	if (!HookAvatarControlClass())
		return 0;

	// tell ICQ servers that this client plays Flash avatars
	for (auto &pa : Accounts())
		AddIcqCapability(pa->szModuleName, capFlashAvatars, "Flash avatars");

	HookEvent(ME_DB_EVENT_ADDED, OnEventAdded);
	HookEvent(ME_DB_CONTACT_SETTINGCHANGED, OnSettingChanged);
	HookEvent(ME_DB_CONTACT_DELETED, OnContactDeleted);
	HookEvent(ME_CLIST_STATUSMODECHANGE, OnStatusModeChange);
	return 0;
}

int CMPlugin::Load()
{
	g_dwMainThread = GetCurrentThreadId();
	HookEvent(ME_SYSTEM_MODULESLOADED, OnModulesLoaded);
	return 0;
}

int CMPlugin::Unload()
{
	Tzers_Unload();
	UnhookAvatarControlClass();
	if (g_hNetlib)
		Netlib_CloseHandle(g_hNetlib);
	// the engine stays loaded: its threads never exit (see its README)
	return 0;
}
