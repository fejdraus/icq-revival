/*
IcqRevivalFlash: the animated avatar picker. What ICQ 6.5's avatar gallery
does, in a small window of Miranda: the gallery of our server, in its two
groups, a preview played by the engine, and buttons that set the chosen movie
as the account's own animated avatar (BART type 8) or remove it.

Opened from the menu of an ICQ account (IcqOscarJ adds the item while this
plugin offers MS_ICQREVIVAL_AVATARPICKER). It touches nothing but type 8 of
that account, through PS_ICQ_SETFLASHAVATAR: the picture (type 1), AVS and the
other protocols are left alone.

The gallery: <server web pages>/icq/avatars/list.json, the avatars.json of the
server's gallery reduced to what a client needs:
  {"avatars": [{"file": "pirate.swf", "thumb": "pirate.gif", "author": "icq",
                "title": {"en": "Pirate", "uk": "..."}}, ...]}
"author" is "icq" for ICQ's own and "user" for the ones users made. The
titles are the gallery's own: Ukrainian with a Ukrainian language pack,
English otherwise. The hidden account setting AvatarBase (a full base URL of
the folder) replaces the address for a test setup, as TzerBase does for tZers.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation version 2
of the License.
*/

#include "stdafx.h"

#define AVATAR_PATH   "/icq/avatars/"
#define LIST_FILE     "list.json"
#define MAX_LIST_SIZE (512 * 1024)

#define THUMB_CX 52
#define THUMB_CY 64

#define FACE_TIMER    1
#define FACE_TICK     4000

enum { GROUP_ICQ, GROUP_USER, GROUP_COUNT };

struct GalleryItem
{
	CMStringA file, thumb;
	CMStringW title;
	int group;
	CMStringW thumbFile; // in the cache, once downloaded
};

struct Gallery
{
	CMStringA szBase;
	std::vector<GalleryItem> items;
	bool ok = false;
};

struct Picker
{
	CMStringA szProto;
	CMStringA szBase;
	HWND hwnd = nullptr;
	Gallery *gallery = nullptr;
	HIMAGELIST himl = nullptr;
	int group = GROUP_ICQ;
	int selected = -1;    // in gallery->items
	int face = 0;
	bool bWaiting = true;  // for its gallery
	std::vector<int> shown; // list view row -> gallery item
};

static std::vector<Picker *> g_pickers; // main thread only

/////////////////////////////////////////////////////////////////////////////////////////
// Loading the gallery, on a worker thread

static bool FetchText(const CMStringA &url, CMStringA &body)
{
	MHttpRequest req(REQUEST_GET);
	req.m_szUrl = url;
	req.flags = NLHRF_HTTP11 | NLHRF_REDIRECT | NLHRF_NODUMP;
	NLHR_PTR resp(Netlib_HttpTransaction(g_hNetlib, &req));
	if (resp == nullptr || resp->resultCode != 200) {
		Log("avatars: %s: %s %d", url.c_str(), resp ? "HTTP" : "no response", resp ? resp->resultCode : 0);
		return false;
	}
	if (resp->body.GetLength() > MAX_LIST_SIZE) {
		Log("avatars: %s: %d bytes, refused", url.c_str(), resp->body.GetLength());
		return false;
	}
	body = resp->body;
	return true;
}

// A plain file name of the gallery: letters, digits, '-', '_' and one dot.
static bool IsPlainName(const CMStringA &s, const char *ext1, const char *ext2 = nullptr, const char *ext3 = nullptr)
{
	int dot = s.Find('.');
	if (dot <= 0 || s.Find('.', dot + 1) != -1 || s.GetLength() > 100)
		return false;
	for (int i = 0; i < dot; i++) {
		char c = s[i];
		if (!isalnum((BYTE)c) && c != '-' && c != '_')
			return false;
	}
	const char *ext = s.c_str() + dot;
	return !_stricmp(ext, ext1) || (ext2 && !_stricmp(ext, ext2)) || (ext3 && !_stricmp(ext, ext3));
}

static bool UkrainianTitles()
{
	return PRIMARYLANGID(LANGIDFROMLCID(Langpack_GetDefaultLocale())) == LANG_UKRAINIAN;
}

static void OnGallery(Picker *pk, Gallery *g);

// Back on the main thread: to the window that waits for it, if it is still there.
static void MIR_SYSCALL GalleryDone(void *param)
{
	Gallery *g = (Gallery *)param;
	for (auto *pk : g_pickers)
		if (pk->bWaiting && pk->szBase == g->szBase) {
			pk->bWaiting = false;
			OnGallery(pk, g);
			return;
		}
	delete g;
}

static void __cdecl GalleryThread(void *param)
{
	Gallery *g = (Gallery *)param;
	CMStringA body;
	if (FetchText(g->szBase + LIST_FILE, body)) {
		JSONNode root = JSONNode::parse(body);
		const char *lang = UkrainianTitles() ? "uk" : "en";
		for (auto &it : root["avatars"]) {
			GalleryItem item;
			item.file = it["file"].as_string().c_str();
			item.thumb = it["thumb"].as_string().c_str();
			if (!IsPlainName(item.file, ".swf") || !IsPlainName(item.thumb, ".gif", ".png", ".jpg"))
				continue;
			CMStringA author(it["author"].as_string().c_str());
			item.group = (author == "icq") ? GROUP_ICQ : GROUP_USER;
			item.title = it["title"][lang].as_mstring();
			if (item.title.IsEmpty())
				item.title = it["title"]["en"].as_mstring();
			if (item.title.IsEmpty())
				item.title = _A2T(item.file.Left(item.file.Find('.')));
			g->items.push_back(item);
		}
		g->ok = !g->items.empty();
		Log("avatars: %s: %d avatars", (g->szBase + LIST_FILE).c_str(), (int)g->items.size());

		// the thumbnails, into the cache
		for (auto &it : g->items) {
			CMStringA url(g->szBase + it.thumb);
			CMStringW file = MovieFile(url, CMStringW(_A2T(it.thumb.Mid(it.thumb.Find('.')))));
			if (!_waccess(file, 0) || DownloadFile(url, file, false))
				it.thumbFile = file;
		}
	}

	// the window may be gone meanwhile
	CallFunctionAsync(GalleryDone, g);
}

/////////////////////////////////////////////////////////////////////////////////////////
// The window

static CMStringA CurrentUrl(Picker *pk)
{
	return CMStringA(ptrA(db_get_sa(0, pk->szProto, "FlashAvatarUrl")));
}

// The gallery item an address is: <base>...<file>, by its file name.
static int ItemOfUrl(Picker *pk, const CMStringA &url)
{
	if (pk->gallery == nullptr || url.IsEmpty())
		return -1;
	int slash = url.ReverseFind('/');
	CMStringA name(url.Mid(slash + 1));
	int q = name.Find('?');
	if (q != -1)
		name.Truncate(q);
	for (size_t i = 0; i < pk->gallery->items.size(); i++)
		if (!pk->gallery->items[i].file.CompareNoCase(name) && url.Find(AVATAR_PATH) != -1)
			return (int)i;
	return -1;
}

static void ShowCurrent(Picker *pk)
{
	CMStringA url(CurrentUrl(pk));
	int i = ItemOfUrl(pk, url);
	CMStringW text;
	if (url.IsEmpty())
		text = TranslateT("No animated avatar is set.");
	else if (i >= 0)
		text.Format(TranslateT("Now set: %s"), pk->gallery->items[i].title.c_str());
	else
		text = TranslateT("Now set: an animated avatar from elsewhere.");
	SetDlgItemTextW(pk->hwnd, IDC_CURRENT, text);

	int online = Proto_GetStatus(pk->szProto) != ID_STATUS_OFFLINE;
	EnableWindow(GetDlgItem(pk->hwnd, IDC_SET), online && pk->selected >= 0 && pk->selected != i);
	EnableWindow(GetDlgItem(pk->hwnd, IDC_REMOVE), online && !url.IsEmpty());
}

static void Preview(Picker *pk)
{
	HWND hwndPreview = GetDlgItem(pk->hwnd, IDC_PREVIEW);
	if (pk->selected < 0) {
		SetDlgItemTextW(pk->hwnd, IDC_TITLE, L"");
		SendMessage(hwndPreview, FLASHVIEW_SETMOVIE, 0, 0);
		return;
	}
	auto &it = pk->gallery->items[pk->selected];
	SetDlgItemTextW(pk->hwnd, IDC_TITLE, it.title);
	CMStringA url(pk->szBase + it.file);
	SendMessage(hwndPreview, FLASHVIEW_SETMOVIE, 0, (LPARAM)url.c_str());
	pk->face = 0;
}

// The list view shows one group, like the gallery's two tabs.
static void FillList(Picker *pk)
{
	HWND hwndList = GetDlgItem(pk->hwnd, IDC_LIST);
	SendMessage(hwndList, WM_SETREDRAW, FALSE, 0);
	ListView_DeleteAllItems(hwndList);
	pk->shown.clear();
	if (pk->gallery) {
		for (size_t i = 0; i < pk->gallery->items.size(); i++) {
			auto &it = pk->gallery->items[i];
			if (it.group != pk->group)
				continue;
			LVITEMW lvi = {};
			lvi.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
			lvi.iItem = (int)pk->shown.size();
			lvi.pszText = (wchar_t *)it.title.c_str();
			lvi.iImage = (int)i;
			lvi.lParam = (LPARAM)i;
			int row = ListView_InsertItem(hwndList, &lvi);
			pk->shown.push_back((int)i);
			if ((int)i == pk->selected)
				ListView_SetItemState(hwndList, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
		}
	}
	SendMessage(hwndList, WM_SETREDRAW, TRUE, 0);
	InvalidateRect(hwndList, nullptr, TRUE);
}

// A thumbnail at the image list's size: a picture of another size is stretched.
static HBITMAP LoadThumb(const CMStringW &file)
{
	if (file.IsEmpty())
		return nullptr;
	HBITMAP hbm = Image_Load(file);
	if (hbm == nullptr)
		return nullptr;
	BITMAP bm;
	GetObject(hbm, sizeof(bm), &bm);
	if (bm.bmWidth != THUMB_CX || bm.bmHeight != THUMB_CY) {
		HBITMAP hbmNew = Image_Resize(hbm, RESIZEBITMAP_STRETCH, THUMB_CX, THUMB_CY);
		if (hbmNew != hbm) {
			DeleteObject(hbm);
			hbm = hbmNew;
		}
	}
	return hbm;
}

static void OnGallery(Picker *pk, Gallery *g)
{
	pk->gallery = g;
	if (!g->ok) {
		SetDlgItemTextW(pk->hwnd, IDC_STATUS, TranslateT("The server's gallery could not be loaded."));
		return;
	}

	// one image per gallery item; a missing thumbnail is a blank one
	pk->himl = ImageList_Create(THUMB_CX, THUMB_CY, ILC_COLOR32, (int)g->items.size(), 0);
	HBITMAP hbmBlank = nullptr;
	for (auto &it : g->items) {
		HBITMAP hbm = LoadThumb(it.thumbFile);
		if (hbm == nullptr) {
			if (hbmBlank == nullptr) {
				BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER), THUMB_CX, -THUMB_CY, 1, 32, BI_RGB } };
				void *bits;
				hbmBlank = CreateDIBSection(nullptr, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
			}
			ImageList_Add(pk->himl, hbmBlank, nullptr);
		}
		else {
			ImageList_Add(pk->himl, hbm, nullptr);
			DeleteObject(hbm);
		}
	}
	if (hbmBlank)
		DeleteObject(hbmBlank);
	ListView_SetImageList(GetDlgItem(pk->hwnd, IDC_LIST), pk->himl, LVSIL_NORMAL);

	// the tab of the one set now, which is also shown first
	pk->selected = ItemOfUrl(pk, CurrentUrl(pk));
	if (pk->selected >= 0)
		pk->group = g->items[pk->selected].group;
	TabCtrl_SetCurSel(GetDlgItem(pk->hwnd, IDC_GROUPS), pk->group);
	FillList(pk);
	Preview(pk);
	ShowCurrent(pk);
	SetDlgItemTextW(pk->hwnd, IDC_STATUS, L"");
}

static void SetAvatar(Picker *pk, bool bRemove)
{
	CMStringA url;
	if (!bRemove) {
		if (pk->selected < 0)
			return;
		url = pk->szBase + pk->gallery->items[pk->selected].file;
	}

	INT_PTR res = CallProtoService(pk->szProto, PS_ICQ_SETFLASHAVATAR, 0, bRemove ? 0 : (LPARAM)url.c_str());
	Log("avatars: %s %s: %d", pk->szProto.c_str(), bRemove ? "remove" : url.c_str(), (int)res);
	const wchar_t *msg;
	if (res == 0)
		msg = bRemove ? TranslateT("The animated avatar was removed.") : TranslateT("The animated avatar was set.");
	else if (res == 1)
		msg = TranslateT("The account is offline.");
	else
		msg = TranslateT("The account did not take this avatar.");
	SetDlgItemTextW(pk->hwnd, IDC_STATUS, msg);
	ShowCurrent(pk);
}

static INT_PTR CALLBACK PickerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	Picker *pk = (Picker *)GetWindowLongPtr(hwnd, GWLP_USERDATA);

	switch (msg) {
	case WM_INITDIALOG:
		pk = (Picker *)lParam;
		pk->hwnd = hwnd;
		SetWindowLongPtr(hwnd, GWLP_USERDATA, lParam);
		TranslateDialogDefault(hwnd);
		{
			CMStringW caption(TranslateT("Animated avatar"));
			if (PROTOACCOUNT *pa = Proto_GetAccount(pk->szProto))
				caption.AppendFormat(L": %s", pa->tszAccountName);
			SetWindowTextW(hwnd, caption);

			HWND hwndTabs = GetDlgItem(hwnd, IDC_GROUPS);
			TCITEMW tci = {};
			tci.mask = TCIF_TEXT;
			tci.pszText = TranslateT("Official");
			TabCtrl_InsertItem(hwndTabs, GROUP_ICQ, &tci);
			tci.pszText = TranslateT("User created");
			TabCtrl_InsertItem(hwndTabs, GROUP_USER, &tci);

			// the list view inside the tab control's page
			RECT rc;
			GetWindowRect(hwndTabs, &rc);
			MapWindowPoints(nullptr, hwnd, (POINT *)&rc, 2);
			TabCtrl_AdjustRect(hwndTabs, FALSE, &rc);
			HWND hwndList = GetDlgItem(hwnd, IDC_LIST);
			SetWindowPos(hwndList, HWND_TOP, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, 0);
			ListView_SetExtendedListViewStyle(hwndList, LVS_EX_DOUBLEBUFFER);
			ListView_SetIconSpacing(hwndList, THUMB_CX + 34, THUMB_CY + 34);
		}
		SetDlgItemTextW(hwnd, IDC_STATUS, TranslateT("Loading the server's gallery..."));
		ShowCurrent(pk);
		SetTimer(hwnd, FACE_TIMER, FACE_TICK, nullptr);
		{
			Gallery *g = new Gallery();
			g->szBase = pk->szBase;
			mir_forkthread(GalleryThread, g);
		}
		return TRUE;

	case WM_TIMER:
		if (wParam == FACE_TIMER && pk) {
			// the preview's face plays a gesture now and then, as on the web card
			static const int faces[] = { 0, 1, 0, 3, 0, 6 }; // stam, smile, laugh, love
			pk->face = (pk->face + 1) % _countof(faces);
			SendDlgItemMessage(hwnd, IDC_PREVIEW, FLASHVIEW_SETFACE, faces[pk->face], 0);
			ShowCurrent(pk); // the account may have gone on or off line
		}
		return TRUE;

	case WM_NOTIFY:
		{
			auto *hdr = (NMHDR *)lParam;
			if (hdr->idFrom == IDC_GROUPS && hdr->code == TCN_SELCHANGE) {
				pk->group = TabCtrl_GetCurSel(hdr->hwndFrom);
				FillList(pk);
			}
			else if (hdr->idFrom == IDC_LIST && hdr->code == LVN_ITEMCHANGED) {
				auto *nmlv = (NMLISTVIEW *)lParam;
				if ((nmlv->uNewState & LVIS_SELECTED) && !(nmlv->uOldState & LVIS_SELECTED) && nmlv->iItem >= 0 && nmlv->iItem < (int)pk->shown.size()) {
					pk->selected = pk->shown[nmlv->iItem];
					Preview(pk);
					ShowCurrent(pk);
					SetDlgItemTextW(hwnd, IDC_STATUS, L"");
				}
			}
			else if (hdr->idFrom == IDC_LIST && hdr->code == NM_DBLCLK) {
				if (IsWindowEnabled(GetDlgItem(hwnd, IDC_SET)))
					SetAvatar(pk, false);
			}
		}
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDC_SET:
			SetAvatar(pk, false);
			return TRUE;
		case IDC_REMOVE:
			SetAvatar(pk, true);
			return TRUE;
		case IDCANCEL:
			DestroyWindow(hwnd);
			return TRUE;
		}
		break;

	case WM_CLOSE:
		DestroyWindow(hwnd);
		return TRUE;

	case WM_DESTROY:
		KillTimer(hwnd, FACE_TIMER);
		if (pk) {
			for (size_t i = 0; i < g_pickers.size(); i++)
				if (g_pickers[i] == pk) {
					g_pickers.erase(g_pickers.begin() + i);
					break;
				}
			ListView_SetImageList(GetDlgItem(hwnd, IDC_LIST), nullptr, LVSIL_NORMAL);
			if (pk->himl)
				ImageList_Destroy(pk->himl);
			delete pk->gallery;
			delete pk;
			SetWindowLongPtr(hwnd, GWLP_USERDATA, 0);
		}
		break;
	}
	return FALSE;
}

/////////////////////////////////////////////////////////////////////////////////////////
// MS_ICQREVIVAL_AVATARPICKER: lParam = the account

static INT_PTR OpenPicker(WPARAM, LPARAM lParam)
{
	const char *szProto = (const char *)lParam;
	if (szProto == nullptr || !ProtoServiceExists(szProto, PS_ICQ_SETFLASHAVATAR))
		return 1;

	for (auto *pk : g_pickers)
		if (pk->szProto == szProto) {
			ShowWindow(pk->hwnd, SW_RESTORE);
			SetForegroundWindow(pk->hwnd);
			return 0;
		}

	CMStringA szBase(ServerWebBase(szProto, "AvatarBase", AVATAR_PATH));
	if (szBase.IsEmpty()) {
		MessageBoxW(nullptr, TranslateT("The account has no sign-in server set."), TranslateT("Animated avatar"), MB_OK | MB_ICONINFORMATION);
		return 1;
	}

	Picker *pk = new Picker();
	pk->szProto = szProto;
	pk->szBase = szBase;
	g_pickers.push_back(pk);
	if (CreateDialogParamW(g_plugin.getInst(), MAKEINTRESOURCEW(IDD_AVATARS), nullptr, PickerProc, (LPARAM)pk) == nullptr) {
		Log("avatars: cannot create the picker (%d)", GetLastError());
		g_pickers.pop_back();
		delete pk;
		return 1;
	}
	ShowWindow(pk->hwnd, SW_SHOW);
	return 0;
}

void Avatars_Load()
{
	CreateServiceFunction(MS_ICQREVIVAL_AVATARPICKER, OpenPicker);
}

void Avatars_ModulesLoaded()
{
	INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES };
	InitCommonControlsEx(&icc);
}

void Avatars_Unload()
{
	while (!g_pickers.empty())
		DestroyWindow(g_pickers.back()->hwnd);
}
