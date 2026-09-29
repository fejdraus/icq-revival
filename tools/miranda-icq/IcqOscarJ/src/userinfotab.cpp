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
//  DESCRIPTION:
//
//  Code for User details ICQ specific pages
// -----------------------------------------------------------------------------

#include "stdafx.h"

#define SVS_NORMAL        0
#define SVS_ZEROISUNSPEC  2
#define SVS_IP            3
#define SVS_SIGNED        6
#define SVS_ICQVERSION    8
#define SVS_TIMESTAMP     9
#define SVS_STATUSID      10

extern const char *nameXStatus[];

/////////////////////////////////////////////////////////////////////////////////////////

static void SetValue(CIcqProto* ppro, HWND hwndDlg, int idCtrl, MCONTACT hContact, char* szModule, char* szSetting, int special)
{
	DBVARIANT dbv = { 0 };
	char str[MAX_PATH];
	char* pstr = nullptr;
	int unspecified = 0;
	int bUtf = 0, bDbv = 0, bAlloc = 0;

	dbv.type = DBVT_DELETED;

	if ((hContact == NULL) && ((INT_PTR)szModule < 0x100)) {
		dbv.type = (INT_PTR)szModule;

		switch ((INT_PTR)szModule) {
		case DBVT_BYTE:
			dbv.cVal = (INT_PTR)szSetting;
			break;
		case DBVT_WORD:
			dbv.wVal = (INT_PTR)szSetting;
			break;
		case DBVT_DWORD:
			dbv.dVal = (UINT_PTR)szSetting;
			break;
		case DBVT_ASCIIZ:
			dbv.pszVal = pstr = szSetting;
			break;
		default:
			unspecified = 1;
			dbv.type = DBVT_DELETED;
		}
	}
	else {
		if (szModule == nullptr)
			unspecified = 1;
		else {
			unspecified = db_get(hContact, szModule, szSetting, &dbv);
			bDbv = 1;
		}
	}

	if (!unspecified) {
		switch (dbv.type) {
		case DBVT_BYTE:
			unspecified = (special == SVS_ZEROISUNSPEC && dbv.bVal == 0);
			pstr = _itoa(special == SVS_SIGNED ? dbv.cVal : dbv.bVal, str, 10);
			break;

		case DBVT_WORD:
			if (special == SVS_ICQVERSION) {
				if (dbv.wVal != 0) {
					char szExtra[80];

					mir_snprintf(str, "%d", dbv.wVal);
					pstr = str;

					if (hContact && ppro->IsDirectConnectionOpen(hContact, DIRECTCONN_STANDARD, 1)) {
						ICQTranslateUtfStatic(LPGEN(" (DC Established)"), szExtra, _countof(szExtra));
						mir_strcat(str, (char*)szExtra);
						bUtf = 1;
					}
				}
				else
					unspecified = 1;
			}
			else if (special == SVS_STATUSID) {
				char *pszStatus = MirandaStatusToStringUtf(dbv.wVal);
				BYTE bXStatus = ppro->getContactXStatus(hContact);

				if (bXStatus) {
					char *pXName = ppro->getSettingStringUtf(hContact, DBSETTING_XSTATUS_NAME, nullptr);
					if (pXName == nullptr) // give default name
						pXName = ICQTranslateUtf(nameXStatus[bXStatus - 1]);

					mir_snprintf(str, "%s (%s)", pszStatus, pXName);
					SAFE_FREE((void**)&pXName);
				}
				else strncpy_s(str, pszStatus, _TRUNCATE);

				bUtf = 1;
				SAFE_FREE(&pszStatus);
				pstr = str;
				unspecified = 0;
			}
			else {
				unspecified = (special == SVS_ZEROISUNSPEC && dbv.wVal == 0);
				pstr = _itoa(special == SVS_SIGNED ? dbv.sVal : dbv.wVal, str, 10);
			}
			break;

		case DBVT_DWORD:
			unspecified = (special == SVS_ZEROISUNSPEC && dbv.dVal == 0);
			if (special == SVS_IP) {
				struct in_addr ia;
				ia.S_un.S_addr = htonl(dbv.dVal);
				pstr = inet_ntoa(ia);
				if (dbv.dVal == 0)
					unspecified = 1;
			}
			else if (special == SVS_TIMESTAMP) {
				if (dbv.dVal == 0)
					unspecified = 1;
				else
					pstr = time2text(dbv.dVal);
			}
			else
				pstr = _itoa(special == SVS_SIGNED ? dbv.lVal : dbv.dVal, str, 10);
			break;

		case DBVT_ASCIIZ:
		case DBVT_WCHAR:
			unspecified = (special == SVS_ZEROISUNSPEC && dbv.pszVal[0] == '\0');
			if (!unspecified && pstr != szSetting) {
				pstr = ppro->getSettingStringUtf(hContact, szModule, szSetting, nullptr);
				bUtf = 1;
				bAlloc = 1;
			}
			if (idCtrl == IDC_UIN)
				SetDlgItemText(hwndDlg, IDC_UINSTATIC, TranslateT("ScreenName:"));
			break;

		default:
			pstr = str;
			mir_strcpy(str, "???");
			break;
		}
	}

	EnableDlgItem(hwndDlg, idCtrl, !unspecified);
	if (unspecified)
		SetDlgItemText(hwndDlg, idCtrl, TranslateT("<not specified>"));
	else if (bUtf)
		SetDlgItemTextUtf(hwndDlg, idCtrl, pstr);
	else
		SetDlgItemTextA(hwndDlg, idCtrl, pstr);

	if (bDbv)
		db_free(&dbv);

	if (bAlloc)
		SAFE_FREE(&pstr);
}

/////////////////////////////////////////////////////////////////////////////////////////

static INT_PTR CALLBACK IcqDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_INITDIALOG:
		TranslateDialogDefault(hwndDlg);
		// The protocol pointer used to arrive with PSN_PARAMCHANGED, which the
		// current core no longer sends; the adapter page now passes it in lParam.
		SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
		break;

	case WM_NOTIFY:
		switch (((LPNMHDR)lParam)->idFrom) {
		case 0:
			switch (((LPNMHDR)lParam)->code) {
			case PSN_INFOCHANGED:
				CIcqProto * ppro = (CIcqProto*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
				if (!ppro)
					break;

				char* szProto;
				MCONTACT hContact = (MCONTACT)((LPPSHNOTIFY)lParam)->lParam;

				if (hContact == NULL)
					szProto = ppro->m_szModuleName;
				else
					szProto = Proto_GetBaseAccountName(hContact);

				if (!szProto)
					break;

				SetValue(ppro, hwndDlg, IDC_UIN, hContact, szProto, UNIQUEIDSETTING, SVS_NORMAL);
				SetValue(ppro, hwndDlg, IDC_ONLINESINCE, hContact, szProto, "LogonTS", SVS_TIMESTAMP);
				SetValue(ppro, hwndDlg, IDC_IDLETIME, hContact, szProto, "IdleTS", SVS_TIMESTAMP);
				SetValue(ppro, hwndDlg, IDC_IP, hContact, szProto, "IP", SVS_IP);
				SetValue(ppro, hwndDlg, IDC_REALIP, hContact, szProto, "RealIP", SVS_IP);

				if (hContact) {
					SetValue(ppro, hwndDlg, IDC_PORT, hContact, szProto, "UserPort", SVS_ZEROISUNSPEC);
					SetValue(ppro, hwndDlg, IDC_VERSION, hContact, szProto, "Version", SVS_ICQVERSION);
					SetValue(ppro, hwndDlg, IDC_MIRVER, hContact, szProto, "MirVer", SVS_ZEROISUNSPEC);
					if (ppro->getByte(hContact, "ClientID", 0))
						ppro->setDword(hContact, "TickTS", 0);
					SetValue(ppro, hwndDlg, IDC_SYSTEMUPTIME, hContact, szProto, "TickTS", SVS_TIMESTAMP);
					SetValue(ppro, hwndDlg, IDC_STATUS, hContact, szProto, "Status", SVS_STATUSID);
				}
				else {
					MFileVersion v;
					Miranda_GetFileVersion(&v);

					char str[MAX_PATH];
					mir_snprintf(str, "Miranda NG %d.%d.%d.%d (ICQ %s)", v[0], v[1], v[2], v[3], __VERSION_STRING_DOTS);

					SetValue(ppro, hwndDlg, IDC_PORT, hContact, (char*)DBVT_WORD, (char*)ppro->wListenPort, SVS_ZEROISUNSPEC);
					SetValue(ppro, hwndDlg, IDC_VERSION, hContact, (char*)DBVT_WORD, (char*)ICQ_VERSION, SVS_ICQVERSION);
					SetValue(ppro, hwndDlg, IDC_MIRVER, hContact, (char*)DBVT_ASCIIZ, str, SVS_ZEROISUNSPEC);
					SetDlgItemText(hwndDlg, IDC_SUPTIME, TranslateT("Member since:"));
					SetValue(ppro, hwndDlg, IDC_SYSTEMUPTIME, hContact, szProto, "MemberTS", SVS_TIMESTAMP);
					SetValue(ppro, hwndDlg, IDC_STATUS, hContact, (char*)DBVT_WORD, (char*)ppro->m_iStatus, SVS_STATUSID);
				}
			}
		}
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDCANCEL:
			SendMessage(GetParent(hwndDlg), msg, wParam, lParam);
			break;
		}
		break;
	}

	return FALSE;
}

/////////////////////////////////////////////////////////////////////////////////////////

// In the current core the details pages are CUserInfoPageDlg objects, while
// both of our procedures are left over from the old API. The adapter passes
// messages through unchanged and adds what the core no longer sends: the
// protocol pointer in lParam of WM_INITDIALOG (it used to come with
// PSN_PARAMCHANGED) and PSN_INFOCHANGED whenever the details window asks for a
// refresh (the window used to send it itself).
class CIcqUserInfoPage : public CUserInfoPageDlg
{
	CIcqProto *m_ppro;
	DLGPROC m_pfnProc;
	int m_idPage;

public:
	CIcqUserInfoPage(CIcqProto *ppro, int idDialog, DLGPROC pfnProc) :
		CUserInfoPageDlg(g_plugin, idDialog),
		m_ppro(ppro),
		m_pfnProc(pfnProc),
		m_idPage(idDialog)
	{
		m_autoClose = 0; // the details window closes itself; a page must not
	}

	// The details window stretches a page to its own size, but only this handler
	// recomputes the layout from the template: without it the contents stay in
	// the top left corner as a frame that never moves.
	int Resizer(UTILRESIZECONTROL *urc) override
	{
		if (m_idPage == IDD_INFO_CHANGEINFO) {
			switch (urc->wId) {
			case IDC_SAVE:
				return RD_ANCHORX_RIGHT | RD_ANCHORY_BOTTOM;
			case IDC_UPLOADING:
				return RD_ANCHORX_WIDTH | RD_ANCHORY_BOTTOM;
			default: // the settings list
				return RD_ANCHORX_WIDTH | RD_ANCHORY_HEIGHT;
			}
		}

		// The details page is a set of label-and-value pairs: labels stay put,
		// values stretch with the width.
		switch (urc->wId) {
		case -1: // labels the template leaves without an id
		case IDC_UINSTATIC:
		case IDC_SUPTIME:
			return RD_ANCHORX_LEFT | RD_ANCHORY_TOP;
		default:
			return RD_ANCHORX_WIDTH | RD_ANCHORY_TOP;
		}
	}

	bool OnInitDialog() override
	{
		m_pfnProc(m_hwnd, WM_INITDIALOG, 0, (LPARAM)m_ppro);
		return true;
	}

	bool OnRefresh() override
	{
		PSHNOTIFY pshn = {};
		pshn.hdr.code = PSN_INFOCHANGED;
		pshn.hdr.hwndFrom = m_hwnd;
		pshn.hdr.idFrom = 0;
		pshn.lParam = (LPARAM)m_hContact;
		m_pfnProc(m_hwnd, WM_NOTIFY, 0, (LPARAM)&pshn);
		return false;
	}

	INT_PTR DlgProc(UINT msg, WPARAM wParam, LPARAM lParam) override
	{
		switch (msg) {
		case WM_INITDIALOG:
			break; // sent from OnInitDialog instead, once the window exists

		case WM_NOTIFY:
			// PSN_INFOCHANGED arrives through OnRefresh; forwarding it here as
			// well would fill the page twice.
			if (((LPNMHDR)lParam)->idFrom == 0 && ((LPNMHDR)lParam)->code == PSN_INFOCHANGED)
				break;
			[[fallthrough]];

		default:
			if (INT_PTR res = m_pfnProc(m_hwnd, msg, wParam, lParam))
				return res;
		}

		return CUserInfoPageDlg::DlgProc(msg, wParam, lParam);
	}
};

/////////////////////////////////////////////////////////////////////////////////////////

int CIcqProto::OnUserInfoInit(WPARAM wParam, LPARAM lParam)
{
	if ((!IsICQContact(lParam)) && lParam)
		return 0;

	USERINFOPAGE uip = {};
	uip.flags = ODPF_UNICODE | ODPF_USERINFOTAB | ODPF_DONTTRANSLATE;
	uip.szGroup.w = m_tszUserName;
	uip.szProto = m_szModuleName;

	uip.position = -1900000000;
	uip.szTitle.w = LPGENW("Details");
	uip.pDialog = new CIcqUserInfoPage(this, IDD_INFO_ICQ, IcqDlgProc);
	g_plugin.addUserInfo(wParam, &uip);

	// Only the user's own profile is editable; there is nothing to change on
	// somebody else's contact.
	if (!lParam) {
		uip.position = -1899999999;
		uip.szTitle.w = LPGENW("Account");
		uip.pDialog = new CIcqUserInfoPage(this, IDD_INFO_CHANGEINFO, ChangeInfoDlgProc);
		g_plugin.addUserInfo(wParam, &uip);

		// For the user's own profile the details window asks nobody: it calls
		// PS_GETINFO through CallContactService, which finds no account for
		// hContact == 0 and silently reports success. The window then waits for an
		// acknowledgement that never comes - hence the endless "Updating" caption
		// and the greyed-out button. Ask for our own profile ourselves, and when
		// there is nobody to ask, end the wait with a deferred failure (it cannot
		// be immediate: the window has not started waiting yet).
		if (GetInfo(0, SGIF_ONOPEN))
			ProtoBroadcastAsync(0, ACKTYPE_GETINFO, ACKRESULT_FAILED, nullptr, 0);
	}

	return 0;
}
