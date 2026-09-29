// ---------------------------------------------------------------------------80
//                ICQ plugin for Miranda Instant Messenger
//                ________________________________________
//
// Copyright © 2026 ICQ Revival
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// -----------------------------------------------------------------------------
//  DESCRIPTION:
//
//  tZers: the short animations with sound ICQ 6 sends. ICQ 6.5 sends one as
//  an advanced message through the server (channel 2, TLV 0x2711) of type
//  MTYPE_PLUGIN, plugin {4FA6F34C-09B7-FD48-9208-7E857AE07330}, function 0,
//  "Send Tzer"; its body is
//    <tzerRoot id="cantH" url="http://../canthearu.swf"
//              thumb="http://../canthearu.png" name="Can't Hear U" freeData=""/>
//  The name is UTF-8, in the sender's language. The receiving ICQ 6.5 plays
//  the movie at url.
//
//  Here a tZer becomes a message in the history, "tZer: <name>", readable
//  anywhere, and ME_ICQ_TZER hands the movie's address to a plugin that can
//  play it (IcqRevivalFlash).
// -----------------------------------------------------------------------------

#include "stdafx.h"

// The value of attribute name="..." in a tag, unescaped; empty when missing.
static CMStringA TzerAttr(const char *szXml, const char *szName)
{
	CMStringA key(FORMAT, " %s=\"", szName), ret;
	const char *p = strstr(szXml, key);
	if (p == nullptr)
		return ret;
	p += key.GetLength();
	const char *e = strchr(p, '"');
	if (e == nullptr)
		return ret;

	ret.Append(p, int(e - p));
	ret.Replace("&quot;", "\"");
	ret.Replace("&apos;", "'");
	ret.Replace("&lt;", "<");
	ret.Replace("&gt;", ">");
	ret.Replace("&amp;", "&");
	ret.Trim();
	return ret;
}

static CMStringA TzerEscape(const char *str)
{
	CMStringA ret(str);
	ret.Replace("&", "&amp;");
	ret.Replace("\"", "&quot;");
	ret.Replace("<", "&lt;");
	ret.Replace(">", "&gt;");
	return ret;
}

static bool IsWebUrl(const char *szUrl)
{
	return !_strnicmp(szUrl, "http://", 7) || !_strnicmp(szUrl, "https://", 8);
}

// What the history shows: "tZer: <name>", readable without any plugin. The
// movie's address is not shown; ME_ICQ_TZER hands it to a plugin that plays it.
static CMStringA TzerText(const char *szName)
{
	return CMStringA(FORMAT, "tZer: %s", *szName ? szName : "?");
}

void CIcqProto::handleTzer(DWORD dwUin, DWORD dwTimestamp, const char *szXml)
{
	if (strstr(szXml, "<tzerRoot") == nullptr) {
		debugLogA("tZer without tzerRoot, ignored");
		return;
	}

	CMStringA szId = TzerAttr(szXml, "id"), szName = TzerAttr(szXml, "name"),
		szUrl = TzerAttr(szXml, "url"), szThumb = TzerAttr(szXml, "thumb");
	if (!IsWebUrl(szUrl))
		szUrl.Empty();
	if (!IsWebUrl(szThumb))
		szThumb.Empty();
	if (szName.IsEmpty())
		szName = szId;

	int bAdded;
	MCONTACT hContact = HContactFromUIN(dwUin, &bAdded);
	if (hContact == INVALID_CONTACT_ID || hContact == 0)
		return;

	debugLogA("tZer %s from %u: %s", szId.c_str(), dwUin, szUrl.c_str());

	CMStringA szText(TzerText(szName));
	DB::EventInfo dbei;
	dbei.iTimestamp = dwTimestamp;
	dbei.pBlob = szText.GetBuffer();
	dbei.cbBlob = szText.GetLength() + 1;
	ProtoChainRecvMsg(hContact, dbei);

	if (!szUrl.IsEmpty()) {
		ICQ_TZER tz = { sizeof(tz), szId, szName, szUrl, szThumb, 0 };
		NotifyEventHooks(m_hTzerEvent, hContact, (LPARAM)&tz);
	}
}

INT_PTR __cdecl CIcqProto::SendTzer(WPARAM hContact, LPARAM lParam)
{
	ICQ_TZER *tz = (ICQ_TZER *)lParam;
	if (tz == nullptr || tz->cbSize < (int)sizeof(ICQ_TZER) || tz->szUrl == nullptr || !IsWebUrl(tz->szUrl))
		return 1;

	DWORD dwUin;
	if (!icqOnline() || getContactUid(hContact, &dwUin, nullptr) || dwUin == 0)
		return 1; // tZers are ICQ to ICQ

	const char *szId = tz->szId ? tz->szId : "";
	const char *szName = tz->szName ? tz->szName : "";
	const char *szThumb = (tz->szThumb && IsWebUrl(tz->szThumb)) ? tz->szThumb : "";

	CMStringA szBody(FORMAT, "<tzerRoot id=\"%s\" url=\"%s\" thumb=\"%s\" name=\"%s\" freeData=\"\"/>\r\n",
		TzerEscape(szId).c_str(), TzerEscape(tz->szUrl).c_str(), TzerEscape(szThumb).c_str(), TzerEscape(szName).c_str());

	cookie_message_data *pCookieData = CreateMessageCookie(MTYPE_TZER, ACKTYPE_SERVER);
	DWORD dwCookie = AllocateCookie(CKT_MESSAGE, 0, hContact, (void*)pCookieData);
	icq_sendXtrazRequestServ(dwUin, dwCookie, szBody.GetBuffer(), szBody.GetLength(), pCookieData);
	debugLogA("tZer %s sent to %u", szId, dwUin);

	// our copy in the history
	CMStringA szText(TzerText(szName));
	DBEVENTINFO dbei = {};
	dbei.szModule = m_szModuleName;
	dbei.iTimestamp = time(0);
	dbei.eventType = EVENTTYPE_MESSAGE;
	dbei.flags = DBEF_SENT | DBEF_UTF;
	dbei.pBlob = szText.GetBuffer();
	dbei.cbBlob = szText.GetLength() + 1;
	db_event_add(hContact, &dbei);

	ICQ_TZER sent = { sizeof(sent), szId, szName, tz->szUrl, szThumb, 1 };
	NotifyEventHooks(m_hTzerEvent, hContact, (LPARAM)&sent);
	return 0;
}
