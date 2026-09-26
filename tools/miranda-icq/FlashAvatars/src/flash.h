/*
FlashAvatars: what the avatar part (main.cpp) and the tZers (tzer.cpp) share:
the engine, the network user, the log and the movie cache.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation version 2
of the License.
*/

#pragma once

#define MAX_MOVIE_SIZE (4 * 1024 * 1024)

extern HNETLIBUSER g_hNetlib;

void Log(const char *fmt, ...);

// Libs\FlashPlayerControl.dll, loaded on first use; nullptr without it
HMODULE LoadEngine();

// <avatar cache>\Flash\<md5 of url><ext>
CMStringW MovieFile(const CMStringA &url, const wchar_t *wszExt);

// Fetches url into file; to be called on a worker thread
bool DownloadFile(const CMStringA &url, const CMStringW &file, bool bFlash);

// The ICQ capability this plugin announces for every ICQ account
void AddIcqCapability(const char *szModule, const BYTE caps[0x10], const char *szName);

// tzer.cpp
void Tzers_ModulesLoaded();
void Tzers_Unload();

/////////////////////////////////////////////////////////////////////////////////////////
// m_icq.h of our IcqOscarJ port

#define PS_ICQ_ADDCAPABILITY "/IcqAddCapability"
#define PS_ICQ_SENDTZER      "/SendTzer"
#define ME_ICQ_TZER          "/Tzer"

struct ICQ_CUSTOMCAP
{
	int cbSize;
	char caps[0x10];
	HANDLE hIcon;
	char name[64];
};

struct ICQ_TZER
{
	int cbSize;
	const char *szId;     // tZer id as ICQ 6 knows it (tzer.xml)
	const char *szName;   // title, UTF-8
	const char *szUrl;    // the movie (.swf)
	const char *szThumb;  // its picture (.png)
	int bSent;            // ME_ICQ_TZER: sent by us (1) or received (0)
};
