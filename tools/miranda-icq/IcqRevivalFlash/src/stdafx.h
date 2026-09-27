/*
IcqRevivalFlash: ICQ 6 animated avatars in Miranda NG, played by the Ruffle-based
Flash engine (tools/icq65/flashplayer).

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation version 2
of the License.
*/

#pragma once

#include <windows.h>
#include <ole2.h>
#include <ocidl.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <io.h>
#include <time.h>

#include <vector>

#include <newpluginapi.h>
#include <m_acc.h>
#include <m_clist.h>
#include <m_database.h>
#include <m_langpack.h>
#include <m_netlib.h>
#include <m_protocols.h>
#include <m_protosvc.h>
#include <m_utils.h>
#include <m_srmm_int.h>
#include <m_message.h>
#include <m_icolib.h>
#include <m_imgsrvc.h>
#include <m_json.h>
#include <commctrl.h>

#include "version.h"

// IShockwaveFlash, from the type library of our engine (typelib/flash.idl in
// tools/icq65/flashplayer), which lists the methods in Adobe's vtable order.
#import "flash.tlb" raw_interfaces_only no_namespace named_guids no_smart_pointers

#define MODULENAME "IcqRevivalFlash"

#include "flash.h"
#include "resource.h"

struct CMPlugin : public PLUGIN<CMPlugin>
{
	CMPlugin();

	int Load() override;
	int Unload() override;
};
