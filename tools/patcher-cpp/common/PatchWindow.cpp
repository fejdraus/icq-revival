// See PatchWindow.h.

#include "PatchWindow.h"
#include "PatchConsole.h"
#include "PatchFiles.h"
#include "PatchIcon.h"
#include "Registry.h"

#include <algorithm>
using std::max;
using std::min;
#include <commctrl.h>
#include <objidl.h>
#include <gdiplus.h>
#include <ole2.h>

#include <cmath>

namespace
{
    // The palette. The window is a grey canvas with white cards on it and a
    // dark header, so the parts stand apart; only the accent line and the
    // main button carry the colour of the client version.
    const COLORREF Canvas = RGB(0xDD, 0xE3, 0xE0);
    const COLORREF Card = RGB(0xFF, 0xFF, 0xFF);
    const COLORREF Border = RGB(0xB4, 0xBF, 0xBA);
    const COLORREF Header = RGB(0x1B, 0x24, 0x20);
    const COLORREF HeaderText = RGB(0xFF, 0xFF, 0xFF);
    const COLORREF HeaderDim = RGB(0xB9, 0xC6, 0xC0);
    const COLORREF Ink = RGB(0x14, 0x1A, 0x17);
    const COLORREF Dim = RGB(0x3E, 0x4A, 0x45);
    const COLORREF ButtonFace = RGB(0xF1, 0xF4, 0xF2);
    const COLORREF ButtonBorder = RGB(0x8E, 0x9B, 0x95);
    const COLORREF ButtonHover = RGB(0xE2, 0xE8, 0xE5);
    const COLORREF Rule = RGB(0xD5, 0xDC, 0xD8);
    const COLORREF Done = RGB(0x17, 0x70, 0x3C);
    const COLORREF Warn = RGB(0xA2, 0x4F, 0x0B);
    const COLORREF Faint = RGB(0x6B, 0x75, 0x70);
    const COLORREF NotFound = RGB(0xC0, 0x39, 0x2B);

    // The width of the window the C# layout was made for, at 96 DPI.
    const int W = 820;
    // The width of a card in it.
    const int CW = W - 32;

    enum
    {
        IdFolder = 100,
        IdServer,
        IdList,
        IdAll,
        IdBar,
        IdFirstButton = 200,
    };

    const wchar_t* ClassName = L"IcqRevivalPatchWindow";
    const wchar_t* AllText = L"Select all";

    PatchWindow* Instance = nullptr;

    void Fill(HDC dc, const RECT& r, COLORREF c)
    {
        SetBkColor(dc, c);
        ExtTextOutW(dc, 0, 0, ETO_OPAQUE, &r, nullptr, 0, nullptr);
    }

    void Frame(HDC dc, const RECT& r, COLORREF c)
    {
        Fill(dc, { r.left, r.top, r.right, r.top + 1 }, c);
        Fill(dc, { r.left, r.bottom - 1, r.right, r.bottom }, c);
        Fill(dc, { r.left, r.top, r.left + 1, r.bottom }, c);
        Fill(dc, { r.right - 1, r.top, r.right, r.bottom }, c);
    }

    COLORREF Darker(COLORREF c, double f)
    {
        return RGB(ps::Int(GetRValue(c) * f), ps::Int(GetGValue(c) * f), ps::Int(GetBValue(c) * f));
    }

    // ControlPaint.Dark: the colour WinForms writes disabled text in on a
    // background of this colour - its luminance, on a scale of 240, cut by
    // a third and then halved. (HLSColor of System.Windows.Forms, integer
    // arithmetic and all.)
    COLORREF DarkOf(COLORREF c)
    {
        const int HLSMax = 240, RGBMax = 255, Undefined = HLSMax * 2 / 3;
        int r = GetRValue(c), g = GetGValue(c), b = GetBValue(c);
        int max = (std::max)(r, (std::max)(g, b)), min = (std::min)(r, (std::min)(g, b));
        int sum = max + min, dif = max - min;
        int lum = ((sum * HLSMax) + RGBMax) / (2 * RGBMax);
        int hue = Undefined, sat = 0;
        if (dif != 0)
        {
            if (lum <= HLSMax / 2) sat = ((dif * HLSMax) + (sum / 2)) / sum;
            else sat = ((dif * HLSMax) + ((2 * RGBMax - sum) / 2)) / (2 * RGBMax - sum);
            int rd = (((max - r) * (HLSMax / 6)) + (dif / 2)) / dif;
            int gd = (((max - g) * (HLSMax / 6)) + (dif / 2)) / dif;
            int bd = (((max - b) * (HLSMax / 6)) + (dif / 2)) / dif;
            if (r == max) hue = bd - gd;
            else if (g == max) hue = (HLSMax / 3) + rd - bd;
            else hue = ((2 * HLSMax) / 3) + gd - rd;
            if (hue < 0) hue += HLSMax;
            if (hue > HLSMax) hue -= HLSMax;
        }
        int zeroLum = (lum * (1000 - 333)) / 1000;
        lum = zeroLum - (int)(zeroLum * 0.5f);
        if (sat == 0)
        {
            int v = (lum * RGBMax) / HLSMax;
            return RGB(v, v, v);
        }
        auto hueToRgb = [&](int n1, int n2, int h) {
            if (h < 0) h += HLSMax;
            if (h > HLSMax) h -= HLSMax;
            if (h < HLSMax / 6) return n1 + (((n2 - n1) * h + (HLSMax / 12)) / (HLSMax / 6));
            if (h < HLSMax / 2) return n2;
            if (h < (HLSMax * 2) / 3) return n1 + (((n2 - n1) * (((HLSMax * 2) / 3) - h) + (HLSMax / 12)) / (HLSMax / 6));
            return n1;
        };
        int m2 = lum <= HLSMax / 2 ? (lum * (HLSMax + sat) + (HLSMax / 2)) / HLSMax : lum + sat - ((lum * sat) + (HLSMax / 2)) / HLSMax;
        int m1 = 2 * lum - m2;
        return RGB((hueToRgb(m1, m2, hue + HLSMax / 3) * RGBMax + HLSMax / 2) / HLSMax,
                   (hueToRgb(m1, m2, hue) * RGBMax + HLSMax / 2) / HLSMax,
                   (hueToRgb(m1, m2, hue - HLSMax / 3) * RGBMax + HLSMax / 2) / HLSMax);
    }

    // The left and right padding TextRenderer gives text: a sixth of the
    // font's height before it, half as much again after it.
    DRAWTEXTPARAMS Margins(HDC dc)
    {
        TEXTMETRICW tm;
        GetTextMetricsW(dc, &tm);
        double overhang = tm.tmHeight / 6.0;
        DRAWTEXTPARAMS p = { sizeof(DRAWTEXTPARAMS) };
        p.iLeftMargin = (int)std::ceil(overhang);
        p.iRightMargin = (int)std::ceil(overhang * 1.5);
        return p;
    }
}

StateView StateView::Of(const std::wstring& state)
{
    struct Known
    {
        const wchar_t* State;
        const wchar_t* Mark;
        const wchar_t* Text;
        bool Counts;
    };
    static const Known known[] = {
        { L"patched", L"done", L"Applied", true },
        { L"original", L"todo", L"Not applied", true },
        { L"another server", L"todo", L"Other server", true },
        { L"partly", L"todo", L"Partly applied", true },
        { L"no links", L"none", L"Nothing to do", false },
        { L"missing", L"none", L"Not in client", false },
        { L"no folder", L"none", L"-", false },
        { L"other version", L"warn", L"Other version", true },
        { L"unknown", L"warn", L"Unknown", true },
    };
    for (const Known& k : known)
    {
        if (ps::KeyEq(k.State, state)) return StateView{ k.Mark, k.Text, k.Counts };
    }
    return StateView{ L"warn", state, true };
}

const wchar_t* PatchWindow::SnapshotVariable = L"ICQ_PATCH_SNAPSHOT";

OptStr PatchWindow::SnapshotPath()
{
    wchar_t buf[32768];
    DWORD n = GetEnvironmentVariableW(SnapshotVariable, buf, 32768);
    if (n == 0 || n >= 32768) return std::nullopt;
    return std::wstring(buf, n);
}

void PatchWindow::Init()
{
    INITCOMMONCONTROLSEX icc = { sizeof icc, ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    // The folder dialog needs COM on this thread, in a single apartment.
    OleInitialize(nullptr);
    static ULONG_PTR token = 0;
    if (token == 0)
    {
        Gdiplus::GdiplusStartupInput input;
        Gdiplus::GdiplusStartup(&token, &input, nullptr);
    }
}

int PatchWindow::S(double v) const { return ps::Int(v * Scale); }

HFONT PatchWindow::MakeFont(const std::wstring& face, double points, int weight, bool forControl) const
{
    HDC dc = GetDC(nullptr);
    double dpi = GetDeviceCaps(dc, LOGPIXELSY);
    ReleaseDC(nullptr, dc);
    // Text WinForms draws itself goes through a font rounded up to whole
    // pixels; the one it hands a native control is rounded to the nearest.
    double px = dpi * points / 72.0;
    LOGFONTW lf = {};
    lf.lfHeight = -(forControl ? (int)std::floor(px + 0.5) : (int)std::ceil(px));
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = DEFAULT_QUALITY;
    std::wstring f = PatchIcon::Face(face);
    // Without Segoe UI Semibold (XP, Vista) its stand-in is drawn bold.
    if (f != face && face.find(L"Semibold") != std::wstring::npos) lf.lfWeight = FW_BOLD;
    wcsncpy_s(lf.lfFaceName, f.c_str(), _TRUNCATE);
    return CreateFontIndirectW(&lf);
}

int PatchWindow::MeasureWidth(const std::wstring& text, HFONT font) const
{
    HDC dc = GetDC(nullptr);
    HGDIOBJ old = SelectObject(dc, font);
    DRAWTEXTPARAMS p = Margins(dc);
    RECT r = { 0, 0, 0x7FFFFFFF, 0x7FFFFFFF };
    std::wstring t = text;
    DrawTextExW(dc, &t[0], (int)t.size(), &r, DT_CALCRECT | DT_SINGLELINE | DT_HIDEPREFIX, &p);
    SelectObject(dc, old);
    ReleaseDC(nullptr, dc);
    return r.right - r.left;
}

PatchWindow::Button* PatchWindow::NewButton(const std::wstring& text, bool primary, int id)
{
    Button* b = new Button();
    b->Text = text;
    b->Primary = primary;
    b->Id = id;
    // Measured at the screen's DPI and scaled with the window after, as
    // WinForms did it.
    b->Width = (std::max)(100, MeasureWidth(text, formFont_) + 40);
    b->Hwnd = CreateWindowExW(0, L"BUTTON", text.c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 10, 10,
                              form_, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    SetWindowLongPtrW(b->Hwnd, GWLP_USERDATA, (LONG_PTR)b);
    WNDPROC old = (WNDPROC)SetWindowLongPtrW(b->Hwnd, GWLP_WNDPROC, (LONG_PTR)ButtonProc);
    if (buttonProc_ == nullptr) buttonProc_ = old;
    SendMessageW(b->Hwnd, WM_SETFONT, (WPARAM)(primary ? boldFont_ : formFont_), FALSE);
    return b;
}

PatchWindow::PatchWindow(const std::wstring& title, const std::wstring& subtitle, const std::wstring& badge,
                         const std::wstring& accentTop, const std::wstring& accentBottom, const std::wstring& clientName,
                         const std::wstring& serverHint, const std::vector<std::pair<std::wstring, int>>& columns)
    : title_(title), subtitle_(subtitle), badge_(badge), accentTop_(accentTop), accentBottom_(accentBottom), hint_(serverHint)
{
    Instance = this;
    HDC sdc = GetDC(nullptr);
    Scale = GetDeviceCaps(sdc, LOGPIXELSX) / 96.0;
    ReleaseDC(nullptr, sdc);
    Accent = PatchIcon::ColorOf(accentBottom);
    summaryHeight_ = S(40);
    captionFolder_ = ps::ToUpper(clientName + L" folder");
    captionServer_ = ps::ToUpper(L"Server domain");

    formFont_ = MakeFont(L"Segoe UI", 9.5, FW_NORMAL, false);
    formFontControl_ = MakeFont(L"Segoe UI", 9.5, FW_NORMAL, true);
    boldFont_ = MakeFont(L"Segoe UI", 9.5, FW_BOLD, false);
    titleFont_ = MakeFont(L"Segoe UI Semibold", 16, FW_NORMAL, false);
    captionFont_ = MakeFont(L"Segoe UI", 8.25, FW_BOLD, false);
    pathFont_ = MakeFont(L"Segoe UI Semibold", 10, FW_NORMAL, false);
    serverFont_ = MakeFont(L"Segoe UI", 11, FW_NORMAL, true);
    allFont_ = MakeFont(L"Segoe UI Semibold", 9.5, FW_NORMAL, true);
    summaryFont_ = MakeFont(L"Segoe UI Semibold", 10, FW_NORMAL, false);
    cardBrush_ = CreateSolidBrush(Card);

    HINSTANCE inst = GetModuleHandleW(nullptr);
    bigIcon_ = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
    smallIcon_ = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    headerIcon_ = PatchIcon::Draw(ps::Int(60 * Scale), badge, accentTop, accentBottom);

    WNDCLASSEXW wc = { sizeof wc };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = bigIcon_;
    wc.hIconSm = smallIcon_;
    wc.lpszClassName = ClassName;
    RegisterClassExW(&wc);

    // The client area of the C# window: 820 x 660 at 96 DPI.
    RECT r = { 0, 0, S(W), S(660) };
    DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    AdjustWindowRectEx(&r, style, FALSE, 0);
    int ww = r.right - r.left, wh = r.bottom - r.top;
    // CenterScreen: the working area of the screen the mouse is on.
    POINT cursor;
    GetCursorPos(&cursor);
    MONITORINFO mi = { sizeof mi };
    GetMonitorInfoW(MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST), &mi);
    int x = mi.rcWork.left + ((mi.rcWork.right - mi.rcWork.left) - ww) / 2;
    int y = mi.rcWork.top + ((mi.rcWork.bottom - mi.rcWork.top) - wh) / 2;
    form_ = CreateWindowExW(0, ClassName, title.c_str(), style, x, y, ww, wh, nullptr, nullptr, inst, nullptr);
    SendMessageW(form_, WM_SETICON, ICON_BIG, (LPARAM)bigIcon_);
    SendMessageW(form_, WM_SETICON, ICON_SMALL, (LPARAM)smallIcon_);

    // The list of changes comes first in the tab order, as it did.
    list_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHAREIMAGELISTS | LVS_NOSORTHEADER,
                            0, 0, 10, 10, form_, (HMENU)(INT_PTR)IdList, inst, nullptr);
    SendMessageW(list_, WM_SETFONT, (WPARAM)formFontControl_, FALSE);
    SendMessageW(list_, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES | LVS_EX_INFOTIP);
    SendMessageW(list_, LVM_SETTEXTCOLOR, 0, Ink);
    // The tick is the only mark on a row; the State column says the rest.
    // An empty image one pixel wide only gives the rows some height.
    HIMAGELIST spacer = ImageList_Create(1, ps::Int(22 * Scale), ILC_COLOR32, 0, 0);
    SendMessageW(list_, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)spacer);
    std::vector<std::pair<std::wstring, int>> cols = columns;
    cols.push_back({ L"State", 110 });
    for (size_t i = 0; i < cols.size(); i++)
    {
        LVCOLUMNW c = {};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        c.fmt = LVCFMT_LEFT;
        c.cx = ps::Int(cols[i].second * Scale);
        c.pszText = &cols[i].first[0];
        SendMessageW(list_, LVM_INSERTCOLUMNW, i, (LPARAM)&c);
    }
    SendMessageW(list_, LVM_ENABLEGROUPVIEW, TRUE, 0);

    // WinForms draws the words of a check box itself, with the padding it
    // gives all text: they stand a few pixels further from the box than
    // Windows puts them. So once the control has drawn itself its words are
    // wiped and drawn again where WinForms put them (CustomDrawAll); the
    // control keeps them as its text, for whoever reads the window.
    all_ = CreateWindowExW(0, L"BUTTON", AllText, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_3STATE, 0, 0, 10, 10, form_,
                           (HMENU)(INT_PTR)IdAll, inst, nullptr);
    SendMessageW(all_, WM_SETFONT, (WPARAM)allFont_, FALSE);
    {
        // AutoSize: the box, a gap, and the words.
        int text = MeasureWidth(AllText, allFont_);
        allWidth_ = AllTextLeft() + text;
        HDC dc = GetDC(nullptr);
        HGDIOBJ old = SelectObject(dc, allFont_);
        TEXTMETRICW tm;
        GetTextMetricsW(dc, &tm);
        SelectObject(dc, old);
        ReleaseDC(nullptr, dc);
        allHeight_ = (std::max)((int)tm.tmHeight, ps::Int(13 * Scale)) + 3;
    }

    // the bottom bar: how far along it is, and the buttons
    bar_ = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | PBS_SMOOTH, 0, 0, 10, 10, form_, (HMENU)(INT_PTR)IdBar, inst, nullptr);
    buttonsRight_ = W - 16;

    // the client folder and the server, on one card
    folderButton_ = NewButton(L"Change folder...", false, IdFolder);
    server_ = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 10, 10,
                              form_, (HMENU)(INT_PTR)IdServer, inst, nullptr);
    SendMessageW(server_, WM_SETFONT, (WPARAM)serverFont_, FALSE);
    editProc_ = (WNDPROC)SetWindowLongPtrW(server_, GWLP_WNDPROC, (LONG_PTR)EditProc);
    {
        // TextBox.PreferredHeight: the height of its font, rounded up, and
        // the border four times over, plus three.
        Gdiplus::FontFamily family(PatchIcon::Face(L"Segoe UI").c_str());
        HDC dc = GetDC(nullptr);
        double em = 11 * GetDeviceCaps(dc, LOGPIXELSY) / 72.0;
        ReleaseDC(nullptr, dc);
        double line = em * family.GetLineSpacing(Gdiplus::FontStyleRegular) / family.GetEmHeight(Gdiplus::FontStyleRegular);
        serverHeight_ = (int)std::ceil(line) + GetSystemMetrics(SM_CYBORDER) * 4 + 3;
    }
    Layout();
}

PatchWindow::~PatchWindow()
{
    for (Button* b : footerButtons_) delete b;
    delete folderButton_;
    delete (Gdiplus::Bitmap*)headerIcon_;
    for (HFONT f : { formFont_, formFontControl_, boldFont_, titleFont_, captionFont_, pathFont_, serverFont_, allFont_, summaryFont_ })
    {
        if (f) DeleteObject(f);
    }
    if (cardBrush_) DeleteObject(cardBrush_);
    if (Instance == this) Instance = nullptr;
}

void PatchWindow::AddButton(const std::wstring& text, std::function<void()> action, bool primary)
{
    Button* b = NewButton(text, primary, IdFirstButton + (int)footerButtons_.size());
    b->Action = std::move(action);
    buttonsRight_ -= b->Width;
    b->Right = W - (buttonsRight_ + b->Width);
    footerButtons_.push_back(b);
    buttonsRight_ -= 8;
    // The summary ends where the buttons begin, and stays under them.
    summaryWidth_ = (std::max)(40, buttonsRight_ - 20);
    if (primary) defaultButton_ = b->Id;
    Layout();
}

std::wstring PatchWindow::ServerText() const
{
    int n = GetWindowTextLengthW(server_);
    std::wstring s(n + 1, L'\0');
    GetWindowTextW(server_, &s[0], n + 1);
    s.resize(n);
    return s;
}

void PatchWindow::SetServerText(const std::wstring& text) { SetWindowTextW(server_, text.c_str()); }

void PatchWindow::Layout()
{
    RECT c;
    GetClientRect(form_, &c);
    int wc = c.right, hc = c.bottom;
    int top = S(96) + S(4);
    int cardX = S(16), cardW = wc - 2 * S(16);
    int settingsY = top + S(16);
    int contentTop = top + S(158);
    int footerY = hc - S(64);
    int contentY = contentTop + S(12);
    int contentH = footerY - contentTop - S(12) - S(16);

    HDWP dw = BeginDeferWindowPos(12);
    auto place = [&](HWND h, int x, int y, int w, int hh) {
        dw = DeferWindowPos(dw, h, nullptr, x, y, (std::max)(0, w), (std::max)(0, hh), SWP_NOZORDER | SWP_NOACTIVATE);
    };
    int fbw = S(folderButton_->Width);
    place(folderButton_->Hwnd, cardX + cardW - S(16) - fbw, settingsY + S(26), fbw, S(34));
    place(server_, cardX + S(16), settingsY + S(104), S(320), serverHeight_);
    place(all_, cardX + 1 + S(4), contentY + 1 + S(10), allWidth_, allHeight_);
    place(list_, cardX + 1, contentY + 1 + S(40), cardW - 2, contentH - 2 - S(40));
    int summaryW = wc - S(20) - S(W - 20 - summaryWidth_);
    place(bar_, S(20), footerY + S(40), summaryW, S(10));
    for (Button* b : footerButtons_)
    {
        int bw = S(b->Width);
        place(b->Hwnd, wc - S(b->Right) - bw, footerY + S(15), bw, S(34));
    }
    EndDeferWindowPos(dw);
    InvalidateRect(form_, nullptr, FALSE);
}

void PatchWindow::DrawLabel(HDC dc, const std::wstring& text, const RECT& r, HFONT font, COLORREF color, UINT flags,
                            bool labelAlign) const
{
    if (text.empty()) return;
    HGDIOBJ old = SelectObject(dc, font);
    SetTextColor(dc, color);
    SetBkMode(dc, TRANSPARENT);
    DRAWTEXTPARAMS p = Margins(dc);
    RECT rr = r;
    std::wstring t = text;
    if (labelAlign && (flags & (DT_VCENTER | DT_BOTTOM)))
    {
        // A label places middle and bottom text itself, as TextRenderer
        // does: half the height less half the text's, each cut to whole
        // pixels - a pixel lower than DrawText centres it now and then.
        RECT m = r;
        std::wstring mt = text;
        int th = DrawTextExW(dc, &mt[0], (int)mt.size(), &m, (flags & ~(DT_VCENTER | DT_BOTTOM)) | DT_CALCRECT | DT_HIDEPREFIX, &p);
        int h = r.bottom - r.top;
        if (th <= h) rr.top = (flags & DT_VCENTER) ? r.top + h / 2 - th / 2 : r.bottom - th;
        flags &= ~(DT_VCENTER | DT_BOTTOM);
    }
    DrawTextExW(dc, &t[0], (int)t.size(), &rr, flags | DT_HIDEPREFIX, &p);
    SelectObject(dc, old);
}

void PatchWindow::Paint(HDC dc, const RECT&)
{
    RECT c;
    GetClientRect(form_, &c);
    int wc = c.right, hc = c.bottom;
    Fill(dc, c, Canvas);

    // header: the icon, the name of the patch and what it does
    int headerH = S(96);
    Fill(dc, { 0, 0, wc, headerH }, Header);
    {
        Gdiplus::Graphics g(dc);
        Gdiplus::Bitmap* icon = (Gdiplus::Bitmap*)headerIcon_;
        g.DrawImage(icon, Gdiplus::Rect(S(20), S(18), S(60), S(60)));
    }
    DrawLabel(dc, title_, { S(94), S(12), wc, headerH }, titleFont_, HeaderText, DT_SINGLELINE | DT_NOCLIP);
    DrawLabel(dc, subtitle_, { S(96), S(48), wc - S(20), S(48) + S(42) }, formFont_, HeaderDim, DT_WORDBREAK | DT_EDITCONTROL);
    Fill(dc, { 0, headerH, wc, headerH + S(4) }, Accent);

    // the client folder and the server, on one card
    int top = headerH + S(4);
    int cardX = S(16), cardW = wc - 2 * S(16);
    int sy = top + S(16), sh = S(158) - S(16);
    RECT settings = { cardX, sy, cardX + cardW, sy + sh };
    Fill(dc, settings, Card);
    Frame(dc, settings, Border);
    DrawLabel(dc, captionFolder_, { cardX + S(16), sy + S(14), cardX + cardW, sy + sh }, captionFont_, Dim, DT_SINGLELINE | DT_NOCLIP);
    DrawLabel(dc, pathText_, { cardX + S(16), sy + S(36), cardX + cardW - S(184), sy + S(36) + S(22) }, pathFont_, pathColor_,
              DT_SINGLELINE | DT_END_ELLIPSIS);
    Fill(dc, { cardX + S(16), sy + S(70), cardX + cardW - S(16), sy + S(70) + (std::max)(1, S(1)) }, Rule);
    DrawLabel(dc, captionServer_, { cardX + S(16), sy + S(82), cardX + cardW, sy + sh }, captionFont_, Dim, DT_SINGLELINE | DT_NOCLIP);
    DrawLabel(dc, hint_, { cardX + S(352), sy + S(100), cardX + cardW - S(16), sy + S(100) + S(38) }, formFont_, Dim,
              DT_WORDBREAK | DT_EDITCONTROL);

    // the list of changes, on a card of its own
    int contentTop = top + S(158);
    int footerY = hc - S(64);
    int cy = contentTop + S(12);
    int ch = footerY - contentTop - S(12) - S(16);
    RECT content = { cardX, cy, cardX + cardW, cy + ch };
    Fill(dc, content, Card);
    Frame(dc, content, Border);
    int barBottom = cy + 1 + S(40);
    Fill(dc, { cardX + 1, barBottom - 1, cardX + cardW - 1, barBottom }, Rule);
    DrawLabel(dc, picked_, { cardX + 1 + S(130), cy + 1 + S(12), cardX + cardW - 1 - S(12), cy + 1 + S(12) + S(20) }, formFont_, Dim,
              DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_END_ELLIPSIS);

    // the bottom bar
    Fill(dc, { 0, footerY, wc, hc }, Card);
    Fill(dc, { 0, footerY, wc, footerY + 1 }, Border);
    int summaryW = wc - S(20) - S(W - 20 - summaryWidth_);
    RECT sr = { S(20), footerY + S(13), S(20) + summaryW, footerY + S(13) + summaryHeight_ };
    DrawLabel(dc, summary_, sr, summaryFont_, summaryColor_,
              DT_SINGLELINE | DT_END_ELLIPSIS | (working_ ? DT_BOTTOM : DT_VCENTER));
}

void PatchWindow::DrawButton(const DRAWITEMSTRUCT* d)
{
    Button* b = (Button*)GetWindowLongPtrW(d->hwndItem, GWLP_USERDATA);
    if (b == nullptr) return;
    RECT r = d->rcItem;
    bool pressed = (d->itemState & ODS_SELECTED) != 0;
    bool disabled = (d->itemState & ODS_DISABLED) != 0;
    COLORREF back = b->Primary ? Accent : ButtonFace;
    COLORREF border = b->Primary ? Accent : ButtonBorder;
    COLORREF hover = b->Primary ? Darker(Accent, 0.85) : ButtonHover;
    COLORREF fore = b->Primary ? RGB(255, 255, 255) : Ink;
    // Disabled while Apply or Restore runs: WinForms writes the text darker
    // than the face (ControlPaint.Dark).
    if (disabled) fore = DarkOf(back);
    // Held down: WinForms leaves that to the system when no colour is set;
    // a shade darker than the hover one.
    if (!disabled && pressed) back = Darker(hover, 0.92);
    else if (!disabled && b->Hover) back = hover;
    Fill(d->hDC, r, back);
    Frame(d->hDC, r, border);
    DrawLabel(d->hDC, b->Text, r, b->Primary ? boldFont_ : formFont_, fore, DT_SINGLELINE | DT_CENTER | DT_VCENTER, false);
    if ((d->itemState & ODS_FOCUS) && !(d->itemState & ODS_NOFOCUSRECT))
    {
        RECT f = { r.left + 3, r.top + 3, r.right - 3, r.bottom - 3 };
        SetTextColor(d->hDC, fore);
        DrawFocusRect(d->hDC, &f);
    }
}

LRESULT CALLBACK PatchWindow::ButtonProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    Button* b = (Button*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    PatchWindow* self = Instance;
    if (b != nullptr)
    {
        if (msg == WM_MOUSEMOVE && !b->Hover)
        {
            b->Hover = true;
            TRACKMOUSEEVENT t = { sizeof t, TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&t);
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        else if (msg == WM_MOUSELEAVE)
        {
            b->Hover = false;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        else if (msg == WM_ERASEBKGND)
        {
            return 1;
        }
    }
    return CallWindowProcW(self->buttonProc_, hwnd, msg, wp, lp);
}

LRESULT CALLBACK PatchWindow::EditProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    PatchWindow* self = Instance;
    LRESULT r = CallWindowProcW(self->editProc_, hwnd, msg, wp, lp);
    // Leave: the focus moved on to another control of the window, not to
    // another program - coming back puts it into the box again.
    if (msg == WM_KILLFOCUS)
    {
        HWND to = (HWND)wp;
        if (to != nullptr && IsChild(self->form_, to) && self->OnServerLeave)
        {
            try
            {
                self->OnServerLeave();
            }
            catch (const PatchError& e)
            {
                PatchConsole::ErrorLine(e.Message);
            }
        }
    }
    return r;
}

LRESULT CALLBACK PatchWindow::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    PatchWindow* self = Instance;
    if (self == nullptr || self->form_ == nullptr || self->form_ != hwnd) return DefWindowProcW(hwnd, msg, wp, lp);
    return self->Handle(msg, wp, lp);
}

LRESULT PatchWindow::Handle(UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(form_, &ps);
        RECT c;
        GetClientRect(form_, &c);
        // Drawn off screen and put up in one go, so nothing flickers.
        HDC mem = CreateCompatibleDC(dc);
        HBITMAP bmp = CreateCompatibleBitmap(dc, (std::max)(1L, c.right), (std::max)(1L, c.bottom));
        HGDIOBJ old = SelectObject(mem, bmp);
        Paint(mem, ps.rcPaint);
        BitBlt(dc, ps.rcPaint.left, ps.rcPaint.top, ps.rcPaint.right - ps.rcPaint.left, ps.rcPaint.bottom - ps.rcPaint.top, mem,
               ps.rcPaint.left, ps.rcPaint.top, SRCCOPY);
        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(form_, &ps);
        return 0;
    }
    case WM_PRINTCLIENT:
    {
        RECT c;
        GetClientRect(form_, &c);
        Paint((HDC)wp, c);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_SIZE:
        Layout();
        return 0;
    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mm = (MINMAXINFO*)lp;
        mm->ptMinTrackSize.x = S(680);
        mm->ptMinTrackSize.y = S(520);
        return 0;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        if ((HWND)lp == all_)
        {
            SetTextColor((HDC)wp, Ink);
            SetBkColor((HDC)wp, Card);
            return (LRESULT)cardBrush_;
        }
        break;
    case WM_SETCURSOR:
        if (Busy)
        {
            SetCursor(LoadCursorW(nullptr, IDC_WAIT));
            return TRUE;
        }
        if (LOWORD(lp) == HTCLIENT)
        {
            HWND over = (HWND)wp;
            bool hand = over == all_ || over == folderButton_->Hwnd;
            for (Button* b : footerButtons_) hand = hand || over == b->Hwnd;
            if (hand)
            {
                SetCursor(LoadCursorW(nullptr, IDC_HAND));
                return TRUE;
            }
        }
        break;
    case WM_DRAWITEM:
        DrawButton((const DRAWITEMSTRUCT*)lp);
        return TRUE;
    case DM_GETDEFID:
        return defaultButton_ != 0 ? MAKELRESULT(defaultButton_, DC_HASDEFID) : 0;
    case WM_ACTIVATE:
        // The control that had the focus gets it back, as in a dialog.
        if (LOWORD(wp) == WA_INACTIVE)
        {
            HWND f = GetFocus();
            if (f != nullptr && IsChild(form_, f)) lastFocus_ = f;
        }
        else
        {
            SetFocus(lastFocus_ != nullptr && IsWindowEnabled(lastFocus_) ? lastFocus_ : list_);
        }
        return 0;
    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        int code = HIWORD(wp);
        if (code != BN_CLICKED) break;
        try
        {
            if (id == IdFolder)
            {
                if (OnFolderButton) OnFolderButton();
            }
            else if (id == IdAll)
            {
                SwitchAll();
            }
            else
            {
                for (Button* b : footerButtons_)
                {
                    if (b->Id == id && IsWindowEnabled(b->Hwnd))
                    {
                        // The action may close the window; it is the last thing done.
                        std::function<void()> action = b->Action;
                        action();
                        break;
                    }
                }
            }
        }
        catch (const PatchError& e)
        {
            // A failure inside a button's work is reported and the window
            // stays, as it did in the script.
            PatchConsole::ErrorLine(e.Message);
        }
        return 0;
    }
    case WM_NOTIFY:
    {
        NMHDR* h = (NMHDR*)lp;
        if (h->hwndFrom == all_ && h->code == NM_CUSTOMDRAW) return CustomDrawAll((NMCUSTOMDRAW*)lp);
        if (h->hwndFrom != list_) break;
        switch (h->code)
        {
        case NM_CUSTOMDRAW:
            return CustomDraw((NMLVCUSTOMDRAW*)lp);
        case LVN_ITEMCHANGING:
        {
            // Once anything is applied the ticks stay as they were applied with.
            NMLISTVIEW* n = (NMLISTVIEW*)lp;
            if ((n->uChanged & LVIF_STATE) && ((n->uNewState ^ n->uOldState) & LVIS_STATEIMAGEMASK) &&
                (n->uOldState & LVIS_STATEIMAGEMASK) != 0)
            {
                if (Locked && Shown && !Filling) return TRUE;
            }
            return FALSE;
        }
        case LVN_ITEMCHANGED:
        {
            NMLISTVIEW* n = (NMLISTVIEW*)lp;
            if ((n->uChanged & LVIF_STATE) && ((n->uNewState ^ n->uOldState) & LVIS_STATEIMAGEMASK) &&
                (n->uOldState & LVIS_STATEIMAGEMASK) != 0 && n->iItem >= 0)
            {
                UpdateChecks(n->iItem);
            }
            return 0;
        }
        case LVN_GETINFOTIPW:
        {
            NMLVGETINFOTIPW* t = (NMLVGETINFOTIPW*)lp;
            if (t->iItem >= 0 && t->iItem < (int)rows_.size() && t->pszText != nullptr && t->cchTextMax > 0)
            {
                wcsncpy_s(t->pszText, t->cchTextMax, rows_[t->iItem].Tip.c_str(), _TRUNCATE);
            }
            return 0;
        }
        }
        break;
    }
    case WM_CLOSE:
        // Not closed halfway through writing the client's files.
        if (Busy) return 0;
        DestroyWindow(form_);
        return 0;
    case WM_DESTROY:
        form_ = nullptr;
        return 0;
    }
    return DefWindowProcW(form_, msg, wp, lp);
}

int PatchWindow::AllTextLeft() const
{
    // Where WinForms starts the words of "Select all": four pixels past the
    // width of a check mark, less the padding TextRenderer puts before them
    // - measured on its window at 96 and 120 DPI.
    HDC dc = GetDC(nullptr);
    HGDIOBJ old = SelectObject(dc, allFont_);
    DRAWTEXTPARAMS p = Margins(dc);
    SelectObject(dc, old);
    ReleaseDC(nullptr, dc);
    return GetSystemMetrics(SM_CXMENUCHECK) + 4 - p.iLeftMargin;
}

LRESULT PatchWindow::CustomDrawAll(NMCUSTOMDRAW* cd)
{
    if (cd->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYPOSTPAINT;
    if (cd->dwDrawStage != CDDS_POSTPAINT) return CDRF_DODEFAULT;
    RECT r = cd->rc;
    RECT wipe = r;
    wipe.left += ps::Int(13 * Scale) + 1;
    Fill(cd->hdc, wipe, Card);
    r.left += AllTextLeft();
    // WinForms lays the words out in the box less its bottom edge.
    r.bottom -= 2;
    bool enabled = IsWindowEnabled(all_) != FALSE;
    DrawLabel(cd->hdc, AllText, r, allFont_, enabled ? Ink : DarkOf(Card), DT_SINGLELINE | DT_VCENTER);
    LRESULT ui = SendMessageW(all_, WM_QUERYUISTATE, 0, 0);
    if (GetFocus() == all_ && !(ui & UISF_HIDEFOCUS))
    {
        HGDIOBJ old = SelectObject(cd->hdc, allFont_);
        DRAWTEXTPARAMS p = Margins(cd->hdc);
        RECT t = r;
        std::wstring s = AllText;
        DrawTextExW(cd->hdc, &s[0], (int)s.size(), &t, DT_SINGLELINE | DT_CALCRECT, &p);
        int h = t.bottom - t.top;
        RECT f = { r.left, r.top + (r.bottom - r.top - h) / 2, t.right, r.top + (r.bottom - r.top - h) / 2 + h };
        SelectObject(cd->hdc, old);
        SetTextColor(cd->hdc, Ink);
        SetBkColor(cd->hdc, Card);
        DrawFocusRect(cd->hdc, &f);
    }
    return CDRF_DODEFAULT;
}

LRESULT PatchWindow::CustomDraw(NMLVCUSTOMDRAW* cd)
{
    switch (cd->nmcd.dwDrawStage)
    {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT:
        return CDRF_NOTIFYSUBITEMDRAW;
    case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
    {
        // Group headers draw on their own; only rows of the list get colours.
        size_t row = (size_t)cd->nmcd.dwItemSpec;
        if (row < rows_.size() && cd->iSubItem >= 0 && (size_t)cd->iSubItem < rows_[row].Colors.size())
        {
            cd->clrText = rows_[row].Colors[cd->iSubItem];
            return CDRF_NEWFONT;
        }
        return CDRF_DODEFAULT;
    }
    }
    return CDRF_DODEFAULT;
}

void PatchWindow::SetFolder(const OptStr& path)
{
    if (ps::IsTrue(path))
    {
        pathText_ = *path;
        pathColor_ = Ink;
    }
    else
    {
        pathText_ = L"Not found - use \"Change folder...\" to pick it";
        pathColor_ = NotFound;
    }
    InvalidateRect(form_, nullptr, FALSE);
}

void PatchWindow::ClearList()
{
    Filling = true;
    SendMessageW(list_, WM_SETREDRAW, FALSE, 0);
    SendMessageW(list_, LVM_DELETEALLITEMS, 0, 0);
    SendMessageW(list_, LVM_REMOVEALLGROUPS, 0, 0);
    Rows.clear();
    rows_.clear();
}

int PatchWindow::AddGroup(const std::wstring& name)
{
    std::wstring header = name;
    LVGROUP g = {};
    g.cbSize = sizeof g;
    g.mask = LVGF_HEADER | LVGF_GROUPID | LVGF_ALIGN;
    g.pszHeader = &header[0];
    g.iGroupId = nextGroup_++;
    g.uAlign = LVGA_HEADER_LEFT;
    SendMessageW(list_, LVM_INSERTGROUP, (WPARAM)-1, (LPARAM)&g);
    return g.iGroupId;
}

void PatchWindow::AddRow(int group, const std::vector<std::wstring>& cells, const std::wstring& state, const std::wstring& key)
{
    StateView view = StateView::Of(state);
    std::wstring text = cells[0];
    // A capital to start the row, except for names spelt with one inside (tZers).
    if (text.size() > 1 && !IsCharUpperW(text[1])) text = ps::ToUpper(text.substr(0, 1)) + text.substr(1);

    Row row;
    row.Key = key;
    row.Tip = text;
    row.Colors.push_back(Ink);
    for (size_t i = 1; i < cells.size(); i++) row.Colors.push_back(Dim);
    if (view.Mark == L"done") row.Colors.push_back(Done);
    else if (view.Mark == L"warn") row.Colors.push_back(Warn);
    else if (view.Mark == L"todo") row.Colors.push_back(Ink);
    else row.Colors.push_back(Faint);

    int index = (int)rows_.size();
    LVITEMW it = {};
    it.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_GROUPID;
    it.iItem = index;
    it.iImage = -1;
    it.iGroupId = group;
    it.pszText = &text[0];
    index = (int)SendMessageW(list_, LVM_INSERTITEMW, 0, (LPARAM)&it);
    rows_.push_back(row);
    Rows.push_back(view);
    std::vector<std::wstring> sub(cells.begin() + 1, cells.end());
    sub.push_back(view.Text);
    for (size_t i = 0; i < sub.size(); i++)
    {
        LVITEMW s = {};
        s.iSubItem = (int)i + 1;
        s.pszText = &sub[i][0];
        SendMessageW(list_, LVM_SETITEMTEXTW, index, (LPARAM)&s);
    }
    ListView_SetCheckState(list_, index, !Unchecked.Contains(key));
}

int PatchWindow::ItemCount() const { return (int)SendMessageW(list_, LVM_GETITEMCOUNT, 0, 0); }

bool PatchWindow::Ticked(int index) const { return ListView_GetCheckState(list_, index) != 0; }

void PatchWindow::CompleteList()
{
    Locked = false;
    for (const StateView& r : Rows)
    {
        if (r.Counts && r.Mark == L"done") Locked = true;
    }
    EnableWindow(all_, !Locked);
    // A locked client holds what it was applied with, and whatever is in
    // place is part of that - also a job that is off until chosen.
    if (Locked)
    {
        for (int i = 0; i < ItemCount(); i++)
        {
            if (Rows[i].Mark == L"done" && !Ticked(i))
            {
                ListView_SetCheckState(list_, i, TRUE);
                Unchecked.Remove(rows_[i].Key);
            }
        }
    }
    SendMessageW(list_, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(list_, nullptr, TRUE);
    Filling = false;
    UpdateSummary();
}

void PatchWindow::UpdateChecks(int index)
{
    if (Filling || index < 0 || index >= (int)rows_.size()) return;
    if (Ticked(index)) Unchecked.Remove(rows_[index].Key);
    else Unchecked.Add(rows_[index].Key);
    // Select all sums up once, after the last row.
    if (!Syncing) UpdateSummary();
}

void PatchWindow::SwitchAll()
{
    // Everything ticked becomes everything cleared; anything else, all ticked.
    if (Locked) return;
    int n = ItemCount();
    bool target = false;
    for (int i = 0; i < n; i++)
    {
        if (!Ticked(i)) target = true;
    }
    Syncing = true;
    for (int i = 0; i < n; i++)
    {
        if (Ticked(i) != target) ListView_SetCheckState(list_, i, target);
    }
    Syncing = false;
    UpdateSummary();
}

bool PatchWindow::IsSelected(const std::wstring& key) const { return !Unchecked.Contains(key); }

void PatchWindow::SetSummary(const std::wstring& text, COLORREF color)
{
    summary_ = text;
    summaryColor_ = color;
    InvalidateFooterText();
}

void PatchWindow::InvalidateFooterText()
{
    InvalidateRect(form_, nullptr, FALSE);
}

void PatchWindow::UpdateSummary()
{
    int n = ItemCount();
    int ticked = 0;
    for (int i = 0; i < n; i++)
    {
        if (Ticked(i)) ticked++;
    }
    SendMessageW(all_, BM_SETCHECK, n > 0 && ticked == n ? BST_CHECKED : ticked == 0 ? BST_UNCHECKED : BST_INDETERMINATE, 0);
    picked_ = n == 0 ? L""
            : Locked ? L"Selection locked - Restore original to change it"
                     : ps::Num(ticked) + L" of " + ps::Num(n) + L" selected";

    // What Apply would do: put in what is ticked and missing, take out
    // what is in place and cleared.
    int counted = 0, done = 0, warn = 0, pending = 0;
    for (int i = 0; i < n; i++)
    {
        const StateView& view = Rows[i];
        if (!view.Counts) continue;
        counted++;
        if (view.Mark == L"done") done++;
        if (view.Mark == L"warn") warn++;
        bool t = Ticked(i);
        if ((t && view.Mark == L"todo") || (!t && view.Mark == L"done")) pending++;
    }
    if (counted == 0) summary_ = L"";
    else if (warn > 0) SetSummary(ps::Num(warn) + L" item(s) do not match this client version", Warn);
    else if (pending > 0) SetSummary(L"Apply will change " + ps::Num(pending) + L" of " + ps::Num(counted), Ink);
    else if (done == counted) SetSummary(L"All " + ps::Num(done) + L" changes are in place", Done);
    else SetSummary(L"Selection in place: " + ps::Num(done) + L" of " + ps::Num(counted) + L" applied", Done);
    InvalidateFooterText();
}

void PatchWindow::ReadUnchecked(const std::wstring& settingsKey, const std::vector<std::wstring>& defaultOff)
{
    std::vector<std::wstring> known;
    try
    {
        Reg::Key key = Reg::Open(HKEY_CURRENT_USER, settingsKey, false);
        if (key)
        {
            for (const std::wstring& k : Reg::Strings(Reg::GetValue(key, L"Unchecked")))
            {
                if (!k.empty()) Unchecked.Add(k);
            }
            known = Reg::Strings(Reg::GetValue(key, L"Known"));
        }
    }
    catch (const PatchError&)
    {
    }
    for (const std::wstring& k : defaultOff)
    {
        if (!ps::Contains(known, k)) Unchecked.Add(k);
    }
}

void PatchWindow::SaveUnchecked(const std::wstring& settingsKey)
{
    try
    {
        Reg::Key key = Reg::Create(HKEY_CURRENT_USER, settingsKey);
        Reg::SetMultiString(key, L"Unchecked", Unchecked.Items());
        std::vector<std::wstring> names;
        for (const Row& r : rows_) names.push_back(r.Key);
        Reg::SetMultiString(key, L"Known", names);
    }
    catch (const PatchError&)
    {
    }
}

void PatchWindow::Pump()
{
    MSG m;
    while (form_ != nullptr && PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE))
    {
        if (m.message == WM_QUIT)
        {
            PostQuitMessage((int)m.wParam);
            break;
        }
        if (!IsDialogMessageW(form_, &m))
        {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
}

void PatchWindow::StartWork(const std::wstring& text)
{
    Busy = true;
    for (Button* b : footerButtons_) EnableWindow(b->Hwnd, FALSE);
    for (HWND h : { folderButton_->Hwnd, server_, list_, all_ }) EnableWindow(h, FALSE);
    SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    working_ = true;
    // Summary.Height = 26 and, below, = 40: set after the window was
    // scaled, so WinForms took them as pixels - the summary sits higher
    // above 96 DPI once anything has run. Kept as it was.
    summaryHeight_ = 26;
    SetSummary(text, Ink);
    SendMessageW(bar_, PBM_SETPOS, 0, 0);
    ::ShowWindow(bar_, SW_SHOW);
    PatchSteps::Show = [this](int done, int total, const std::wstring& step) {
        SendMessageW(bar_, PBM_SETRANGE32, 0, total);
        SendMessageW(bar_, PBM_SETPOS, (std::min)(done - 1, total), 0);
        summary_ = step;
        InvalidateFooterText();
        UpdateWindow(form_);
        Pump();
    };
    UpdateWindow(form_);
    Pump();
}

void PatchWindow::StopWork()
{
    int max = (int)SendMessageW(bar_, PBM_GETRANGE, FALSE, 0);
    SendMessageW(bar_, PBM_SETPOS, max, 0);
    Pump();
    PatchSteps::Show = nullptr;
    ::ShowWindow(bar_, SW_HIDE);
    working_ = false;
    summaryHeight_ = 40;
    for (Button* b : footerButtons_) EnableWindow(b->Hwnd, TRUE);
    for (HWND h : { folderButton_->Hwnd, server_, list_ }) EnableWindow(h, TRUE);
    EnableWindow(all_, !Locked);
    Busy = false;
    POINT p;
    GetCursorPos(&p);
    SetCursorPos(p.x, p.y);
    InvalidateFooterText();
}

void PatchWindow::Close()
{
    if (form_ != nullptr) SendMessageW(form_, WM_CLOSE, 0, 0);
}

void PatchWindow::Message(const std::wstring& text, const std::wstring& caption, UINT icon)
{
    MessageBoxW(form_, text.c_str(), caption.c_str(), MB_OK | icon);
}

namespace
{
    bool PngEncoder(CLSID* clsid)
    {
        UINT num = 0, size = 0;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0) return false;
        std::vector<unsigned char> buf(size);
        Gdiplus::ImageCodecInfo* codecs = (Gdiplus::ImageCodecInfo*)buf.data();
        Gdiplus::GetImageEncoders(num, size, codecs);
        for (UINT i = 0; i < num; i++)
        {
            if (wcscmp(codecs[i].MimeType, L"image/png") == 0)
            {
                *clsid = codecs[i].Clsid;
                return true;
            }
        }
        return false;
    }
}

void PatchWindow::Snapshot(const std::wstring& file)
{
    RECT b;
    GetWindowRect(form_, &b);
    int w = b.right - b.left, h = b.bottom - b.top;
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    HGDIOBJ old = SelectObject(mem, bmp);
    // The window drawn into the bitmap by itself and its controls, frame
    // included - what Form.DrawToBitmap of the C# patch did, so snapshots of
    // the two compare. (The frame comes out in the plain style Windows
    // prints it in, not as the desktop composes it.)
    PrintWindow(form_, mem, 0);
    SelectObject(mem, old);
    {
        Gdiplus::Bitmap image(bmp, nullptr);
        CLSID png;
        if (PngEncoder(&png)) image.Save(file.c_str(), &png, nullptr);
    }
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
}

void PatchWindow::ShowWindow()
{
    OptStr snapshot = SnapshotPath();
    if (ps::IsTrue(snapshot))
    {
        SetWindowPos(form_, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        ::ShowWindow(form_, SW_SHOW);
        SetForegroundWindow(form_);
        SetFocus(list_);
        Shown = true;
        UpdateWindow(form_);
        Pump();
        Sleep(400);
        Pump();
        Snapshot(*snapshot);
        DestroyWindow(form_);
        Pump();
        return;
    }
    ::ShowWindow(form_, SW_SHOW);
    SetFocus(list_);
    UpdateWindow(form_);
    Shown = true;
    MSG m;
    while (form_ != nullptr && GetMessageW(&m, nullptr, 0, 0) > 0)
    {
        if (!IsDialogMessageW(form_, &m))
        {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
}
