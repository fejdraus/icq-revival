// The window every client patch shows - the port of
// tools\patcher\Common\PatchWindow.cs to the plain Win32 API.
//
// Each patch keeps its own logic and only describes its window: title, one
// line about what it does, the badge and colour of its client version, the
// columns of its list. Everything about how that looks lives here, so the
// patches for different clients look like one family.
//
// The WinForms window was panels, labels and controls; here the static parts
// (header, cards, captions, texts) are painted by the window itself and only
// what a person works with is a control of its own: the buttons, the server
// box, the list, "Select all" and the progress bar. The sizes are the ones
// the C# window laid out at 96 DPI, scaled by the DPI of the screen as
// WinForms scales them.

#pragma once

#include "PatchItems.h"
#include "Ps.h"

#include <windows.h>
#include <commctrl.h>

#include <functional>
#include <string>
#include <utility>
#include <vector>

// What a patch reports for a change, as the window shows it: a mark, a
// word, and whether it counts towards "everything is in place".
struct StateView
{
    std::wstring Mark;
    std::wstring Text;
    bool Counts = true;

    static StateView Of(const std::wstring& state);
};

class PatchWindow
{
public:
    // Columns: { "Change", 360 }, { "Where", 200 }; a State column is added last.
    PatchWindow(const std::wstring& title, const std::wstring& subtitle, const std::wstring& badge,
                const std::wstring& accentTop, const std::wstring& accentBottom, const std::wstring& clientName,
                const std::wstring& serverHint, const std::vector<std::pair<std::wstring, int>>& columns);
    ~PatchWindow();
    PatchWindow(const PatchWindow&) = delete;
    PatchWindow& operator=(const PatchWindow&) = delete;

    // Common controls, GDI+ and COM, before the first window.
    static void Init();

    double Scale = 1;
    COLORREF Accent = 0;
    std::vector<StateView> Rows;
    // What the user took the tick off, by key: kept across refills of the
    // list, so a re-check does not undo a choice not applied yet.
    ps::StringSet Unchecked;
    bool Filling = false, Syncing = false, Locked = false, Shown = false, Busy = false;

    // FolderButton.Click and Server.Leave of the C# window.
    std::function<void()> OnFolderButton;
    std::function<void()> OnServerLeave;

    HWND Handle() const { return form_; }
    std::wstring ServerText() const;
    void SetServerText(const std::wstring& text);

    // Buttons are laid out from the right, in the order they are added.
    void AddButton(const std::wstring& text, std::function<void()> action, bool primary = false);

    void SetFolder(const OptStr& path);
    void ClearList();
    // Gives the id of the group, for AddRow.
    int AddGroup(const std::wstring& name);
    // cells fills the columns before State; the tooltip shows the whole
    // first one. key names the row for the selection.
    void AddRow(int group, const std::vector<std::wstring>& cells, const std::wstring& state, const std::wstring& key);
    // Ends a refill of the list and sums it up in the bottom bar.
    void CompleteList();
    // Whether a row is to be applied: the selection a patch acts on.
    bool IsSelected(const std::wstring& key) const;

    // The cleared rows are remembered between runs, under the patch's own
    // key in HKCU, with every row the window showed then. A job that is off
    // until chosen (defaultOff) starts cleared the first time it is seen.
    void ReadUnchecked(const std::wstring& settingsKey, const std::vector<std::wstring>& defaultOff);
    void SaveUnchecked(const std::wstring& settingsKey);

    // Apply and Restore run on the window's own thread: the bar is moved
    // and the window repainted at each step, with everything that could
    // start another run held still meanwhile.
    void StartWork(const std::wstring& text);
    void StopWork();

    // Form.Close: refused while Busy.
    void Close();

    // Shows the window until it is closed - or, with ICQ_PATCH_SNAPSHOT
    // set, draws it into that PNG file and closes it again.
    void ShowWindow();

    // MessageBox.Show with the window as its owner.
    void Message(const std::wstring& text, const std::wstring& caption, UINT icon);

    // The environment variable that turns ShowWindow into a snapshot: for
    // checking the layout without a person at the screen, the window is
    // drawn into this PNG file and closed again.
    static const wchar_t* SnapshotVariable;
    static OptStr SnapshotPath();

private:
    struct Button
    {
        HWND Hwnd = nullptr;
        std::wstring Text;
        bool Primary = false;
        bool Hover = false;
        int Width = 0;  // at 96 DPI, as WinForms had it before scaling
        int Right = 0;  // distance of its right edge from the right of its panel, at 96 DPI
        int Id = 0;
        std::function<void()> Action;
    };

    struct Row
    {
        std::wstring Key;
        std::wstring Tip;
        std::vector<COLORREF> Colors;
    };

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    static LRESULT CALLBACK ButtonProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    static LRESULT CALLBACK EditProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    LRESULT Handle(UINT msg, WPARAM wp, LPARAM lp);

    int S(double v) const;
    HFONT MakeFont(const std::wstring& face, double points, int weight, bool forControl) const;
    Button* NewButton(const std::wstring& text, bool primary, int id);
    int MeasureWidth(const std::wstring& text, HFONT font) const;
    void Layout();
    void Paint(HDC dc, const RECT& clip);
    // Text as TextRenderer draws it. A label places middle and bottom text
    // its own way (labelAlign); a button leaves it to Windows.
    void DrawLabel(HDC dc, const std::wstring& text, const RECT& r, HFONT font, COLORREF color, UINT flags,
                   bool labelAlign = true) const;
    void DrawButton(const DRAWITEMSTRUCT* d);
    LRESULT CustomDraw(NMLVCUSTOMDRAW* cd);
    LRESULT CustomDrawAll(NMCUSTOMDRAW* cd);
    int AllTextLeft() const;
    void UpdateChecks(int index);
    void SwitchAll();
    void UpdateSummary();
    bool Ticked(int index) const;
    int ItemCount() const;
    void SetSummary(const std::wstring& text, COLORREF color);
    void InvalidateFooterText();
    void Pump();
    void Snapshot(const std::wstring& file);

    HWND form_ = nullptr;
    HWND server_ = nullptr;
    HWND list_ = nullptr;
    HWND all_ = nullptr;
    HWND bar_ = nullptr;
    WNDPROC buttonProc_ = nullptr;
    WNDPROC editProc_ = nullptr;
    Button* folderButton_ = nullptr;
    std::vector<Button*> footerButtons_;
    int buttonsRight_ = 0;
    int defaultButton_ = 0;

    std::wstring title_, subtitle_, badge_, accentTop_, accentBottom_, captionFolder_, captionServer_, hint_;
    std::wstring pathText_;
    COLORREF pathColor_ = 0;
    std::wstring picked_;
    std::wstring summary_;
    COLORREF summaryColor_ = 0;
    bool working_ = false;
    int summaryHeight_ = 0;  // in pixels; S(40) until the first run
    int summaryWidth_ = 300;  // at 96 DPI

    std::vector<Row> rows_;
    int nextGroup_ = 1;
    HWND lastFocus_ = nullptr;

    HFONT formFont_ = nullptr, formFontControl_ = nullptr, boldFont_ = nullptr, titleFont_ = nullptr,
          captionFont_ = nullptr, pathFont_ = nullptr, serverFont_ = nullptr, allFont_ = nullptr, summaryFont_ = nullptr;
    HBRUSH cardBrush_ = nullptr;
    HICON bigIcon_ = nullptr, smallIcon_ = nullptr;
    void* headerIcon_ = nullptr;  // Gdiplus::Bitmap
    int serverHeight_ = 0;
    int allWidth_ = 0, allHeight_ = 0;
};
