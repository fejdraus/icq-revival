// See PatchIcon.h.

#include "PatchIcon.h"

#include <algorithm>
using std::max;
using std::min;
#include <objidl.h>
#include <gdiplus.h>

#include <cmath>

namespace PatchIcon
{
    COLORREF ColorOf(const std::wstring& hex)
    {
        unsigned int v = wcstoul(hex.c_str() + (hex.empty() || hex[0] != L'#' ? 0 : 1), nullptr, 16);
        return RGB((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
    }

    namespace
    {
        Gdiplus::Color GdipColor(const std::wstring& hex, BYTE alpha = 255)
        {
            COLORREF c = ColorOf(hex);
            return Gdiplus::Color(alpha, GetRValue(c), GetGValue(c), GetBValue(c));
        }

        int CALLBACK FoundFace(const LOGFONTW*, const TEXTMETRICW*, DWORD, LPARAM found)
        {
            *(bool*)found = true;
            return 0;
        }
    }

    std::wstring Face(const std::wstring& wanted)
    {
        LOGFONTW lf = {};
        lf.lfCharSet = DEFAULT_CHARSET;
        wcsncpy_s(lf.lfFaceName, wanted.c_str(), _TRUNCATE);
        bool found = false;
        HDC dc = GetDC(nullptr);
        EnumFontFamiliesExW(dc, &lf, FoundFace, (LPARAM)&found, 0);
        ReleaseDC(nullptr, dc);
        return found ? wanted : L"Tahoma";
    }

    Gdiplus::Bitmap* Draw(int size, const std::wstring& badge, const std::wstring& top, const std::wstring& bottom)
    {
        using namespace Gdiplus;
        Bitmap* bmp = new Bitmap(size, size, PixelFormat32bppARGB);
        {
            Graphics g(bmp);
            g.SetSmoothingMode(SmoothingModeAntiAlias);
            g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
            g.Clear(Color(0, 0, 0, 0));

            double pad = (std::max)(0.5, size / 32.0);
            double w = size - 2 * pad;
            double r = w * 0.22;
            {
                GraphicsPath tile;
                tile.AddArc((REAL)pad, (REAL)pad, (REAL)(2 * r), (REAL)(2 * r), 180, 90);
                tile.AddArc((REAL)(pad + w - 2 * r), (REAL)pad, (REAL)(2 * r), (REAL)(2 * r), 270, 90);
                tile.AddArc((REAL)(pad + w - 2 * r), (REAL)(pad + w - 2 * r), (REAL)(2 * r), (REAL)(2 * r), 0, 90);
                tile.AddArc((REAL)pad, (REAL)(pad + w - 2 * r), (REAL)(2 * r), (REAL)(2 * r), 90, 90);
                tile.CloseFigure();
                LinearGradientBrush fill(PointF(0, (REAL)pad), PointF(0, (REAL)(size - pad)), GdipColor(top), GdipColor(bottom));
                g.FillPath(&fill, &tile);
            }

            bool withText = size >= 48;
            double cx = size / 2.0;
            double cy = withText ? size * 0.40 : size / 2.0;
            // The sprout of the site's icon (deploy/shared/sprout.svg), in
            // white: drawn in its 64-unit box, around the point (32, 31).
            double k = (withText ? size * 0.50 : size * 0.78) / 44.0;
            auto at = [&](double x, double y) { return PointF((REAL)(cx + (x - 32) * k), (REAL)(cy + (y - 31) * k)); };
            SolidBrush white(Color(250, 255, 255, 255));
            Pen stem(Color(250, 255, 255, 255), (REAL)(4.5 * k));
            stem.SetStartCap(LineCapRound);
            stem.SetEndCap(LineCapRound);
            g.DrawLine(&stem, at(32, 50), at(32, 30));
            g.DrawBezier(&stem, at(18, 51), at(27.3, 47), at(36.7, 47), at(46, 51));
            GraphicsPath leaves;
            leaves.AddBezier(at(32, 33), at(18, 34), at(12, 24), at(13, 15));
            leaves.AddBezier(at(13, 15), at(24, 14), at(32, 20), at(32, 33));
            leaves.CloseFigure();
            leaves.AddBezier(at(32, 29), at(45, 30), at(52, 21), at(51, 11));
            leaves.AddBezier(at(51, 11), at(39, 10), at(32, 17), at(32, 29));
            leaves.CloseFigure();
            g.FillPath(&white, &leaves);

            if (withText)
            {
                double em = size * 0.20;
                if (badge.size() > 3) em = size * 0.165;
                FontFamily family(Face(L"Segoe UI").c_str());
                Font font(&family, (REAL)em, FontStyleBold, UnitPixel);
                StringFormat fmt;
                fmt.SetAlignment(StringAlignmentCenter);
                fmt.SetLineAlignment(StringAlignmentCenter);
                RectF box(0, (REAL)(size * 0.70), (REAL)size, (REAL)(size * 0.24));
                g.DrawString(badge.c_str(), (INT)badge.size(), &font, box, &fmt, &white);
            }
        }
        return bmp;
    }
}
