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
            double petalLen = withText ? size * 0.19 : size * 0.25;
            double petalWid = petalLen * 0.72;
            SolidBrush white(Color(250, 255, 255, 255));
            for (int i = 0; i < 8; i++)
            {
                GraphicsState state = g.Save();
                g.TranslateTransform((REAL)cx, (REAL)cy);
                g.RotateTransform((REAL)(45 * i));
                g.FillEllipse(&white, (REAL)(-petalWid / 2), (REAL)(-petalLen * 1.55), (REAL)petalWid, (REAL)(petalLen * 1.1));
                g.Restore(state);
            }
            double heart = petalLen * 0.62;
            SolidBrush heartBrush(GdipColor(bottom));
            g.FillEllipse(&heartBrush, (REAL)(cx - heart / 2), (REAL)(cy - heart / 2), (REAL)heart, (REAL)heart);

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
