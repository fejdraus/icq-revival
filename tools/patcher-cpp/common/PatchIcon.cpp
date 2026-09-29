// See PatchIcon.h.

#include "PatchIcon.h"

#include <algorithm>
using std::max;
using std::min;
#include <objidl.h>
#include <gdiplus.h>

#include <cmath>
#include <cstring>

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

    namespace
    {
        // The flower of the ICQ Revival logo, 256 pixels square on a
        // transparent ground: tools\patcher\Common\flower.png, which the exe
        // carries as the RCDATA resource FLOWER (app.rc). Loaded once and kept
        // for the life of the process; nullptr when it could not be read.
        Gdiplus::Bitmap* Flower()
        {
            using namespace Gdiplus;
            static Bitmap* flower = nullptr;
            static bool tried = false;
            if (tried) return flower;
            tried = true;

            HMODULE self = GetModuleHandleW(nullptr);
            HRSRC r = FindResourceW(self, L"FLOWER", MAKEINTRESOURCEW(10));  // RT_RCDATA
            if (r == nullptr) return nullptr;
            DWORD size = SizeofResource(self, r);
            const void* data = LockResource(LoadResource(self, r));
            if (data == nullptr || size == 0) return nullptr;

            // GDI+ reads a PNG from a stream; the one over a copy in global
            // memory is there on every Windows the exe runs on, XP included.
            HGLOBAL copy = GlobalAlloc(GMEM_MOVEABLE, size);
            if (copy == nullptr) return nullptr;
            void* to = GlobalLock(copy);
            memcpy(to, data, size);
            GlobalUnlock(copy);
            IStream* stream = nullptr;
            if (FAILED(CreateStreamOnHGlobal(copy, TRUE, &stream)))
            {
                GlobalFree(copy);
                return nullptr;
            }
            Bitmap* png = Bitmap::FromStream(stream);
            if (png != nullptr && png->GetLastStatus() == Ok)
            {
                // A copy, so that the stream may be let go.
                Bitmap* own = new Bitmap((INT)png->GetWidth(), (INT)png->GetHeight(), PixelFormat32bppARGB);
                {
                    Graphics g(own);
                    g.SetCompositingMode(CompositingModeSourceCopy);
                    g.DrawImage(png, 0, 0, (INT)png->GetWidth(), (INT)png->GetHeight());
                }
                flower = own;
            }
            delete png;
            stream->Release();
            return flower;
        }

        // A rectangle with fully rounded ends.
        void Pill(Gdiplus::GraphicsPath& path, double x, double y, double w, double h)
        {
            using Gdiplus::REAL;
            path.AddArc((REAL)x, (REAL)y, (REAL)h, (REAL)h, 90, 180);
            path.AddArc((REAL)(x + w - h), (REAL)y, (REAL)h, (REAL)h, 270, 180);
            path.CloseFigure();
        }
    }

    Gdiplus::Bitmap* Draw(int size, const std::wstring& badge, const std::wstring& top, const std::wstring& bottom)
    {
        using namespace Gdiplus;
        Bitmap* bmp = new Bitmap(size, size, PixelFormat32bppARGB);
        {
            Graphics g(bmp);
            g.SetSmoothingMode(SmoothingModeAntiAlias);
            g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
            g.SetInterpolationMode(InterpolationModeHighQualityBicubic);
            g.SetPixelOffsetMode(PixelOffsetModeHighQuality);
            g.SetCompositingQuality(CompositingQualityHighQuality);
            g.Clear(Color(0, 0, 0, 0));

            double pad = (std::max)(0.5, size / 32.0);
            bool withText = size >= 48;
            double side = withText ? size * 0.80 : size - 2 * pad;
            double fx = (size - side) / 2;
            double fy = withText ? pad : (size - side) / 2;
            if (Bitmap* f = Flower())
            {
                // No half-transparent seam where the edge pixels are sampled.
                ImageAttributes attrs;
                attrs.SetWrapMode(WrapModeTileFlipXY);
                g.DrawImage(f, RectF((REAL)fx, (REAL)fy, (REAL)side, (REAL)side),
                    0, 0, (REAL)f->GetWidth(), (REAL)f->GetHeight(), UnitPixel, &attrs);
            }

            if (withText)
            {
                // The pill: the dark outline and the white rim of the logo's
                // shapes around the colour of the client version. Under 64
                // pixels there is no room for the rim.
                double h = size * 0.32;
                double y = size - pad - h;
                double maxW = size - 2 * pad;
                double line = (std::max)(1.0, size / 40.0);
                int rings = size >= 64 ? 2 : 1;
                double inset = rings * line;
                // The digits stand about 0.7 em tall: 0.6 of the inside.
                double em = (h - 2 * inset) * 0.85;

                StringFormat* fmt = StringFormat::GenericTypographic()->Clone();
                fmt->SetAlignment(StringAlignmentCenter);
                fmt->SetLineAlignment(StringAlignmentNear);
                fmt->SetFormatFlags(fmt->GetFormatFlags() | StringFormatFlagsNoWrap);
                FontFamily family(Face(L"Segoe UI").c_str());
                double textW;
                {
                    Font probe(&family, (REAL)em, FontStyleBold, UnitPixel);
                    RectF bounds;
                    g.MeasureString(badge.c_str(), (INT)badge.size(), &probe, PointF(0, 0), fmt, &bounds);
                    textW = bounds.Width;
                }
                double room = maxW - h * 0.7;
                if (textW > room)
                {
                    em *= room / textW;
                    textW = room;
                }
                double w = (std::min)(maxW, (std::max)(h * 1.8, textW + h * 0.7));
                double x = (size - w) / 2;

                GraphicsPath outer, rim, inner;
                Pill(outer, x, y, w, h);
                Pill(rim, x + line, y + line, w - 2 * line, h - 2 * line);
                Pill(inner, x + inset, y + inset, w - 2 * inset, h - 2 * inset);
                SolidBrush dark(Color(255, 2, 33, 25));
                SolidBrush white(Color(255, 255, 255, 255));
                LinearGradientBrush fill(PointF(0, (REAL)(y + inset - 1)), PointF(0, (REAL)(y + h - inset + 1)), GdipColor(top), GdipColor(bottom));
                g.FillPath(&dark, &outer);
                if (rings > 1) g.FillPath(&white, &rim);
                g.FillPath(&fill, &inner);

                // The line is laid out from the top of its ascent; the digits
                // are centred by their own height.
                Font font(&family, (REAL)em, FontStyleBold, UnitPixel);
                double ascent = em * family.GetCellAscent(FontStyleBold) / family.GetEmHeight(FontStyleBold);
                double baseline = y + h / 2 + em * 0.70 / 2;
                RectF box((REAL)x, (REAL)(baseline - ascent), (REAL)w, (REAL)h);
                g.DrawString(badge.c_str(), (INT)badge.size(), &font, box, fmt, &white);
                delete fmt;
            }
        }
        return bmp;
    }
}
