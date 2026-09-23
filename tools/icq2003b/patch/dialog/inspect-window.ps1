# Опрашивает открытое окно переписки ICQ: какие в нём элементы, чьи они и какие
# у них идентификаторы. Нужно, чтобы понять, откуда берётся полоса Send By,
# раз правка шаблона и кода плагина её не убирает.

Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public class Win {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumProc cb, IntPtr p);
    [DllImport("user32.dll")]
    public static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr p);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int max);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassNameW(IntPtr h, StringBuilder s, int max);
    [DllImport("user32.dll")]
    public static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")]
    public static extern int GetWindowLongW(IntPtr h, int index);
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    public static string Text(IntPtr h) {
        var sb = new StringBuilder(256); GetWindowTextW(h, sb, 256); return sb.ToString();
    }
    public static string Cls(IntPtr h) {
        var sb = new StringBuilder(256); GetClassNameW(h, sb, 256); return sb.ToString();
    }
}
'@

$icq = Get-Process -Name Icq -ErrorAction SilentlyContinue
if (-not $icq) { 'ICQ не запущен'; return }

$targets = New-Object System.Collections.ArrayList
$find = [Win+EnumProc] {
    param($h, $l)
    $procId = 0
    [void][Win]::GetWindowThreadProcessId($h, [ref]$procId)
    if ($procId -eq $icq.Id -and [Win]::Text($h) -like '*Message Session*') { [void]$targets.Add($h) }
    return $true
}
[void][Win]::EnumWindows($find, [IntPtr]::Zero)

if ($targets.Count -eq 0) { 'Окно переписки не найдено - откройте его'; return }

# Вывод изнутри обратного вызова теряется: его вызывает не PowerShell, а сама
# система, и активного конвейера в этот момент нет. Поэтому копим в список.
$rows = New-Object System.Collections.ArrayList

foreach ($top in $targets) {
    [void]$rows.Add(('ОКНО: {0} [{1}]' -f ([Win]::Text($top)), ([Win]::Cls($top))))
    $walk = [Win+EnumProc] {
        param($h, $l)
        $id = [Win]::GetDlgCtrlID($h)
        $cls = [Win]::Cls($h)
        $txt = [Win]::Text($h)
        $vis = [Win]::IsWindowVisible($h)
        $r = New-Object Win+RECT
        [void][Win]::GetWindowRect($h, [ref]$r)
        $style = [Win]::GetWindowLongW($h, -16)
        [void]$rows.Add(('  id={0,-6} {1,-24} vis={2,-5} style=0x{3:X8} {4,3}x{5,-3} "{6}"' -f `
            $id, $cls, $vis, $style, ($r.Right - $r.Left), ($r.Bottom - $r.Top), $txt))
        return $true
    }
    [void][Win]::EnumChildWindows($top, $walk, [IntPtr]::Zero)
}

$rows
