# The window every client patch shows, and the icon it carries.
#
# Each patch keeps its own logic and only describes its window: title, one
# line about what it does, the badge and colour of its client version, the
# columns of its list. Everything about how that looks lives here, so the
# patches for different clients look like one family.
#
# A patch pulls this file in with
#
#   #_if PSScript
#   . (Join-Path $PSScriptRoot '..\..\common\PatchWindow.ps1')
#   #_else
#   #_include "$PSScriptRoot/../../common/PatchWindow.ps1"
#   #_endif
#
# so that it works run as a script and compiled with ps12exe alike: ps12exe
# copies the file into the exe, which then needs nothing next to it.
#
# The icon is drawn, not stored: New-PatchIconFile writes the same picture
# the window shows into an .ico for ps12exe (tools\common\Build-Patches.ps1).

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# --- icon ----------------------------------------------------------------------

function ConvertTo-PatchColor([string]$hex) { return [Drawing.ColorTranslator]::FromHtml($hex) }

# A flower of eight petals on a rounded tile in the colour of the client
# version. From 48 pixels up the version is written under the flower, so the
# exe of each patch can be told apart at a glance in Explorer.
function New-PatchIconBitmap([int]$size, [string]$badge, [string]$top, [string]$bottom) {
    $bmp = New-Object Drawing.Bitmap($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.TextRenderingHint = 'AntiAliasGridFit'
    $g.Clear([Drawing.Color]::Transparent)

    $pad = [Math]::Max(0.5, $size / 32.0)
    $w = $size - 2 * $pad
    $r = $w * 0.22
    $tile = New-Object Drawing.Drawing2D.GraphicsPath
    $tile.AddArc($pad, $pad, 2 * $r, 2 * $r, 180, 90)
    $tile.AddArc($pad + $w - 2 * $r, $pad, 2 * $r, 2 * $r, 270, 90)
    $tile.AddArc($pad + $w - 2 * $r, $pad + $w - 2 * $r, 2 * $r, 2 * $r, 0, 90)
    $tile.AddArc($pad, $pad + $w - 2 * $r, 2 * $r, 2 * $r, 90, 90)
    $tile.CloseFigure()
    $fill = New-Object Drawing.Drawing2D.LinearGradientBrush(
        (New-Object Drawing.PointF(0, $pad)), (New-Object Drawing.PointF(0, ($size - $pad))),
        (ConvertTo-PatchColor $top), (ConvertTo-PatchColor $bottom))
    $g.FillPath($fill, $tile)

    $withText = $size -ge 48
    $cx = $size / 2.0
    $cy = if ($withText) { $size * 0.40 } else { $size / 2.0 }
    $petalLen = if ($withText) { $size * 0.19 } else { $size * 0.25 }
    $petalWid = $petalLen * 0.72
    $white = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(250, 255, 255, 255))
    for ($i = 0; $i -lt 8; $i++) {
        $state = $g.Save()
        $g.TranslateTransform($cx, $cy)
        $g.RotateTransform(45 * $i)
        $g.FillEllipse($white, - $petalWid / 2, - $petalLen * 1.55, $petalWid, $petalLen * 1.1)
        $g.Restore($state)
    }
    $heart = $petalLen * 0.62
    $g.FillEllipse((New-Object Drawing.SolidBrush((ConvertTo-PatchColor $bottom))), $cx - $heart / 2, $cy - $heart / 2, $heart, $heart)

    if ($withText) {
        $em = $size * 0.20
        if ($badge.Length -gt 3) { $em = $size * 0.165 }
        $font = New-Object Drawing.Font('Segoe UI', [single]$em, [Drawing.FontStyle]::Bold, [Drawing.GraphicsUnit]::Pixel)
        $fmt = New-Object Drawing.StringFormat
        $fmt.Alignment = 'Center'
        $fmt.LineAlignment = 'Center'
        $box = New-Object Drawing.RectangleF(0, ($size * 0.70), $size, ($size * 0.24))
        $g.DrawString($badge, $font, $white, $box, $fmt)
    }
    $g.Dispose()
    return $bmp
}

# An .ico with one frame per size: 32-bit bitmaps for the small ones, which
# every part of Windows reads, and PNG for 256.
function New-PatchIconBytes([string]$badge, [string]$top, [string]$bottom) {
    $sizes = 16, 20, 24, 32, 40, 48, 64, 256
    $frames = foreach ($s in $sizes) {
        $bmp = New-PatchIconBitmap $s $badge $top $bottom
        if ($s -ge 256) {
            $ms = New-Object IO.MemoryStream
            $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
            , $ms.ToArray()
        } else {
            $rect = New-Object Drawing.Rectangle(0, 0, $s, $s)
            $data = $bmp.LockBits($rect, 'ReadOnly', [Drawing.Imaging.PixelFormat]::Format32bppArgb)
            $pixels = New-Object byte[] ($s * $s * 4)
            [Runtime.InteropServices.Marshal]::Copy($data.Scan0, $pixels, 0, $pixels.Length)
            $bmp.UnlockBits($data)
            $maskRow = [int]([Math]::Floor(($s + 31) / 32) * 4)
            $ms = New-Object IO.MemoryStream
            $bw = New-Object IO.BinaryWriter($ms)
            $bw.Write([uint32]40); $bw.Write([int32]$s); $bw.Write([int32](2 * $s))
            $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]0)
            $bw.Write([uint32]($pixels.Length + $maskRow * $s))
            $bw.Write([int32]0); $bw.Write([int32]0); $bw.Write([uint32]0); $bw.Write([uint32]0)
            for ($y = $s - 1; $y -ge 0; $y--) { $bw.Write($pixels, $y * $s * 4, $s * 4) }
            $bw.Write((New-Object byte[] ($maskRow * $s)))
            $bw.Flush()
            , $ms.ToArray()
        }
        $bmp.Dispose()
    }
    $ms = New-Object IO.MemoryStream
    $bw = New-Object IO.BinaryWriter($ms)
    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
        $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([uint16]1); $bw.Write([uint16]32)
        $bw.Write([uint32]$frames[$i].Length); $bw.Write([uint32]$offset)
        $offset += $frames[$i].Length
    }
    foreach ($f in $frames) { $bw.Write($f) }
    $bw.Flush()
    return $ms.ToArray()
}

function New-PatchIconFile([string]$path, [string]$badge, [string]$top, [string]$bottom) {
    [IO.File]::WriteAllBytes($path, (New-PatchIconBytes $badge $top $bottom))
}

# --- states --------------------------------------------------------------------

# What a patch reports for a change, as the window shows it: a mark, a word,
# and whether it counts towards "everything is in place".
$PatchStates = @{
    'patched'        = @{ Mark = 'done';  Text = 'Applied';        Counts = $true }
    'original'       = @{ Mark = 'todo';  Text = 'Not applied';    Counts = $true }
    'another server' = @{ Mark = 'todo';  Text = 'Other server';   Counts = $true }
    'no links'       = @{ Mark = 'none';  Text = 'Nothing to do';  Counts = $false }
    'missing'        = @{ Mark = 'none';  Text = 'Not in client';  Counts = $false }
    'no folder'      = @{ Mark = 'none';  Text = '-';              Counts = $false }
    'other version'  = @{ Mark = 'warn';  Text = 'Other version';  Counts = $true }
    'unknown'        = @{ Mark = 'warn';  Text = 'Unknown';        Counts = $true }
}

function Get-PatchStateView([string]$state) {
    if ($PatchStates.ContainsKey($state)) { return $PatchStates[$state] }
    return @{ Mark = 'warn'; Text = $state; Counts = $true }
}

function New-PatchMark([int]$size, [string]$kind) {
    $bmp = New-Object Drawing.Bitmap($size, $size)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([Drawing.Color]::Transparent)
    $d = $size * 0.78
    $o = ($size - $d) / 2
    $pw = [single]([Math]::Max(1.2, $size / 9.0))
    switch ($kind) {
        'done' {
            $g.FillEllipse((New-Object Drawing.SolidBrush((ConvertTo-PatchColor '#2E9E5B'))), $o, $o, $d, $d)
            $pen = New-Object Drawing.Pen([Drawing.Color]::White, $pw)
            $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
            $pts = [Drawing.PointF[]]@(
                (New-Object Drawing.PointF(($size * 0.31), ($size * 0.52))),
                (New-Object Drawing.PointF(($size * 0.45), ($size * 0.65))),
                (New-Object Drawing.PointF(($size * 0.70), ($size * 0.37))))
            $g.DrawLines($pen, $pts)
        }
        'todo' {
            $pen = New-Object Drawing.Pen((ConvertTo-PatchColor '#9AA3AD'), $pw)
            $g.DrawEllipse($pen, $o + $pw / 2, $o + $pw / 2, $d - $pw, $d - $pw)
        }
        'warn' {
            $g.FillEllipse((New-Object Drawing.SolidBrush((ConvertTo-PatchColor '#D9822B'))), $o, $o, $d, $d)
            $pen = New-Object Drawing.Pen([Drawing.Color]::White, $pw)
            $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
            $g.DrawLine($pen, $size / 2, $size * 0.30, $size / 2, $size * 0.54)
            $dot = $pw * 1.1
            $g.FillEllipse([Drawing.Brushes]::White, $size / 2 - $dot / 2, $size * 0.64, $dot, $dot)
        }
        default {
            $pen = New-Object Drawing.Pen((ConvertTo-PatchColor '#C5CBD1'), $pw)
            $g.DrawLine($pen, $size * 0.30, $size / 2, $size * 0.70, $size / 2)
        }
    }
    $g.Dispose()
    return $bmp
}

# --- window --------------------------------------------------------------------

try { [Windows.Forms.Application]::EnableVisualStyles() } catch { }

function New-PatchButton([string]$text, [bool]$primary, $ui) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text
    $b.FlatStyle = 'Flat'
    $b.Cursor = [Windows.Forms.Cursors]::Hand
    $b.Height = 32
    $b.Width = [Math]::Max(96, [Windows.Forms.TextRenderer]::MeasureText($text, $ui.Form.Font).Width + 36)
    $b.UseVisualStyleBackColor = $false
    if ($primary) {
        $b.BackColor = $ui.Accent
        $b.ForeColor = [Drawing.Color]::White
        $b.Font = New-Object Drawing.Font($ui.Form.Font, [Drawing.FontStyle]::Bold)
        $b.FlatAppearance.BorderColor = $ui.Accent
        $b.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(255,
            [int]($ui.Accent.R * 0.88), [int]($ui.Accent.G * 0.88), [int]($ui.Accent.B * 0.88))
    } else {
        $b.BackColor = [Drawing.Color]::White
        $b.ForeColor = ConvertTo-PatchColor '#1F2933'
        $b.FlatAppearance.BorderColor = ConvertTo-PatchColor '#C3CAD2'
        $b.FlatAppearance.MouseOverBackColor = ConvertTo-PatchColor '#EEF1F4'
    }
    return $b
}

# Columns: @(@('Change', 360), @('Where', 200)); a State column is added last.
function New-PatchWindow {
    param(
        [string]$Title, [string]$Subtitle, [string]$Badge,
        [string]$AccentTop, [string]$AccentBottom,
        [string]$ClientName, [string]$ServerHint, [object[]]$Columns
    )
    $g = [Drawing.Graphics]::FromHwnd([IntPtr]::Zero)
    $scale = $g.DpiX / 96.0
    $g.Dispose()

    $ui = @{ Scale = $scale; Accent = (ConvertTo-PatchColor $AccentBottom); Rows = New-Object System.Collections.ArrayList }
    $ink = ConvertTo-PatchColor '#1F2933'
    $dim = ConvertTo-PatchColor '#5F6B7A'

    $form = New-Object Windows.Forms.Form
    $ui.Form = $form
    $form.SuspendLayout()
    $form.AutoScaleDimensions = New-Object Drawing.SizeF(96, 96)
    $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object Drawing.Font('Segoe UI', 9)
    $form.Text = $Title
    $form.ClientSize = New-Object Drawing.Size(800, 620)
    $form.MinimumSize = New-Object Drawing.Size(640, 480)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [Drawing.Color]::White
    $form.ForeColor = $ink
    $iconStream = New-Object IO.MemoryStream(, (New-PatchIconBytes $Badge $AccentTop $AccentBottom))
    $form.Icon = New-Object Drawing.Icon($iconStream)

    # header: the icon, the name of the patch and what it does
    $header = New-Object Windows.Forms.Panel
    # Sized like the window before anything is anchored to its right edge.
    $header.Width = 800
    $header.Dock = 'Top'
    $header.Height = 92
    $header.BackColor = ConvertTo-PatchColor '#F6F8F7'
    $pic = New-Object Windows.Forms.PictureBox
    $pic.Location = New-Object Drawing.Point(20, 18)
    $pic.Size = New-Object Drawing.Size(56, 56)
    $pic.SizeMode = 'Zoom'
    $pic.Image = New-PatchIconBitmap ([int](56 * $scale)) $Badge $AccentTop $AccentBottom
    $header.Controls.Add($pic)
    $titleLabel = New-Object Windows.Forms.Label
    $titleLabel.Text = $Title
    $titleLabel.Font = New-Object Drawing.Font('Segoe UI Semibold', 15)
    $titleLabel.AutoSize = $true
    $titleLabel.Location = New-Object Drawing.Point(88, 14)
    $header.Controls.Add($titleLabel)
    $sub = New-Object Windows.Forms.Label
    $sub.Text = $Subtitle
    $sub.ForeColor = $dim
    $sub.Location = New-Object Drawing.Point(90, 46)
    $sub.Size = New-Object Drawing.Size(690, 40)
    $sub.Anchor = 'Top, Left, Right'
    $header.Controls.Add($sub)

    $accent = New-Object Windows.Forms.Panel
    $accent.Dock = 'Top'
    $accent.Height = 3
    $accent.BackColor = $ui.Accent

    # the client folder and the server
    $settings = New-Object Windows.Forms.Panel
    $settings.Width = 800
    $settings.Dock = 'Top'
    $settings.Height = 128
    $capFont = New-Object Drawing.Font('Segoe UI', 8, [Drawing.FontStyle]::Bold)

    $capFolder = New-Object Windows.Forms.Label
    $capFolder.Text = ($ClientName + ' folder').ToUpper()
    $capFolder.Font = $capFont
    $capFolder.ForeColor = $dim
    $capFolder.AutoSize = $true
    $capFolder.Location = New-Object Drawing.Point(20, 14)
    $settings.Controls.Add($capFolder)
    $ui.Path = New-Object Windows.Forms.Label
    $ui.Path.Location = New-Object Drawing.Point(20, 34)
    $ui.Path.Size = New-Object Drawing.Size(620, 22)
    $ui.Path.Anchor = 'Top, Left, Right'
    $ui.Path.AutoEllipsis = $true
    $ui.Path.Font = New-Object Drawing.Font('Segoe UI', 9.5)
    $settings.Controls.Add($ui.Path)
    $ui.FolderButton = New-PatchButton 'Change folder...' $false $ui
    $ui.FolderButton.Location = New-Object Drawing.Point((780 - $ui.FolderButton.Width), 28)
    $ui.FolderButton.Anchor = 'Top, Right'
    $settings.Controls.Add($ui.FolderButton)

    $capServer = New-Object Windows.Forms.Label
    $capServer.Text = 'SERVER DOMAIN'
    $capServer.Font = $capFont
    $capServer.ForeColor = $dim
    $capServer.AutoSize = $true
    $capServer.Location = New-Object Drawing.Point(20, 68)
    $settings.Controls.Add($capServer)
    $ui.Server = New-Object Windows.Forms.TextBox
    $ui.Server.Font = New-Object Drawing.Font('Segoe UI', 10.5)
    $ui.Server.Location = New-Object Drawing.Point(20, 88)
    $ui.Server.Width = 300
    $settings.Controls.Add($ui.Server)
    $hint = New-Object Windows.Forms.Label
    $hint.Text = $ServerHint
    $hint.ForeColor = $dim
    $hint.Location = New-Object Drawing.Point(336, 84)
    $hint.Size = New-Object Drawing.Size(444, 40)
    $hint.Anchor = 'Top, Left, Right'
    $settings.Controls.Add($hint)

    # the list of changes
    $content = New-Object Windows.Forms.Panel
    $content.Width = 800
    $content.Dock = 'Fill'
    $content.Padding = New-Object Windows.Forms.Padding(20, 4, 20, 12)
    $list = New-Object Windows.Forms.ListView
    $ui.List = $list
    $list.Dock = 'Fill'
    $list.View = 'Details'
    $list.FullRowSelect = $true
    $list.HeaderStyle = 'Nonclickable'
    $list.ShowItemToolTips = $true
    $list.BorderStyle = 'FixedSingle'
    $marks = New-Object Windows.Forms.ImageList
    $marks.ColorDepth = 'Depth32Bit'
    $m = [int](18 * $scale)
    $marks.ImageSize = New-Object Drawing.Size($m, $m)
    foreach ($k in 'done', 'todo', 'warn', 'none') { $marks.Images.Add($k, (New-PatchMark $m $k)) }
    $list.SmallImageList = $marks
    foreach ($c in $Columns) { [void]$list.Columns.Add($c[0], [int]($c[1] * $scale)) }
    [void]$list.Columns.Add('State', [int](110 * $scale))
    $content.Controls.Add($list)

    # the bottom bar: how far along it is, and the buttons
    $footer = New-Object Windows.Forms.Panel
    $footer.Width = 800
    $footer.Dock = 'Bottom'
    $footer.Height = 60
    $footer.BackColor = ConvertTo-PatchColor '#F6F8F7'
    $line = New-Object Windows.Forms.Panel
    $line.Dock = 'Top'
    $line.Height = 1
    $line.BackColor = ConvertTo-PatchColor '#E1E6E3'
    $footer.Controls.Add($line)
    $ui.Summary = New-Object Windows.Forms.Label
    $ui.Summary.Location = New-Object Drawing.Point(20, 12)
    $ui.Summary.Size = New-Object Drawing.Size(300, 38)
    $ui.Summary.TextAlign = 'MiddleLeft'
    $ui.Summary.Font = New-Object Drawing.Font('Segoe UI Semibold', 9.5)
    $footer.Controls.Add($ui.Summary)
    $ui.Footer = $footer
    $ui.ButtonsRight = 780

    # Docking goes from the last control added to the first.
    $form.Controls.Add($content)
    $form.Controls.Add($footer)
    $form.Controls.Add($settings)
    $form.Controls.Add($accent)
    $form.Controls.Add($header)
    return $ui
}

# Buttons are laid out from the right, in the order they are added.
function Add-PatchButton($ui, [string]$text, [scriptblock]$action, [switch]$Primary) {
    $b = New-PatchButton $text $Primary.IsPresent $ui
    $ui.ButtonsRight -= $b.Width
    $b.Location = New-Object Drawing.Point($ui.ButtonsRight, 14)
    $b.Anchor = 'Top, Right'
    $b.Add_Click($action)
    $ui.Footer.Controls.Add($b)
    $ui.ButtonsRight -= 8
    if ($Primary) { $ui.Form.AcceptButton = $b }
    return $b
}

function Set-PatchFolder($ui, [string]$path) {
    if ($path) {
        $ui.Path.Text = $path
        $ui.Path.ForeColor = ConvertTo-PatchColor '#1F2933'
    } else {
        $ui.Path.Text = 'Not found - use "Change folder..." to pick it'
        $ui.Path.ForeColor = ConvertTo-PatchColor '#C0392B'
    }
}

function Clear-PatchList($ui) {
    $ui.List.BeginUpdate()
    $ui.List.Items.Clear()
    $ui.List.Groups.Clear()
    $ui.Rows.Clear()
}

function Add-PatchGroup($ui, [string]$name) {
    $grp = New-Object Windows.Forms.ListViewGroup($name)
    [void]$ui.List.Groups.Add($grp)
    return $grp
}

# $cells fills the columns before State; the tooltip shows the whole first one.
function Add-PatchRow($ui, $group, [string[]]$cells, [string]$state) {
    $view = Get-PatchStateView $state
    $text = $cells[0]
    if ($text) { $text = $text.Substring(0, 1).ToUpper() + $text.Substring(1) }
    $item = New-Object Windows.Forms.ListViewItem($text, $view.Mark)
    $item.Group = $group
    $item.ToolTipText = $text
    $item.UseItemStyleForSubItems = $false
    for ($i = 1; $i -lt $cells.Count; $i++) {
        $s = $item.SubItems.Add($cells[$i])
        $s.ForeColor = ConvertTo-PatchColor '#5F6B7A'
    }
    $s = $item.SubItems.Add($view.Text)
    $s.ForeColor = switch ($view.Mark) {
        'done' { ConvertTo-PatchColor '#23804A' }
        'warn' { ConvertTo-PatchColor '#B8641A' }
        'todo' { ConvertTo-PatchColor '#1F2933' }
        default { ConvertTo-PatchColor '#8A949E' }
    }
    [void]$ui.List.Items.Add($item)
    [void]$ui.Rows.Add($view)
}

# Ends a refill of the list and sums it up in the bottom bar.
function Complete-PatchList($ui) {
    $ui.List.EndUpdate()
    $counted = @($ui.Rows | Where-Object { $_.Counts })
    $done = @($counted | Where-Object { $_.Mark -eq 'done' }).Count
    $warn = @($counted | Where-Object { $_.Mark -eq 'warn' }).Count
    if ($counted.Count -eq 0) {
        $ui.Summary.Text = ''
    } elseif ($warn -gt 0) {
        $ui.Summary.Text = "$warn item(s) do not match this client version"
        $ui.Summary.ForeColor = ConvertTo-PatchColor '#B8641A'
    } elseif ($done -eq $counted.Count) {
        $ui.Summary.Text = "All $done changes are in place"
        $ui.Summary.ForeColor = ConvertTo-PatchColor '#23804A'
    } else {
        $ui.Summary.Text = "$done of $($counted.Count) changes in place"
        $ui.Summary.ForeColor = ConvertTo-PatchColor '#1F2933'
    }
}

function Show-PatchWindow($ui) {
    $ui.Form.ResumeLayout()
    # For checking the layout without a person at the screen: the window is
    # drawn into this file and closed again.
    if ($env:ICQ_PATCH_SNAPSHOT) {
        $ui.Form.TopMost = $true
        $ui.Form.Show()
        $ui.Form.Activate()
        [Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 400
        [Windows.Forms.Application]::DoEvents()
        $b = $ui.Form.Bounds
        $bmp = New-Object Drawing.Bitmap($b.Width, $b.Height)
        $ui.Form.DrawToBitmap($bmp, (New-Object Drawing.Rectangle(0, 0, $b.Width, $b.Height)))
        $bmp.Save($env:ICQ_PATCH_SNAPSHOT, [Drawing.Imaging.ImageFormat]::Png)
        $ui.Form.Close()
        return
    }
    [void]$ui.Form.ShowDialog()
}
