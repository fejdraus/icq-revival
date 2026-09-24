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
    'partly'         = @{ Mark = 'todo';  Text = 'Partly applied'; Counts = $true }
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

# --- window --------------------------------------------------------------------

try { [Windows.Forms.Application]::EnableVisualStyles() } catch { }
# Labels and buttons otherwise draw their text through GDI+, which leaves
# small type without any smoothing at all; GDI text gets ClearType like the
# text box does. The call fails once a window exists - then every control is
# switched one by one in Show-PatchWindow.
try { [Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

function Set-PatchTextRendering([Windows.Forms.Control]$control) {
    if ($control -is [Windows.Forms.Label] -or $control -is [Windows.Forms.ButtonBase]) {
        $control.UseCompatibleTextRendering = $false
    }
    foreach ($child in $control.Controls) { Set-PatchTextRendering $child }
}

# The palette. The window is a grey canvas with white cards on it and a dark
# header, so the parts stand apart; only the accent line and the main button
# carry the colour of the client version.
$PatchPalette = @{
    Canvas = '#DDE3E0'; Card = '#FFFFFF'; Border = '#B4BFBA'; Header = '#1B2420'
    HeaderText = '#FFFFFF'; HeaderDim = '#B9C6C0'; Ink = '#141A17'; Dim = '#3E4A45'
    Button = '#F1F4F2'; ButtonBorder = '#8E9B95'; ButtonHover = '#E2E8E5'
}

function Get-PatchColor([string]$name) { return ConvertTo-PatchColor $PatchPalette[$name] }

function New-PatchButton([string]$text, [bool]$primary, $ui) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text
    $b.FlatStyle = 'Flat'
    $b.Cursor = [Windows.Forms.Cursors]::Hand
    $b.Height = 34
    $b.Width = [Math]::Max(100, [Windows.Forms.TextRenderer]::MeasureText($text, $ui.Form.Font).Width + 40)
    $b.UseVisualStyleBackColor = $false
    if ($primary) {
        $b.BackColor = $ui.Accent
        $b.ForeColor = [Drawing.Color]::White
        $b.Font = New-Object Drawing.Font($ui.Form.Font, [Drawing.FontStyle]::Bold)
        $b.FlatAppearance.BorderColor = $ui.Accent
        $b.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(255,
            [int]($ui.Accent.R * 0.85), [int]($ui.Accent.G * 0.85), [int]($ui.Accent.B * 0.85))
    } else {
        $b.BackColor = Get-PatchColor 'Button'
        $b.ForeColor = Get-PatchColor 'Ink'
        $b.FlatAppearance.BorderColor = Get-PatchColor 'ButtonBorder'
        $b.FlatAppearance.MouseOverBackColor = Get-PatchColor 'ButtonHover'
    }
    return $b
}

# A white card with a thin border, set into the canvas by $margin. Returns
# the outer panel, to dock, and the card, to fill.
function New-PatchCard([int]$width, [Windows.Forms.Padding]$margin) {
    $outer = New-Object Windows.Forms.Panel
    $outer.Width = $width
    $outer.Padding = $margin
    $card = New-Object Windows.Forms.Panel
    $card.Width = $width - $margin.Horizontal
    $card.Dock = 'Fill'
    $card.BackColor = Get-PatchColor 'Card'
    $card.Padding = New-Object Windows.Forms.Padding(1)
    $card.Add_Paint({
        param($sender, $e)
        $pen = New-Object Drawing.Pen([Drawing.ColorTranslator]::FromHtml('#B4BFBA'))
        $e.Graphics.DrawRectangle($pen, 0, 0, $sender.Width - 1, $sender.Height - 1)
        $pen.Dispose()
    })
    $card.Add_Resize({ $this.Invalidate() })
    $outer.Controls.Add($card)
    return @($outer, $card)
}

function New-PatchCaption([string]$text, [int]$x, [int]$y) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $text.ToUpper()
    $l.Font = New-Object Drawing.Font('Segoe UI', 8.25, [Drawing.FontStyle]::Bold)
    $l.ForeColor = Get-PatchColor 'Dim'
    $l.AutoSize = $true
    $l.Location = New-Object Drawing.Point($x, $y)
    return $l
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

    $ui = @{
        Scale = $scale; Accent = (ConvertTo-PatchColor $AccentBottom); Rows = New-Object System.Collections.ArrayList
        # What the user took the tick off, by key: kept across refills of the
        # list, so a re-check does not undo a choice not applied yet.
        Unchecked = New-Object 'System.Collections.Generic.HashSet[string]'
        Filling = $false; Syncing = $false; Locked = $false; Shown = $false
    }
    $W = 820

    $form = New-Object Windows.Forms.Form
    $ui.Form = $form
    $form.SuspendLayout()
    $form.AutoScaleDimensions = New-Object Drawing.SizeF(96, 96)
    $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object Drawing.Font('Segoe UI', 9.5)
    $form.Text = $Title
    $form.ClientSize = New-Object Drawing.Size($W, 660)
    $form.MinimumSize = New-Object Drawing.Size(680, 520)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = Get-PatchColor 'Canvas'
    $form.ForeColor = Get-PatchColor 'Ink'
    $iconStream = New-Object IO.MemoryStream(, (New-PatchIconBytes $Badge $AccentTop $AccentBottom))
    $form.Icon = New-Object Drawing.Icon($iconStream)
    $form.Tag = $ui
    $form.Add_Shown({ $this.Tag.Shown = $true })

    # Every panel is given the window's width before anything is anchored to
    # its right edge, or the anchored controls would drift off to the right.

    # header: the icon, the name of the patch and what it does
    $header = New-Object Windows.Forms.Panel
    $header.Width = $W
    $header.Dock = 'Top'
    $header.Height = 96
    $header.BackColor = Get-PatchColor 'Header'
    $pic = New-Object Windows.Forms.PictureBox
    $pic.Location = New-Object Drawing.Point(20, 18)
    $pic.Size = New-Object Drawing.Size(60, 60)
    $pic.SizeMode = 'Zoom'
    $pic.Image = New-PatchIconBitmap ([int](60 * $scale)) $Badge $AccentTop $AccentBottom
    $header.Controls.Add($pic)
    $titleLabel = New-Object Windows.Forms.Label
    $titleLabel.Text = $Title
    $titleLabel.Font = New-Object Drawing.Font('Segoe UI Semibold', 16)
    $titleLabel.ForeColor = Get-PatchColor 'HeaderText'
    $titleLabel.AutoSize = $true
    $titleLabel.Location = New-Object Drawing.Point(94, 12)
    $header.Controls.Add($titleLabel)
    $sub = New-Object Windows.Forms.Label
    $sub.Text = $Subtitle
    $sub.ForeColor = Get-PatchColor 'HeaderDim'
    $sub.Location = New-Object Drawing.Point(96, 48)
    $sub.Size = New-Object Drawing.Size(($W - 116), 42)
    $sub.Anchor = 'Top, Left, Right'
    $header.Controls.Add($sub)

    $accent = New-Object Windows.Forms.Panel
    $accent.Dock = 'Top'
    $accent.Height = 4
    $accent.BackColor = $ui.Accent

    # the client folder and the server, on one card
    $pair = New-PatchCard $W (New-Object Windows.Forms.Padding(16, 16, 16, 0))
    $settings = $pair[0]
    $card = $pair[1]
    $settings.Dock = 'Top'
    $settings.Height = 16 + 142
    $cw = $card.Width

    $card.Controls.Add((New-PatchCaption ($ClientName + ' folder') 16 14))
    $ui.Path = New-Object Windows.Forms.Label
    $ui.Path.Location = New-Object Drawing.Point(16, 36)
    $ui.Path.Size = New-Object Drawing.Size(($cw - 200), 22)
    $ui.Path.Anchor = 'Top, Left, Right'
    $ui.Path.AutoEllipsis = $true
    $ui.Path.Font = New-Object Drawing.Font('Segoe UI Semibold', 10)
    $card.Controls.Add($ui.Path)
    $ui.FolderButton = New-PatchButton 'Change folder...' $false $ui
    $ui.FolderButton.Location = New-Object Drawing.Point(($cw - 16 - $ui.FolderButton.Width), 26)
    $ui.FolderButton.Anchor = 'Top, Right'
    $card.Controls.Add($ui.FolderButton)

    $rule = New-Object Windows.Forms.Panel
    $rule.BackColor = ConvertTo-PatchColor '#D5DCD8'
    $rule.Location = New-Object Drawing.Point(16, 70)
    $rule.Size = New-Object Drawing.Size(($cw - 32), 1)
    $rule.Anchor = 'Top, Left, Right'
    $card.Controls.Add($rule)

    $card.Controls.Add((New-PatchCaption 'Server domain' 16 82))
    $ui.Server = New-Object Windows.Forms.TextBox
    $ui.Server.Font = New-Object Drawing.Font('Segoe UI', 11)
    $ui.Server.BorderStyle = 'FixedSingle'
    $ui.Server.Location = New-Object Drawing.Point(16, 104)
    $ui.Server.Width = 320
    $card.Controls.Add($ui.Server)
    $hint = New-Object Windows.Forms.Label
    $hint.Text = $ServerHint
    $hint.ForeColor = Get-PatchColor 'Dim'
    $hint.Location = New-Object Drawing.Point(352, 100)
    $hint.Size = New-Object Drawing.Size(($cw - 368), 38)
    $hint.Anchor = 'Top, Left, Right'
    $card.Controls.Add($hint)

    # the list of changes, on a card of its own
    $pair = New-PatchCard $W (New-Object Windows.Forms.Padding(16, 12, 16, 16))
    $content = $pair[0]
    $card = $pair[1]
    $content.Dock = 'Fill'
    $list = New-Object Windows.Forms.ListView
    $ui.List = $list
    $list.Dock = 'Fill'
    $list.View = 'Details'
    $list.FullRowSelect = $true
    $list.HeaderStyle = 'Nonclickable'
    $list.ShowItemToolTips = $true
    $list.BorderStyle = 'None'
    $list.ForeColor = Get-PatchColor 'Ink'
    $list.CheckBoxes = $true
    # Handlers outlive this function, so they find the window through Tag.
    $list.Tag = $ui
    $list.Add_ItemChecked({ param($sender, $e) Update-PatchChecks $sender.Tag $e.Item })
    # Once anything is applied the ticks stay as they were applied with. Only
    # a person's clicks are held: the list sets its ticks once more itself
    # when it first appears on screen.
    $list.Add_ItemCheck({
        param($sender, $e)
        $u = $sender.Tag
        if ($u.Locked -and $u.Shown -and -not $u.Filling) { $e.NewValue = $e.CurrentValue }
    })
    # The tick is the only mark on a row; the State column says the rest. An
    # empty image one pixel wide only gives the rows some height.
    $spacer = New-Object Windows.Forms.ImageList
    $spacer.ImageSize = New-Object Drawing.Size(1, [int](22 * $scale))
    $list.SmallImageList = $spacer
    foreach ($c in $Columns) { [void]$list.Columns.Add($c[0], [int]($c[1] * $scale)) }
    [void]$list.Columns.Add('State', [int](110 * $scale))
    $card.Controls.Add($list)

    # above the list: tick or clear everything at once
    $bar = New-Object Windows.Forms.Panel
    $bar.Width = $card.Width - 2
    $bar.Dock = 'Top'
    $bar.Height = 40
    $ui.All = New-Object Windows.Forms.CheckBox
    $ui.All.Text = 'Select all'
    $ui.All.Font = New-Object Drawing.Font('Segoe UI Semibold', 9.5)
    $ui.All.AutoSize = $true
    $ui.All.AutoCheck = $false
    $ui.All.Cursor = [Windows.Forms.Cursors]::Hand
    $ui.All.Location = New-Object Drawing.Point(4, 10)
    $ui.All.Tag = $ui
    $ui.All.Add_Click({ param($sender, $e) Switch-PatchAll $sender.Tag })
    $bar.Controls.Add($ui.All)
    $ui.Picked = New-Object Windows.Forms.Label
    $ui.Picked.ForeColor = Get-PatchColor 'Dim'
    $ui.Picked.Location = New-Object Drawing.Point(130, 12)
    $ui.Picked.Size = New-Object Drawing.Size(($bar.Width - 142), 20)
    $ui.Picked.AutoEllipsis = $true
    $ui.Picked.Anchor = 'Top, Left, Right'
    $ui.Picked.TextAlign = 'MiddleRight'
    $bar.Controls.Add($ui.Picked)
    $sep = New-Object Windows.Forms.Panel
    $sep.Dock = 'Bottom'
    $sep.Height = 1
    $sep.BackColor = ConvertTo-PatchColor '#D5DCD8'
    $bar.Controls.Add($sep)
    $card.Controls.Add($bar)

    # the bottom bar: how far along it is, and the buttons
    $footer = New-Object Windows.Forms.Panel
    $footer.Width = $W
    $footer.Dock = 'Bottom'
    $footer.Height = 64
    $footer.BackColor = Get-PatchColor 'Card'
    $line = New-Object Windows.Forms.Panel
    $line.Dock = 'Top'
    $line.Height = 1
    $line.BackColor = Get-PatchColor 'Border'
    $footer.Controls.Add($line)
    $ui.Summary = New-Object Windows.Forms.Label
    $ui.Summary.Location = New-Object Drawing.Point(20, 13)
    $ui.Summary.Size = New-Object Drawing.Size(300, 40)
    $ui.Summary.TextAlign = 'MiddleLeft'
    $ui.Summary.Font = New-Object Drawing.Font('Segoe UI Semibold', 10)
    $footer.Controls.Add($ui.Summary)
    $ui.Footer = $footer
    $ui.ButtonsRight = $W - 16

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
    $b.Location = New-Object Drawing.Point($ui.ButtonsRight, 15)
    $b.Anchor = 'Top, Right'
    $b.Add_Click($action)
    $ui.Footer.Controls.Add($b)
    $ui.ButtonsRight -= 8
    # The summary ends where the buttons begin, and stays under them.
    $ui.Summary.Width = [Math]::Max(40, $ui.ButtonsRight - $ui.Summary.Left)
    $ui.Summary.Anchor = 'Top, Left, Right'
    $ui.Summary.AutoEllipsis = $true
    $ui.Summary.SendToBack()
    if ($Primary) { $ui.Form.AcceptButton = $b }
    return $b
}

function Set-PatchFolder($ui, [string]$path) {
    if ($path) {
        $ui.Path.Text = $path
        $ui.Path.ForeColor = ConvertTo-PatchColor '#141A17'
    } else {
        $ui.Path.Text = 'Not found - use "Change folder..." to pick it'
        $ui.Path.ForeColor = ConvertTo-PatchColor '#C0392B'
    }
}

function Clear-PatchList($ui) {
    $ui.Filling = $true
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
# $key names the row for the selection.
function Add-PatchRow($ui, $group, [string[]]$cells, [string]$state, [string]$key) {
    $view = Get-PatchStateView $state
    $text = $cells[0]
    # A capital to start the row, except for names spelt with one inside (tZers).
    if ($text.Length -gt 1 -and -not [char]::IsUpper($text[1])) { $text = $text.Substring(0, 1).ToUpper() + $text.Substring(1) }
    $item = New-Object Windows.Forms.ListViewItem($text)
    $item.Group = $group
    $item.ToolTipText = $text
    $item.Name = $key
    $item.Checked = -not $ui.Unchecked.Contains($key)
    $item.UseItemStyleForSubItems = $false
    for ($i = 1; $i -lt $cells.Count; $i++) {
        $s = $item.SubItems.Add($cells[$i])
        $s.ForeColor = Get-PatchColor 'Dim'
    }
    $s = $item.SubItems.Add($view.Text)
    $s.ForeColor = switch ($view.Mark) {
        'done' { ConvertTo-PatchColor '#17703C' }
        'warn' { ConvertTo-PatchColor '#A24F0B' }
        'todo' { Get-PatchColor 'Ink' }
        default { ConvertTo-PatchColor '#6B7570' }
    }
    [void]$ui.List.Items.Add($item)
    [void]$ui.Rows.Add($view)
}

# Ends a refill of the list and sums it up in the bottom bar.
#
# A client with anything applied is locked: the ticks stay the ones it was
# applied with, and choosing again starts from "Restore original". Apply then
# only renews what is there - for another domain, say - and never mixes a
# new choice into a patched client.
function Complete-PatchList($ui) {
    $ui.Locked = @($ui.Rows | Where-Object { $_.Counts -and $_.Mark -eq 'done' }).Count -gt 0
    $ui.All.Enabled = -not $ui.Locked
    # A locked client holds what it was applied with, and whatever is in place
    # is part of that - also a job that is off until chosen.
    if ($ui.Locked) {
        for ($i = 0; $i -lt $ui.List.Items.Count; $i++) {
            $item = $ui.List.Items[$i]
            if ($ui.Rows[$i].Mark -eq 'done' -and -not $item.Checked) {
                $item.Checked = $true
                [void]$ui.Unchecked.Remove($item.Name)
            }
        }
    }
    $ui.List.EndUpdate()
    $ui.Filling = $false
    Update-PatchSummary $ui
}

function Update-PatchChecks($ui, $item) {
    if ($ui.Filling) { return }
    if ($item.Checked) { [void]$ui.Unchecked.Remove($item.Name) } else { [void]$ui.Unchecked.Add($item.Name) }
    # Select all sums up once, after the last row.
    if (-not $ui.Syncing) { Update-PatchSummary $ui }
}

# Everything ticked becomes everything cleared; anything else, all ticked.
function Switch-PatchAll($ui) {
    if ($ui.Locked) { return }
    $items = @($ui.List.Items)
    $target = @($items | Where-Object { -not $_.Checked }).Count -gt 0
    $ui.Syncing = $true
    foreach ($item in $items) { if ($item.Checked -ne $target) { $item.Checked = $target } }
    $ui.Syncing = $false
    Update-PatchSummary $ui
}

# Whether a row is to be applied: the selection a patch acts on.
function Test-PatchSelected($ui, [string]$key) { return -not $ui.Unchecked.Contains($key) }

function Update-PatchSummary($ui) {
    $items = @($ui.List.Items)
    $ticked = @($items | Where-Object { $_.Checked }).Count
    $ui.All.CheckState = if ($items.Count -gt 0 -and $ticked -eq $items.Count) { 'Checked' }
        elseif ($ticked -eq 0) { 'Unchecked' } else { 'Indeterminate' }
    $ui.Picked.Text = if (-not $items.Count) { '' }
        elseif ($ui.Locked) { "Selection locked - Restore original to change it" }
        else { "$ticked of $($items.Count) selected" }

    # What Apply would do: put in what is ticked and missing, take out what
    # is in place and cleared.
    $counted = 0; $done = 0; $warn = 0; $pending = 0
    for ($i = 0; $i -lt $items.Count; $i++) {
        $view = $ui.Rows[$i]
        if (-not $view.Counts) { continue }
        $counted++
        if ($view.Mark -eq 'done') { $done++ }
        if ($view.Mark -eq 'warn') { $warn++ }
        if (($items[$i].Checked -and $view.Mark -eq 'todo') -or (-not $items[$i].Checked -and $view.Mark -eq 'done')) { $pending++ }
    }
    if ($counted -eq 0) {
        $ui.Summary.Text = ''
    } elseif ($warn -gt 0) {
        $ui.Summary.Text = "$warn item(s) do not match this client version"
        $ui.Summary.ForeColor = ConvertTo-PatchColor '#A24F0B'
    } elseif ($pending -gt 0) {
        $ui.Summary.Text = "Apply will change $pending of $counted"
        $ui.Summary.ForeColor = ConvertTo-PatchColor '#141A17'
    } elseif ($done -eq $counted) {
        $ui.Summary.Text = "All $done changes are in place"
        $ui.Summary.ForeColor = ConvertTo-PatchColor '#17703C'
    } else {
        $ui.Summary.Text = "Selection in place: $done of $counted applied"
        $ui.Summary.ForeColor = ConvertTo-PatchColor '#17703C'
    }
}

# The cleared rows are remembered between runs, under the patch's own key,
# with every row the window showed then. A job that is off until chosen
# ($defaultOff) starts cleared the first time it is seen.
function Read-PatchUnchecked($ui, [string]$settingsKey, [string[]]$defaultOff) {
    $known = @()
    try {
        $props = Get-ItemProperty -LiteralPath $settingsKey -ErrorAction Stop
        foreach ($k in @($props.Unchecked)) { if ($k) { [void]$ui.Unchecked.Add($k) } }
        $known = @($props.Known)
    } catch { }
    foreach ($k in $defaultOff) { if ($known -notcontains $k) { [void]$ui.Unchecked.Add($k) } }
}

function Save-PatchUnchecked($ui, [string]$settingsKey) {
    try {
        if (-not (Test-Path $settingsKey)) { New-Item -Path $settingsKey -Force | Out-Null }
        New-ItemProperty -LiteralPath $settingsKey -Name Unchecked -PropertyType MultiString -Value ([string[]]@($ui.Unchecked)) -Force | Out-Null
        $known = [string[]]@($ui.List.Items | ForEach-Object { $_.Name })
        New-ItemProperty -LiteralPath $settingsKey -Name Known -PropertyType MultiString -Value $known -Force | Out-Null
    } catch { }
}

function Show-PatchWindow($ui) {
    Set-PatchTextRendering $ui.Form
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
