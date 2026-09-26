// The window every client patch shows.
//
// Each patch keeps its own logic and only describes its window: title, one
// line about what it does, the badge and colour of its client version, the
// columns of its list. Everything about how that looks lives here, so the
// patches for different clients look like one family.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace IcqRevival.Patch
{
    // What a patch reports for a change, as the window shows it: a mark, a
    // word, and whether it counts towards "everything is in place".
    internal sealed class StateView
    {
        public string Mark;
        public string Text;
        public bool Counts;
        // Cannot be ticked: something the change needs is not there.
        public bool Blocked;

        static readonly Dictionary<string, StateView> Known = new Dictionary<string, StateView>(Ps.Keys)
        {
            { "patched",        new StateView { Mark = "done", Text = "Applied",        Counts = true } },
            { "original",       new StateView { Mark = "todo", Text = "Not applied",    Counts = true } },
            { "another server", new StateView { Mark = "todo", Text = "Other server",   Counts = true } },
            { "partly",         new StateView { Mark = "todo", Text = "Partly applied", Counts = true } },
            { "no links",       new StateView { Mark = "none", Text = "Nothing to do",  Counts = false } },
            { "missing",        new StateView { Mark = "none", Text = "Not in client",  Counts = false } },
            { "unavailable",    new StateView { Mark = "none", Text = "Not available",  Counts = false, Blocked = true } },
            { "no folder",      new StateView { Mark = "none", Text = "-",              Counts = false } },
            { "other version",  new StateView { Mark = "warn", Text = "Other version",  Counts = true } },
            { "unknown",        new StateView { Mark = "warn", Text = "Unknown",        Counts = true } },
        };

        public static StateView Of(string state)
        {
            StateView view;
            if (Known.TryGetValue(state ?? "", out view)) return view;
            return new StateView { Mark = "warn", Text = state, Counts = true };
        }
    }

    internal sealed class PatchWindow
    {
        // The palette. The window is a grey canvas with white cards on it and a
        // dark header, so the parts stand apart; only the accent line and the
        // main button carry the colour of the client version.
        static readonly Dictionary<string, string> Palette = new Dictionary<string, string>(Ps.Keys)
        {
            { "Canvas", "#DDE3E0" }, { "Card", "#FFFFFF" }, { "Border", "#B4BFBA" }, { "Header", "#1B2420" },
            { "HeaderText", "#FFFFFF" }, { "HeaderDim", "#B9C6C0" }, { "Ink", "#141A17" }, { "Dim", "#3E4A45" },
            { "Button", "#F1F4F2" }, { "ButtonBorder", "#8E9B95" }, { "ButtonHover", "#E2E8E5" },
        };

        static Color ColorOf(string hex) { return PatchIcon.ColorOf(hex); }
        static Color PaletteColor(string name) { return ColorOf(Palette[name]); }

        // Visual styles, and text drawn through GDI: labels and buttons otherwise
        // draw their text through GDI+, which leaves small type without any
        // smoothing at all; GDI text gets ClearType like the text box does. Called
        // before the first window; ShowWindow switches every control once more,
        // as the original did for when this came too late.
        public static void Init()
        {
            try { Application.EnableVisualStyles(); } catch { }
            try { Application.SetCompatibleTextRenderingDefault(false); } catch { }
        }

        public readonly double Scale;
        public readonly Color Accent;
        public readonly List<StateView> Rows = new List<StateView>();
        // What the user took the tick off, by key: kept across refills of the
        // list, so a re-check does not undo a choice not applied yet.
        public readonly HashSet<string> Unchecked = new HashSet<string>();
        // The patch's jobs, for the ones that cannot be on together
        // (PatchJobs.Rivals); none when not set.
        public PatchJobs Jobs;
        public bool Filling, Syncing, Locked, Shown, Busy;

        public readonly Form Form;
        public readonly Label Path;
        public readonly Button FolderButton;
        public readonly TextBox Server;
        public readonly ListView List;
        public readonly CheckBox All;
        public readonly Label Picked;
        public readonly Label Summary;
        public readonly ProgressBar Bar;
        public readonly Panel Footer;
        int buttonsRight;

        Button NewButton(string text, bool primary)
        {
            var b = new Button();
            b.Text = text;
            b.FlatStyle = FlatStyle.Flat;
            b.Cursor = Cursors.Hand;
            b.Height = 34;
            b.Width = Math.Max(100, TextRenderer.MeasureText(text, Form.Font).Width + 40);
            b.UseVisualStyleBackColor = false;
            if (primary)
            {
                b.BackColor = Accent;
                b.ForeColor = Color.White;
                b.Font = new Font(Form.Font, FontStyle.Bold);
                b.FlatAppearance.BorderColor = Accent;
                b.FlatAppearance.MouseOverBackColor = Color.FromArgb(255,
                    Ps.Int(Accent.R * 0.85), Ps.Int(Accent.G * 0.85), Ps.Int(Accent.B * 0.85));
            }
            else
            {
                b.BackColor = PaletteColor("Button");
                b.ForeColor = PaletteColor("Ink");
                b.FlatAppearance.BorderColor = PaletteColor("ButtonBorder");
                b.FlatAppearance.MouseOverBackColor = PaletteColor("ButtonHover");
            }
            return b;
        }

        // A white card with a thin border, set into the canvas by margin. Gives
        // the outer panel, to dock, and the card, to fill.
        static Panel NewCard(int width, Padding margin, out Panel card)
        {
            var outer = new Panel();
            outer.Width = width;
            outer.Padding = margin;
            var c = new Panel();
            c.Width = width - margin.Horizontal;
            c.Dock = DockStyle.Fill;
            c.BackColor = PaletteColor("Card");
            c.Padding = new Padding(1);
            c.Paint += (sender, e) =>
            {
                var s = (Control)sender;
                using (var pen = new Pen(ColorTranslator.FromHtml("#B4BFBA")))
                {
                    e.Graphics.DrawRectangle(pen, 0, 0, s.Width - 1, s.Height - 1);
                }
            };
            c.Resize += (sender, e) => ((Control)sender).Invalidate();
            outer.Controls.Add(c);
            card = c;
            return outer;
        }

        static Label NewCaption(string text, int x, int y)
        {
            var l = new Label();
            l.Text = text.ToUpper();
            l.Font = new Font("Segoe UI", 8.25f, FontStyle.Bold);
            l.ForeColor = PaletteColor("Dim");
            l.AutoSize = true;
            l.Location = new Point(x, y);
            return l;
        }

        // Columns: { "Change", 360 }, { "Where", 200 }; a State column is added last.
        public PatchWindow(string title, string subtitle, string badge, string accentTop, string accentBottom,
            string clientName, string serverHint, params KeyValuePair<string, int>[] columns)
        {
            using (Graphics g = Graphics.FromHwnd(IntPtr.Zero))
            {
                Scale = g.DpiX / 96.0;
            }
            Accent = ColorOf(accentBottom);
            const int W = 820;

            var form = new Form();
            Form = form;
            form.SuspendLayout();
            form.AutoScaleDimensions = new SizeF(96, 96);
            form.AutoScaleMode = AutoScaleMode.Dpi;
            form.Font = new Font("Segoe UI", 9.5f);
            form.Text = title;
            form.ClientSize = new Size(W, 660);
            form.MinimumSize = new Size(680, 520);
            form.StartPosition = FormStartPosition.CenterScreen;
            form.BackColor = PaletteColor("Canvas");
            form.ForeColor = PaletteColor("Ink");
            form.Icon = new Icon(new MemoryStream(PatchIcon.Bytes(badge, accentTop, accentBottom)));
            form.Shown += (sender, e) => Shown = true;
            // Not closed halfway through writing the client's files.
            form.FormClosing += (sender, e) => { if (Busy) e.Cancel = true; };

            // Every panel is given the window's width before anything is anchored
            // to its right edge, or the anchored controls would drift off to the
            // right.

            // header: the icon, the name of the patch and what it does
            var header = new Panel();
            header.Width = W;
            header.Dock = DockStyle.Top;
            header.Height = 96;
            header.BackColor = PaletteColor("Header");
            var pic = new PictureBox();
            pic.Location = new Point(20, 18);
            pic.Size = new Size(60, 60);
            pic.SizeMode = PictureBoxSizeMode.Zoom;
            pic.Image = PatchIcon.Draw(Ps.Int(60 * Scale), badge, accentTop, accentBottom);
            header.Controls.Add(pic);
            var titleLabel = new Label();
            titleLabel.Text = title;
            titleLabel.Font = new Font("Segoe UI Semibold", 16);
            titleLabel.ForeColor = PaletteColor("HeaderText");
            titleLabel.AutoSize = true;
            titleLabel.Location = new Point(94, 12);
            header.Controls.Add(titleLabel);
            var sub = new Label();
            sub.Text = subtitle;
            sub.ForeColor = PaletteColor("HeaderDim");
            sub.Location = new Point(96, 48);
            sub.Size = new Size(W - 116, 42);
            sub.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            header.Controls.Add(sub);

            var accent = new Panel();
            accent.Dock = DockStyle.Top;
            accent.Height = 4;
            accent.BackColor = Accent;

            // the client folder and the server, on one card
            Panel card;
            Panel settings = NewCard(W, new Padding(16, 16, 16, 0), out card);
            settings.Dock = DockStyle.Top;
            settings.Height = 16 + 142;
            int cw = card.Width;

            card.Controls.Add(NewCaption(clientName + " folder", 16, 14));
            Path = new Label();
            Path.Location = new Point(16, 36);
            Path.Size = new Size(cw - 200, 22);
            Path.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Path.AutoEllipsis = true;
            Path.Font = new Font("Segoe UI Semibold", 10);
            card.Controls.Add(Path);
            FolderButton = NewButton("Change folder...", false);
            FolderButton.Location = new Point(cw - 16 - FolderButton.Width, 26);
            FolderButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            card.Controls.Add(FolderButton);

            var rule = new Panel();
            rule.BackColor = ColorOf("#D5DCD8");
            rule.Location = new Point(16, 70);
            rule.Size = new Size(cw - 32, 1);
            rule.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            card.Controls.Add(rule);

            card.Controls.Add(NewCaption("Server domain", 16, 82));
            Server = new TextBox();
            Server.Font = new Font("Segoe UI", 11);
            Server.BorderStyle = BorderStyle.FixedSingle;
            Server.Location = new Point(16, 104);
            Server.Width = 320;
            card.Controls.Add(Server);
            var hint = new Label();
            hint.Text = serverHint;
            hint.ForeColor = PaletteColor("Dim");
            hint.Location = new Point(352, 100);
            hint.Size = new Size(cw - 368, 38);
            hint.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            card.Controls.Add(hint);

            // the list of changes, on a card of its own
            Panel content = NewCard(W, new Padding(16, 12, 16, 16), out card);
            content.Dock = DockStyle.Fill;
            var list = new ListView();
            List = list;
            list.Dock = DockStyle.Fill;
            list.View = View.Details;
            list.FullRowSelect = true;
            list.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            list.ShowItemToolTips = true;
            list.BorderStyle = BorderStyle.None;
            list.ForeColor = PaletteColor("Ink");
            list.CheckBoxes = true;
            list.ItemChecked += (sender, e) => UpdateChecks(e.Item);
            // Once anything is applied the ticks stay as they were applied with.
            // Only a person's clicks are held: the list sets its ticks once more
            // itself when it first appears on screen.
            list.ItemCheck += (sender, e) =>
            {
                if (Locked && Shown && !Filling) e.NewValue = e.CurrentValue;
                // A row that cannot be applied here is not ticked either.
                if (Shown && !Filling && e.NewValue == CheckState.Checked && e.Index < Rows.Count && Rows[e.Index].Blocked)
                {
                    e.NewValue = e.CurrentValue;
                }
            };
            // The tick is the only mark on a row; the State column says the rest.
            // An empty image one pixel wide only gives the rows some height.
            var spacer = new ImageList();
            spacer.ImageSize = new Size(1, Ps.Int(22 * Scale));
            list.SmallImageList = spacer;
            foreach (KeyValuePair<string, int> c in columns) list.Columns.Add(c.Key, Ps.Int(c.Value * Scale));
            list.Columns.Add("State", Ps.Int(110 * Scale));
            card.Controls.Add(list);

            // above the list: tick or clear everything at once
            var bar = new Panel();
            bar.Width = card.Width - 2;
            bar.Dock = DockStyle.Top;
            bar.Height = 40;
            All = new CheckBox();
            All.Text = "Select all";
            All.Font = new Font("Segoe UI Semibold", 9.5f);
            All.AutoSize = true;
            All.AutoCheck = false;
            All.Cursor = Cursors.Hand;
            All.Location = new Point(4, 10);
            All.Click += (sender, e) => SwitchAll();
            bar.Controls.Add(All);
            Picked = new Label();
            Picked.ForeColor = PaletteColor("Dim");
            Picked.Location = new Point(130, 12);
            Picked.Size = new Size(bar.Width - 142, 20);
            Picked.AutoEllipsis = true;
            Picked.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Picked.TextAlign = ContentAlignment.MiddleRight;
            bar.Controls.Add(Picked);
            var sep = new Panel();
            sep.Dock = DockStyle.Bottom;
            sep.Height = 1;
            sep.BackColor = ColorOf("#D5DCD8");
            bar.Controls.Add(sep);
            card.Controls.Add(bar);

            // the bottom bar: how far along it is, and the buttons
            var footer = new Panel();
            footer.Width = W;
            footer.Dock = DockStyle.Bottom;
            footer.Height = 64;
            footer.BackColor = PaletteColor("Card");
            var line = new Panel();
            line.Dock = DockStyle.Top;
            line.Height = 1;
            line.BackColor = PaletteColor("Border");
            footer.Controls.Add(line);
            Summary = new Label();
            Summary.Location = new Point(20, 13);
            Summary.Size = new Size(300, 40);
            Summary.TextAlign = ContentAlignment.MiddleLeft;
            Summary.Font = new Font("Segoe UI Semibold", 10);
            footer.Controls.Add(Summary);
            // Shown under the summary while Apply or Restore runs; the summary
            // then names the step.
            Bar = new ProgressBar();
            Bar.Location = new Point(20, 40);
            Bar.Size = new Size(300, 10);
            Bar.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Bar.Style = ProgressBarStyle.Continuous;
            Bar.Visible = false;
            footer.Controls.Add(Bar);
            Footer = footer;
            buttonsRight = W - 16;

            // Docking goes from the last control added to the first.
            form.Controls.Add(content);
            form.Controls.Add(footer);
            form.Controls.Add(settings);
            form.Controls.Add(accent);
            form.Controls.Add(header);
        }

        // Buttons are laid out from the right, in the order they are added.
        public Button AddButton(string text, Action action, bool primary = false)
        {
            Button b = NewButton(text, primary);
            buttonsRight -= b.Width;
            b.Location = new Point(buttonsRight, 15);
            b.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            b.Click += (sender, e) => action();
            Footer.Controls.Add(b);
            buttonsRight -= 8;
            // The summary ends where the buttons begin, and stays under them.
            Summary.Width = Math.Max(40, buttonsRight - Summary.Left);
            Bar.Width = Summary.Width;
            Summary.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Summary.AutoEllipsis = true;
            Summary.SendToBack();
            if (primary) Form.AcceptButton = b;
            return b;
        }

        public void SetFolder(string path)
        {
            if (!string.IsNullOrEmpty(path))
            {
                Path.Text = path;
                Path.ForeColor = ColorOf("#141A17");
            }
            else
            {
                Path.Text = "Not found - use \"Change folder...\" to pick it";
                Path.ForeColor = ColorOf("#C0392B");
            }
        }

        public void ClearList()
        {
            Filling = true;
            List.BeginUpdate();
            List.Items.Clear();
            List.Groups.Clear();
            Rows.Clear();
        }

        public ListViewGroup AddGroup(string name)
        {
            var grp = new ListViewGroup(name);
            List.Groups.Add(grp);
            return grp;
        }

        // cells fills the columns before State; the tooltip shows the whole
        // first one. key names the row for the selection.
        public void AddRow(ListViewGroup group, string[] cells, string state, string key)
        {
            StateView view = StateView.Of(state);
            string text = cells[0];
            // A capital to start the row, except for names spelt with one inside (tZers).
            if (text.Length > 1 && !char.IsUpper(text[1])) text = text.Substring(0, 1).ToUpper() + text.Substring(1);
            var item = new ListViewItem(text);
            item.Group = group;
            item.ToolTipText = text;
            item.Name = key;
            item.Checked = !Unchecked.Contains(key);
            item.UseItemStyleForSubItems = false;
            for (int i = 1; i < cells.Length; i++)
            {
                ListViewItem.ListViewSubItem cell = item.SubItems.Add(cells[i]);
                cell.ForeColor = PaletteColor("Dim");
            }
            ListViewItem.ListViewSubItem s = item.SubItems.Add(view.Text);
            switch (view.Mark)
            {
                case "done": s.ForeColor = ColorOf("#17703C"); break;
                case "warn": s.ForeColor = ColorOf("#A24F0B"); break;
                case "todo": s.ForeColor = PaletteColor("Ink"); break;
                default: s.ForeColor = ColorOf("#6B7570"); break;
            }
            List.Items.Add(item);
            Rows.Add(view);
        }

        // Ends a refill of the list and sums it up in the bottom bar.
        //
        // A client with anything applied is locked: the ticks stay the ones it
        // was applied with, and choosing again starts from "Restore original".
        // Apply then only renews what is there - for another domain, say - and
        // never mixes a new choice into a patched client.
        public void CompleteList()
        {
            Locked = Rows.Any(r => r.Counts && r.Mark == "done");
            All.Enabled = !Locked;
            // A locked client holds what it was applied with, and whatever is in
            // place is part of that - also a job that is off until chosen.
            if (Locked)
            {
                for (int i = 0; i < List.Items.Count; i++)
                {
                    ListViewItem item = List.Items[i];
                    if (Rows[i].Mark == "done" && !item.Checked)
                    {
                        item.Checked = true;
                        Unchecked.Remove(item.Name);
                    }
                }
            }
            SettleRivals();
            List.EndUpdate();
            Filling = false;
            UpdateSummary();
        }

        ListViewItem RowOf(string key)
        {
            if (key == null) return null;
            return List.Items.Cast<ListViewItem>().FirstOrDefault(i => i != null && Ps.Eq(i.Name, key));
        }

        StateView ViewOf(ListViewItem item)
        {
            return item != null && item.Index >= 0 && item.Index < Rows.Count ? Rows[item.Index] : null;
        }

        void SetTick(ListViewItem item, bool on)
        {
            item.Checked = on;
            if (on) Unchecked.Remove(item.Name); else Unchecked.Add(item.Name);
        }

        // After a refill: a row that cannot be applied is cleared, and its
        // rival - cleared only to make way for it - ticked again; of two rivals
        // both ticked, the one in place stays, else the one on by default.
        void SettleRivals()
        {
            if (Jobs == null) return;
            foreach (ListViewItem item in List.Items.Cast<ListViewItem>().ToList())
            {
                StateView view = ViewOf(item);
                if (item == null || view == null || !view.Blocked || !item.Checked) continue;
                SetTick(item, false);
                ListViewItem rival = RowOf(Jobs.RivalOf(item.Name));
                StateView rivalView = ViewOf(rival);
                if (rival != null && !rival.Checked && rivalView != null && !rivalView.Blocked) SetTick(rival, true);
            }
            foreach (ListViewItem item in List.Items.Cast<ListViewItem>().ToList())
            {
                if (item == null || !Jobs.IsWinner(item.Name)) continue;
                ListViewItem loser = RowOf(Jobs.RivalOf(item.Name));
                if (loser == null || !item.Checked || !loser.Checked) continue;
                bool winnerIn = ViewOf(item).Mark == "done";
                bool loserIn = ViewOf(loser).Mark == "done";
                SetTick(winnerIn && !loserIn ? loser : item, false);
            }
        }

        // Whether a row counts towards "Select all": not one that cannot be
        // applied, and not one whose rival is ticked in its place.
        bool Selectable(ListViewItem item)
        {
            // A row the list has not come to yet (see Ticked) counts, cleared.
            if (item == null) return true;
            StateView view = ViewOf(item);
            if (view != null && view.Blocked) return false;
            if (Jobs == null || Ticked(item)) return true;
            ListViewItem rival = RowOf(Jobs.RivalOf(item.Name));
            return rival == null || !Ticked(rival);
        }

        void UpdateChecks(ListViewItem item)
        {
            if (Filling) return;
            if (item.Checked) Unchecked.Remove(item.Name); else Unchecked.Add(item.Name);
            // Ticking one of two rivals clears the other.
            if (item.Checked && Jobs != null && !Syncing)
            {
                ListViewItem rival = RowOf(Jobs.RivalOf(item.Name));
                if (rival != null && rival.Checked) rival.Checked = false;
            }
            // Select all sums up once, after the last row.
            if (!Syncing) UpdateSummary();
        }

        // Everything ticked becomes everything cleared; anything else, all ticked.
        void SwitchAll()
        {
            if (Locked) return;
            List<ListViewItem> items = List.Items.Cast<ListViewItem>().ToList();
            bool target = items.Any(i => Selectable(i) && !Ticked(i));
            var before = new Dictionary<ListViewItem, bool>();
            foreach (ListViewItem item in items) { if (item != null) before[item] = Ticked(item); }
            Syncing = true;
            foreach (ListViewItem item in items)
            {
                if (item == null || item.Checked == target) continue;
                StateView view = ViewOf(item);
                if (target && view != null && view.Blocked) continue;
                item.Checked = target;
            }
            // Of two rivals, the one ticked before stays; if neither was, the
            // one on by default.
            if (target && Jobs != null)
            {
                foreach (ListViewItem item in items)
                {
                    if (item == null || !Jobs.IsWinner(item.Name)) continue;
                    ListViewItem loser = RowOf(Jobs.RivalOf(item.Name));
                    if (loser == null || !item.Checked || !loser.Checked) continue;
                    if (before[item] && !before[loser]) loser.Checked = false; else item.Checked = false;
                }
            }
            Syncing = false;
            UpdateSummary();
        }

        // Whether a row is ticked. While the list first appears on screen it
        // sets its ticks once more, row by row, and the rows it has not come to
        // yet read as missing: they count as cleared until it does.
        static bool Ticked(ListViewItem item) { return item != null && item.Checked; }

        // Whether a row is to be applied: the selection a patch acts on.
        public bool IsSelected(string key) { return !Unchecked.Contains(key); }

        void UpdateSummary()
        {
            List<ListViewItem> items = List.Items.Cast<ListViewItem>().ToList();
            List<ListViewItem> selectable = items.Where(Selectable).ToList();
            int ticked = selectable.Count(Ticked);
            All.CheckState = selectable.Count > 0 && ticked == selectable.Count ? CheckState.Checked
                : ticked == 0 ? CheckState.Unchecked : CheckState.Indeterminate;
            Picked.Text = items.Count == 0 ? ""
                : Locked ? "Selection locked - Restore original to change it"
                : ticked + " of " + selectable.Count + " selected";

            // What Apply would do: put in what is ticked and missing, take out
            // what is in place and cleared.
            int counted = 0, done = 0, warn = 0, pending = 0;
            for (int i = 0; i < items.Count; i++)
            {
                StateView view = Rows[i];
                if (!view.Counts) continue;
                counted++;
                if (view.Mark == "done") done++;
                if (view.Mark == "warn") warn++;
                if ((Ticked(items[i]) && view.Mark == "todo") || (!Ticked(items[i]) && view.Mark == "done")) pending++;
            }
            if (counted == 0)
            {
                Summary.Text = "";
            }
            else if (warn > 0)
            {
                Summary.Text = warn + " item(s) do not match this client version";
                Summary.ForeColor = ColorOf("#A24F0B");
            }
            else if (pending > 0)
            {
                Summary.Text = "Apply will change " + pending + " of " + counted;
                Summary.ForeColor = ColorOf("#141A17");
            }
            else if (done == counted)
            {
                Summary.Text = "All " + done + " changes are in place";
                Summary.ForeColor = ColorOf("#17703C");
            }
            else
            {
                Summary.Text = "Selection in place: " + done + " of " + counted + " applied";
                Summary.ForeColor = ColorOf("#17703C");
            }
        }

        // The cleared rows are remembered between runs, under the patch's own
        // key in HKCU, with every row the window showed then. A job that is off
        // until chosen (defaultOff) starts cleared the first time it is seen.
        public void ReadUnchecked(string settingsKey, IEnumerable<string> defaultOff)
        {
            var known = new List<string>();
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(settingsKey))
                {
                    if (key == null) throw new IOException("no settings yet");
                    foreach (string k in PatchSettings.Strings(key.GetValue("Unchecked")))
                    {
                        if (!string.IsNullOrEmpty(k)) Unchecked.Add(k);
                    }
                    known = PatchSettings.Strings(key.GetValue("Known"));
                }
            }
            catch { }
            foreach (string k in defaultOff) { if (!Ps.Contains(known, k)) Unchecked.Add(k); }
        }

        public void SaveUnchecked(string settingsKey)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(settingsKey))
                {
                    key.SetValue("Unchecked", Unchecked.ToArray(), RegistryValueKind.MultiString);
                    string[] names = List.Items.Cast<ListViewItem>().Select(i => i?.Name).ToArray();
                    key.SetValue("Known", names, RegistryValueKind.MultiString);
                }
            }
            catch { }
        }

        // Apply and Restore run on the window's own thread: the bar is moved
        // and the window repainted at each step, with everything that could
        // start another run held still meanwhile.
        public void StartWork(string text)
        {
            Busy = true;
            foreach (Control c in Footer.Controls.Cast<Control>().Concat(new Control[] { FolderButton, Server, List, All }).ToList())
            {
                if (!(c is Label) && !(c is ProgressBar) && !(c is Panel)) c.Enabled = false;
            }
            Form.UseWaitCursor = true;
            Summary.Height = 26;
            Summary.TextAlign = ContentAlignment.BottomLeft;
            Summary.ForeColor = ColorOf("#141A17");
            Summary.Text = text;
            Bar.Value = 0;
            Bar.Visible = true;
            PatchSteps.Show = (done, total, step) =>
            {
                Bar.Maximum = total;
                Bar.Value = Math.Min(done - 1, total);
                Summary.Text = step;
                Application.DoEvents();
            };
            Application.DoEvents();
        }

        public void StopWork()
        {
            Bar.Value = Bar.Maximum;
            Application.DoEvents();
            PatchSteps.Show = null;
            Bar.Visible = false;
            Summary.Height = 40;
            Summary.TextAlign = ContentAlignment.MiddleLeft;
            foreach (Control c in Footer.Controls.Cast<Control>().Concat(new Control[] { FolderButton, Server, List }).ToList())
            {
                c.Enabled = true;
            }
            All.Enabled = !Locked;
            Form.UseWaitCursor = false;
            Busy = false;
        }

        static void SetTextRendering(Control control)
        {
            var label = control as Label;
            if (label != null) label.UseCompatibleTextRendering = false;
            var button = control as ButtonBase;
            if (button != null) button.UseCompatibleTextRendering = false;
            foreach (Control child in control.Controls) SetTextRendering(child);
        }

        // The environment variable that turns ShowWindow into a snapshot: for
        // checking the layout without a person at the screen, the window is
        // drawn into this PNG file and closed again.
        public const string SnapshotVariable = "ICQ_PATCH_SNAPSHOT";

        public static string SnapshotPath
        {
            get { return Environment.GetEnvironmentVariable(SnapshotVariable); }
        }

        public void ShowWindow()
        {
            SetTextRendering(Form);
            Form.ResumeLayout();
            string snapshot = SnapshotPath;
            if (!string.IsNullOrEmpty(snapshot))
            {
                Form.TopMost = true;
                Form.Show();
                Form.Activate();
                Application.DoEvents();
                // ICQ_PATCH_SNAPSHOT_ROW=<key> brings that row into view first.
                ListViewItem row = RowOf(Environment.GetEnvironmentVariable(SnapshotVariable + "_ROW"));
                if (row != null) row.EnsureVisible();
                Thread.Sleep(400);
                Application.DoEvents();
                Rectangle b = Form.Bounds;
                using (var bmp = new Bitmap(b.Width, b.Height))
                {
                    Form.DrawToBitmap(bmp, new Rectangle(0, 0, b.Width, b.Height));
                    bmp.Save(snapshot, System.Drawing.Imaging.ImageFormat.Png);
                }
                Form.Close();
                return;
            }
            Form.ShowDialog();
        }
    }
}
