// Patch for ICQ 6.5 (build 2024) - a windowed tool, the same kind as the one
// for ICQ Pro 2003b.
//
// What it changes is in Icq65Client.cs. The folder is found on its own: next
// to this tool first (dropped into the ICQ folder), then from the registry,
// then the standard path.
//
// Without arguments the window opens. For a scripted run:
//   ICQ-6.5-Patch.exe -Apply   [-Root <folder>] [-Server <domain>] [-Skip <keys>] [-Include tzers-player] [-Player <dll>]
//   ICQ-6.5-Patch.exe -Restore [-Root <folder>]
// -Skip takes job keys (xtraz, tzers, sms, zlango, ads, fix, links, sign-in,
// tzers-player, e2e-probe), separated by commas; they are left out, or taken
// out if in place. -Include takes the jobs that are off unless asked for:
// tzers-player (which then wins over tzers), e2e-probe. -Player is our FlashPlayerControl-Ruffle.dll for it,
// when not next to this exe. The run reports on the standard output
// ("applied: ...", "changes made: N", "files restored: N") and exits with 0,
// or with 1 and the reason on the standard error.
//
// The window is the one all client patches share, ..\Common\PatchWindow.cs.
// Built into tools\icq65\patch\ICQ-6.5-Patch.exe by tools\common\Build-Patches.ps1.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace IcqRevival.Patch
{
    internal static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            CliArgs a;
            try
            {
                a = PatchCli.Parse(args,
                    new CliParam("Apply", CliKind.Switch),
                    new CliParam("Restore", CliKind.Switch),
                    new CliParam("Root", CliKind.Text),
                    new CliParam("Server", CliKind.Text),
                    // Jobs to leave out - or take out, if in place - by their keys.
                    new CliParam("Skip", CliKind.List),
                    // Jobs that are off unless asked for, such as tzers-player.
                    new CliParam("Include", CliKind.List),
                    // Our FlashPlayerControl-Ruffle.dll, when not next to this exe.
                    new CliParam("Player", CliKind.Text));
            }
            catch (CliException e)
            {
                PatchConsole.Attach();
                Console.Error.WriteLine(e.Message);
                return 1;
            }

            if (a.Switch("Apply") || a.Switch("Restore"))
            {
                PatchConsole.Attach();
                return RunHeadless(a);
            }

            PatchWindow.Init();
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            // A failure inside a button's work is reported and the window stays,
            // as it did in the script.
            Application.ThreadException += (sender, e) => Console.Error.WriteLine(e.Exception.Message);
            new Icq65Window(a.Text("Player")).Run();
            return 0;
        }

        // --- scripted run ---------------------------------------------------------

        static int RunHeadless(CliArgs a)
        {
            string rootArg = a.Text("Root");
            string root = !string.IsNullOrEmpty(rootArg) ? System.IO.Path.GetFullPath(rootArg) : Icq65Client.FindRoot();
            if (!Icq65Client.IsClientFolder(root))
            {
                Console.Error.WriteLine("ICQ 6.5 folder not found: " + root);
                return 1;
            }
            var client = new Icq65Client(root, a.Text("Player"));
            if (a.Switch("Restore"))
            {
                int n = client.RestoreAll();
                Console.WriteLine("files restored: " + n);
                return 0;
            }
            string serverArg = a.Text("Server");
            string domain = !string.IsNullOrEmpty(serverArg) ? Domain.Of(serverArg) : Icq65Client.SavedServer();
            if (!Domain.IsValid(domain))
            {
                Console.Error.WriteLine("not a domain: '" + serverArg + "' - pass -Server icq.example.org");
                return 1;
            }
            List<string> done;
            try
            {
                var skip = new HashSet<string>();
                foreach (string k in a.List("Skip")) skip.Add(k);
                string[] include = a.List("Include");
                foreach (string k in Icq65Client.Jobs.Keys)
                {
                    if (Icq65Client.Jobs[k].Off && !Ps.Contains(include, k)) skip.Add(k);
                }
                done = client.ApplyAll(domain, skip);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                return 1;
            }
            foreach (string line in done) Console.WriteLine(line);
            Console.WriteLine("changes made: " + done.Count);
            return 0;
        }
    }

    // --- window -------------------------------------------------------------------

    internal sealed class Icq65Window
    {
        readonly PatchWindow ui;
        readonly string player;
        string root;

        public Icq65Window(string player)
        {
            this.player = player;
            root = Icq65Client.FindRoot();

            ui = new PatchWindow("ICQ 6.5 Patch",
                "Removes what is left of the ICQ.com services - Xtraz, advertising, tZers, SMS and phone - and points the client at your own server. Your profile and history are left untouched.",
                "6.5", "#4CC06E", "#1E8A46", "ICQ 6.5",
                "Just the domain, e.g. icq.example.org. The patch fills in ports and paths, and ICQ signs in there. Remembered for next time.",
                new KeyValuePair<string, int>("Change", 420), new KeyValuePair<string, int>("Where", 190));

            ui.FolderButton.Click += (sender, e) => SelectFolder();
            string saved = Icq65Client.SavedServer();
            if (!string.IsNullOrEmpty(saved)) ui.Server.Text = saved;
            ui.Jobs = Icq65Client.Jobs;
            ui.ReadUnchecked(Icq65Client.SettingsKey, Icq65Client.Jobs.DefaultOff);
            ui.Server.Leave += (sender, e) => UpdateView();

            ui.AddButton("Close", () => ui.Form.Close());
            ui.AddButton("Apply", Apply, primary: true);
            ui.AddButton("Restore original", Restore);
            ui.AddButton("Re-check", UpdateView);
        }

        public void Run()
        {
            UpdateView();
            ui.ShowWindow();
        }

        string CurrentServer() { return Domain.Of(ui.Server.Text); }

        static bool ClientRunning()
        {
            return Process.GetProcessesByName("ICQ").Length > 0;
        }

        bool Ready()
        {
            if (string.IsNullOrEmpty(root))
            {
                MessageBox.Show(
                    "ICQ 6.5 folder not found.\n\nPut this tool into the ICQ folder, or pick the folder manually.",
                    "Client not found", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            if (ClientRunning())
            {
                MessageBox.Show(
                    "ICQ is running, and it keeps its own files open.\n\nClose it first: tray icon -> Exit.",
                    "Close ICQ first", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            return true;
        }

        void Apply()
        {
            if (!Ready()) return;
            string server = CurrentServer();
            if (!Domain.IsValid(server))
            {
                MessageBox.Show(
                    "Type your server's domain, nothing else:\n\n  icq.example.org\n\nThe ports and paths are filled in by the patch.",
                    "Server", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            ui.Server.Text = server;
            Icq65Client.SaveServer(server);
            ui.SaveUnchecked(Icq65Client.SettingsKey);
            ui.StartWork("Applying...");
            List<string> done;
            try
            {
                done = new Icq65Client(root, player).ApplyAll(server, ui.Unchecked);
            }
            catch (Exception e)
            {
                ui.StopWork();
                MessageBox.Show(e.Message, "Wrong client version", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateView();
                return;
            }
            ui.StopWork();
            UpdateView();
            string msg = done.Count > 0
                ? "Changes made: " + done.Count + "\n\n  " + string.Join("\n  ", done.Take(12))
                : "The client already matches the selection.";
            if (done.Count > 12) msg += "\n  ...";
            if (ui.IsSelected("sign-in")) msg += "\n\nWith automatic connection settings ICQ signs in to " + server + ".";
            // The type library is registered for the user this patch runs as;
            // elevated with another account's password, that is not the one
            // who starts ICQ.
            if (ui.IsSelected("tzers-player")) msg += "\n\ntZers play for the Windows user " + Environment.UserName + ", who has to be the one starting ICQ.";
            if (ui.IsSelected("e2e-probe")) msg += "\n\nThe E2E test harness (Phase 1) is in place: the text of every message goes out rewritten (an [e2e-harness] marker and ROT13) and is restored on arrival, so a contact without it sees the scrambled form. Set ICQE2E_LOG to a file path before starting ICQ to log each message; ICQE2E_PEERS=uin1,uin2 limits rewriting to those contacts, ICQE2E_MODE=observe turns rewriting off.";
            msg += "\n\nYou can start ICQ now.";
            MessageBox.Show(msg, "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void Restore()
        {
            if (!Ready()) return;
            ui.StartWork("Restoring...");
            int n;
            try { n = new Icq65Client(root, player).RestoreAll(); }
            finally { ui.StopWork(); }
            UpdateView();
            MessageBox.Show("Files restored: " + n + ".", "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void SelectFolder()
        {
            using (var dlg = new FolderBrowserDialog())
            {
                dlg.Description = "Select the ICQ 6.5 folder (the one with ICQ.exe)";
                if (!string.IsNullOrEmpty(root)) dlg.SelectedPath = root;
                if (dlg.ShowDialog() != DialogResult.OK) return;
                if (Icq65Client.IsClientFolder(dlg.SelectedPath))
                {
                    root = dlg.SelectedPath;
                    UpdateView();
                }
                else
                {
                    MessageBox.Show(
                        "This folder does not look like ICQ 6.5.\n\nExpected: ICQ.exe, MUICore.dll and " + Icq65Client.Content,
                        "Wrong folder", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        void UpdateView()
        {
            ui.SetFolder(root);
            ui.ClearList();
            if (!string.IsNullOrEmpty(root))
            {
                var groups = new Dictionary<string, ListViewGroup>(Ps.Keys);
                foreach (PatchItem it in new Icq65Client(root, player).Items(CurrentServer()))
                {
                    if (!groups.ContainsKey(it.Group)) groups[it.Group] = ui.AddGroup(it.Group);
                    ui.AddRow(groups[it.Group], new[] { it.What, it.Where }, it.State, it.Key);
                }
            }
            ui.CompleteList();
        }
    }
}
