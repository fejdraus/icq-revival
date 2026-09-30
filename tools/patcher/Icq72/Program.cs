// Patch for ICQ 7.2 (build 3143) - a windowed tool, the same kind as the ones
// for ICQ 6.5 and ICQ Pro 2003b.
//
// What it changes is in Icq72Client.cs. The folder is found on its own: next
// to this tool first (dropped into the ICQ folder), then from the registry,
// then the standard path.
//
// Without arguments the window opens. For a scripted run:
//   ICQ-7.2-Patch.exe -Apply   [-Root <folder>] [-Server <domain>] [-Skip <keys>] [-Include tzers-player] [-Player <dll>]
//   ICQ-7.2-Patch.exe -Restore [-Root <folder>]
// -Skip takes job keys (sms, games, xtraz, lifestream, mailbox, ads, fix,
// links, sign-in, tzers-player), separated by commas; they are left out, or
// taken out if in place. -Include takes the jobs that are off unless asked
// for: tzers-player. -Player is our FlashPlayerControl-Ruffle.dll for it,
// when not next to this exe. The run reports on the standard output ("applied: ...", "changes
// made: N", "files restored: N") and exits with 0, or with 1 and the reason
// on the standard error.
//
// The window is the one all client patches share, ..\Common\PatchWindow.cs.
// Built into tools\icq72\patch\ICQ-7.2-Patch.exe by tools\common\Build-Patches.ps1.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
            // A failure inside a button's work is reported and the window stays.
            Application.ThreadException += (sender, e) => Console.Error.WriteLine(e.Exception.Message);
            new Icq72Window(a.Text("Player")).Run();
            return 0;
        }

        // --- scripted run ---------------------------------------------------------

        static int RunHeadless(CliArgs a)
        {
            string rootArg = a.Text("Root");
            string root = !string.IsNullOrEmpty(rootArg) ? System.IO.Path.GetFullPath(rootArg) : Icq72Client.FindRoot();
            if (!Icq72Client.IsClientFolder(root))
            {
                Console.Error.WriteLine("ICQ 7.2 folder not found: " + root);
                return 1;
            }
            var client = new Icq72Client(root, a.Text("Player"));
            if (a.Switch("Restore"))
            {
                int n = client.RestoreAll();
                Console.WriteLine("files restored: " + n);
                return 0;
            }
            string serverArg = a.Text("Server");
            string domain = !string.IsNullOrEmpty(serverArg) ? Domain.Of(serverArg) : Icq72Client.SavedServer();
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
                foreach (string k in Icq72Client.Jobs.Keys)
                {
                    if (Icq72Client.Jobs[k].Off && !Ps.Contains(include, k)) skip.Add(k);
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

    internal sealed class Icq72Window
    {
        readonly PatchWindow ui;
        readonly string player;
        string root;

        public Icq72Window(string player)
        {
            this.player = player;
            root = Icq72Client.FindRoot();

            ui = new PatchWindow("ICQ 7.2 Patch",
                "Removes what is left of the ICQ.com services - SMS, games, Xtraz, Lifestream, the mail tab and advertising - and points the client at your own server. Your profile and history are left untouched.",
                "7.2", "#F5A43C", "#C4631A", "ICQ 7.2",
                "Just the domain, e.g. icq.example.org. The patch fills in ports and paths, and ICQ signs in there. Remembered for next time.",
                new KeyValuePair<string, int>("Change", 420), new KeyValuePair<string, int>("Where", 190));

            ui.FolderButton.Click += (sender, e) => SelectFolder();
            string saved = Icq72Client.SavedServer();
            if (!string.IsNullOrEmpty(saved)) ui.Server.Text = saved;
            ui.Jobs = Icq72Client.Jobs;
            ui.ReadUnchecked(Icq72Client.SettingsKey, Icq72Client.Jobs.DefaultOff);
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
                    "ICQ 7.2 folder not found.\n\nPut this tool into the ICQ folder, or pick the folder manually.",
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
            Icq72Client.SaveServer(server);
            ui.SaveUnchecked(Icq72Client.SettingsKey);
            ui.StartWork("Applying...");
            List<string> done;
            try
            {
                done = new Icq72Client(root, player).ApplyAll(server, ui.Unchecked);
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
            if (ui.IsSelected("tzers-player")) msg += "\n\ntZers and Flash avatars play for the Windows user " + Environment.UserName + ", who has to be the one starting ICQ.";
            msg += "\n\nYou can start ICQ now.";
            MessageBox.Show(msg, "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void Restore()
        {
            if (!Ready()) return;
            ui.StartWork("Restoring...");
            int n;
            try { n = new Icq72Client(root, player).RestoreAll(); }
            finally { ui.StopWork(); }
            UpdateView();
            MessageBox.Show("Files restored: " + n + ".", "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void SelectFolder()
        {
            using (var dlg = new FolderBrowserDialog())
            {
                dlg.Description = "Select the ICQ 7.2 folder (the one with ICQ.exe)";
                if (!string.IsNullOrEmpty(root)) dlg.SelectedPath = root;
                if (dlg.ShowDialog() != DialogResult.OK) return;
                if (Icq72Client.IsClientFolder(dlg.SelectedPath))
                {
                    root = dlg.SelectedPath;
                    UpdateView();
                }
                else
                {
                    MessageBox.Show(
                        "This folder does not look like ICQ 7.2.\n\nExpected: ICQ.exe of version 7.2, " + Icq72Client.Content + " and " + Icq72Client.Config,
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
                foreach (PatchItem it in new Icq72Client(root, player).Items(CurrentServer()))
                {
                    if (!groups.ContainsKey(it.Group)) groups[it.Group] = ui.AddGroup(it.Group);
                    ui.AddRow(groups[it.Group], new[] { it.What, it.Where }, it.State, it.Key);
                }
            }
            ui.CompleteList();
        }
    }
}
