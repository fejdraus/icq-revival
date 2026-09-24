// Patch for ICQ Pro 2003b (build 3916) - a windowed tool, the same kind as
// the one for ICQ 6.5.
//
// What it changes is in Icq2003bClient.cs. The folder is found on its own:
// next to this tool first (dropped into the ICQ folder, or a portable copy),
// then from the registry, then the standard path.
//
// Without arguments the window opens. For a scripted run:
//   ICQ-2003b-Patch.exe -Apply   [-Root <folder>] [-Server <domain>] [-Skip <jobs>] [-Include ukrainian] [-NoRegistry]
//   ICQ-2003b-Patch.exe -Restore [-Root <folder>] [-NoRegistry]
// -Skip takes job keys (banners, google bar, send-by, links, sign-in,
// ukrainian), separated by commas; -Include takes the jobs that are off unless
// asked for. The run reports on the standard output ("applied: ...", "did not
// fit: ...", "changes made: N", "files restored: N") and exits with 0, or
// with 1 and the reason on the standard error.
//
// The window is the one all client patches share, ..\Common\PatchWindow.cs.
// Built into tools\icq2003b\patch\ICQ-2003b-Patch.exe by tools\common\Build-Patches.ps1.

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
                    // Jobs that are off unless asked for, such as ukrainian.
                    new CliParam("Include", CliKind.List),
                    // Leaves the registry alone - the sign-in server lives there,
                    // for the whole machine, not in the folder. For runs on a copy
                    // of the client.
                    new CliParam("NoRegistry", CliKind.Switch));
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
            new Icq2003bWindow(a.Switch("NoRegistry")).Run();
            return 0;
        }

        // --- scripted run ---------------------------------------------------------

        static int RunHeadless(CliArgs a)
        {
            string rootArg = a.Text("Root");
            string root = !string.IsNullOrEmpty(rootArg) ? System.IO.Path.GetFullPath(rootArg) : Icq2003bClient.FindRoot();
            if (!Icq2003bClient.IsClientFolder(root))
            {
                Console.Error.WriteLine("ICQ Pro 2003b folder not found: " + root);
                return 1;
            }
            var client = new Icq2003bClient(root, a.Switch("NoRegistry"));
            if (a.Switch("Restore"))
            {
                Console.WriteLine("files restored: " + client.RestoreAll());
                return 0;
            }
            string previous = Icq2003bClient.SavedBase();
            string serverArg = a.Text("Server");
            string domain = !string.IsNullOrEmpty(serverArg) ? Domain.Of(serverArg) : previous;
            if (!Domain.IsValid(domain))
            {
                Console.Error.WriteLine("not a domain: '" + serverArg + "' - pass -Server icq.example.org");
                return 1;
            }
            var skip = new HashSet<string>();
            foreach (string k in a.List("Skip")) skip.Add(k);
            string[] include = a.List("Include");
            foreach (string k in Icq2003bClient.Jobs.Keys)
            {
                if (Icq2003bClient.Jobs[k].Off && !Ps.Contains(include, k)) skip.Add(k);
            }
            Icq2003bResult result;
            try
            {
                result = client.ApplyAll(domain, previous, skip);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                return 1;
            }
            foreach (string line in result.Lines) Console.WriteLine(line);
            foreach (string t in result.TooLong) Console.WriteLine("did not fit: " + t);
            Console.WriteLine("changes made: " + result.Lines.Count);
            return 0;
        }
    }

    // --- window -------------------------------------------------------------------

    internal sealed class Icq2003bWindow
    {
        readonly PatchWindow ui;
        readonly bool noRegistry;
        string root;

        public Icq2003bWindow(bool noRegistry)
        {
            this.noRegistry = noRegistry;
            root = Icq2003bClient.FindRoot();

            ui = new PatchWindow("ICQ Pro 2003b Patch",
                "Removes the banners, the Google search bar and the empty strip they occupied, and points the menu items that used to open ICQ.com at your own server. The user database and the skin are left untouched.",
                "2003b", "#4FA3E0", "#1F66B0", "ICQ Pro 2003b",
                "Just the domain, e.g. icq.example.org. The patch fills in the port and path, and new accounts sign in there. Remembered for next time.",
                new KeyValuePair<string, int>("Change", 400), new KeyValuePair<string, int>("Where", 210));

            ui.FolderButton.Click += (sender, e) => SelectFolder();
            string saved = Icq2003bClient.SavedBase();
            if (!string.IsNullOrEmpty(saved)) ui.Server.Text = saved;
            ui.ReadUnchecked(Icq2003bClient.SettingsKey, Icq2003bClient.Jobs.DefaultOff);
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

        bool Ready()
        {
            if (string.IsNullOrEmpty(root))
            {
                MessageBox.Show(
                    "ICQ Pro 2003b folder not found.\n\nPut this tool into the ICQ folder, or pick the folder manually.",
                    "Client not found", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            if (Process.GetProcessesByName("Icq").Length > 0)
            {
                MessageBox.Show(
                    "ICQ is running. Close it properly: tray icon -> Exit.\n\n" +
                    "Do not kill the process: the client leaves its contact list cache half-written and then hangs forever on \"Logging in...\"",
                    "Close ICQ first", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            return true;
        }

        void Apply()
        {
            if (!Ready()) return;
            // Checked before anything is written.
            string domain = Domain.Of(ui.Server.Text);
            if (!Domain.IsValid(domain))
            {
                MessageBox.Show(
                    "Type your server's domain, nothing else:\n\n  icq.example.org\n\nThe port and path are filled in by the patch.",
                    "Server", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            ui.Server.Text = domain;
            ui.SaveUnchecked(Icq2003bClient.SettingsKey);
            ui.StartWork("Applying...");
            Icq2003bResult result;
            try
            {
                result = new Icq2003bClient(root, noRegistry).ApplyAll(domain, Icq2003bClient.SavedBase(), ui.Unchecked);
            }
            catch (Exception e)
            {
                ui.StopWork();
                MessageBox.Show(e.Message, "Wrong client version", MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateView();
                return;
            }
            ui.StopWork();
            Icq2003bClient.SaveBase(domain);
            UpdateView();

            List<string> done = result.Lines;
            string msg = done.Count > 0
                ? "Changes made: " + done.Count + "\n\n  " + string.Join("\n  ", done.Take(12))
                : "The client already matches the selection.";
            if (done.Count > 12) msg += "\n  ...";
            if (result.TooLong.Count > 0)
            {
                msg += "\n\nThese did not fit and were left alone:\n  " + string.Join("\n  ", result.TooLong) +
                       "\n\nA link stored inside the executable cannot be made longer than the original," +
                       " so a shorter server address would fix it.";
            }
            if (ui.IsSelected("sign-in") && Ps.Eq(Icq2003bClient.SignInServer(), domain))
            {
                string c = Icq2003bClient.ConnectionServer();
                if (Ps.IsTrue(c) && !Ps.Eq(c, domain))
                {
                    msg += "\n\nICQ is set to sign in to " + c + " under Preferences -> Connection," +
                           " which looks like your own choice, so it was left alone. Change it there" +
                           " to " + domain + " to sign in to this server.";
                }
                else
                {
                    msg += "\n\nICQ signs in to " + domain + ".";
                }
            }
            msg += "\n\nYou can start ICQ now.";
            MessageBox.Show(msg, "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void Restore()
        {
            if (!Ready()) return;
            ui.StartWork("Restoring...");
            int done;
            try { done = new Icq2003bClient(root, noRegistry).RestoreAll(); }
            finally { ui.StopWork(); }
            UpdateView();
            MessageBox.Show("Files restored: " + done + ".", "Done", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void SelectFolder()
        {
            using (var dlg = new FolderBrowserDialog())
            {
                dlg.Description = "Select the ICQ Pro 2003b folder (the one with Icq.exe)";
                if (!string.IsNullOrEmpty(root)) dlg.SelectedPath = root;
                if (dlg.ShowDialog() != DialogResult.OK) return;
                if (Icq2003bClient.IsClientFolder(dlg.SelectedPath))
                {
                    root = dlg.SelectedPath;
                    UpdateView();
                }
                else
                {
                    MessageBox.Show(
                        "This folder does not look like ICQ Pro 2003b.\n\nExpected files: " + Icq2003bClient.ExpectedFiles,
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
                foreach (PatchItem it in new Icq2003bClient(root, noRegistry).Items(Domain.Of(ui.Server.Text)))
                {
                    if (!groups.ContainsKey(it.Group)) groups[it.Group] = ui.AddGroup(it.Group);
                    ui.AddRow(groups[it.Group], new[] { it.What, it.Where }, it.State, it.Key);
                }
            }
            ui.CompleteList();
        }
    }
}
