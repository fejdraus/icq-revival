// The list of changes a client patch offers, shared by every patch and used
// with and without the window.
//
// A patch keeps its changes as small as the files need - one byte run, one
// line of markup - but a person chooses what they get: no Xtraz, no
// advertising, links to their own server. So every change belongs to a job,
// and the window shows one row per job, with one tick and one state.
//
// Filled in by the patch: the jobs in the order the window lists them, and
// which job each change belongs to.

using System;
using System.Collections.Generic;
using System.Linq;

namespace IcqRevival.Patch
{
    // One change, or one job folded out of them. Where is a file, maybe
    // "file at offset".
    internal sealed class PatchItem
    {
        public string Group = "";
        public string Key;
        public string What;
        public string Where;
        public string State;
    }

    internal sealed class PatchJob
    {
        public string Group;
        public string What;
        // Off until chosen: cleared the first time the window sees it.
        public bool Off;
    }

    internal sealed class PatchJobs
    {
        readonly List<string> order = new List<string>();
        readonly Dictionary<string, PatchJob> jobs = new Dictionary<string, PatchJob>(Ps.Keys);
        readonly Dictionary<string, string> jobOf = new Dictionary<string, string>(Ps.Keys);

        public void Add(string key, string group, string what, bool off = false)
        {
            order.Add(key);
            jobs.Add(key, new PatchJob { Group = group, What = what, Off = off });
        }

        // Says which job a change belongs to.
        public void Assign(string part, string job)
        {
            jobOf[part] = job;
        }

        // Two jobs that change the same things opposite ways - taking a
        // feature out, and making it work - so only one of them can be on.
        // The window clears one when the other is ticked; when both are asked
        // for anyway (a scripted run), the winner is taken and the loser left
        // out, which is also what taking it out means for what is in place.
        readonly Dictionary<string, string> rivals = new Dictionary<string, string>(Ps.Keys);
        readonly HashSet<string> winners = new HashSet<string>(Ps.Keys);

        public void Rivals(string winner, string loser)
        {
            rivals[winner] = loser;
            rivals[loser] = winner;
            winners.Add(winner);
        }

        // The job that cannot be on together with this one, or null.
        public string RivalOf(string key)
        {
            string r;
            return key != null && rivals.TryGetValue(key, out r) ? r : null;
        }

        public bool IsWinner(string key) { return key != null && winners.Contains(key); }

        // The jobs to leave out once the rivals are settled: skip, and the
        // loser of every pair of which both are wanted.
        public HashSet<string> Settle(ICollection<string> skip)
        {
            var result = new HashSet<string>();
            if (skip != null) foreach (string k in skip) result.Add(k);
            foreach (string winner in winners)
            {
                string loser = rivals[winner];
                if (IsWanted(result, winner) && IsWanted(result, loser)) result.Add(loser);
            }
            return result;
        }

        public IEnumerable<string> Keys { get { return order; } }

        public PatchJob this[string key] { get { return jobs[key]; } }

        public bool Contains(string key) { return jobs.ContainsKey(key); }

        // The jobs that are off until chosen.
        public string[] DefaultOff { get { return order.Where(k => jobs[k].Off).ToArray(); } }

        // The key a change is chosen by: its job, or the change itself.
        public string KeyOf(string part)
        {
            string job;
            if (jobOf.Count > 0 && jobOf.TryGetValue(part, out job)) return job;
            return part;
        }

        // Whether a change is wanted: all of them, unless its job is in skip -
        // the rows cleared in the window, or -Skip of a scripted run. The keys
        // in skip are matched as they are spelt.
        public bool IsWanted(ICollection<string> skip, string part)
        {
            return !(skip != null && skip.Count > 0 && skip.Contains(KeyOf(part)));
        }

        // One state for a job out of the states of its changes.
        public static string JoinStates(IEnumerable<string> states)
        {
            List<string> s = states.Where(x => !Ps.Eq(x, "missing")).ToList();
            if (s.Count == 0) return "missing";
            foreach (string bad in new[] { "other version", "unknown" })
            {
                if (Ps.Contains(s, bad)) return bad;
            }
            List<string> distinct = Ps.Unique(s);
            if (distinct.Count == 1) return distinct[0];
            return "partly";
        }

        // Folds the changes into one row per job, in the order of the jobs.
        // A change no job claims keeps a row of its own at the end.
        public List<PatchItem> Merge(IList<PatchItem> items)
        {
            var result = new List<PatchItem>();
            foreach (string job in order)
            {
                List<PatchItem> parts = items.Where(i => Ps.Eq(KeyOf(i.Key), job)).ToList();
                if (parts.Count == 0) continue;
                List<string> files = Ps.Unique(parts.Select(p => Ps.Split(p.Where, " at ")[0]));
                string where = files.Count <= 2
                    ? string.Join(", ", files)
                    : parts.Count + " changes in " + files.Count + " files";
                result.Add(new PatchItem
                {
                    Group = jobs[job].Group, Key = job, What = jobs[job].What, Where = where,
                    State = JoinStates(parts.Select(p => p.State)),
                });
            }
            foreach (PatchItem it in items)
            {
                if (!jobs.ContainsKey(KeyOf(it.Key))) result.Add(it);
            }
            return result;
        }
    }

    // How far a long run is. The patch says how many steps there are and names
    // each as it starts; whoever shows it - the window - sets Show. Without it
    // the steps cost nothing.
    internal static class PatchSteps
    {
        public static int Total;
        public static int Done;
        public static Action<int, int, string> Show;

        public static void Start(int total)
        {
            Total = Math.Max(1, total);
            Done = 0;
        }

        public static void Step(string text)
        {
            Done++;
            if (Show != null) Show(Done, Total, text);
        }
    }
}
