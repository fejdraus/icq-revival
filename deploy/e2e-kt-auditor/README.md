# An auditor of the key log, on a machine of its own

What it takes to run `cmd/e2e-kt-auditor` on any Linux machine with systemd
(Debian, Ubuntu and the like; x86_64 or arm64). Background:
[docs/e2e/KEY-TRANSPARENCY.md](../../docs/e2e/KEY-TRANSPARENCY.md), stage 2.

## What an auditor is

The server keeps an append-only, signed log of every change in the E2E key
directory. An auditor follows that log from outside: every minute it reads
what was appended, checks that the log only grew and that every entry keeps
the directory's rules (a device signed by its account key, a rotation proved
by the old key, and so on), and if all is well it cosigns the log's
checkpoint and hands the cosignature to the server. The E2E add-on takes the
log only when the auditors it trusts agree with its own copy, and warns when
none has cosigned for an hour. A server that shows one user a log of its own
is caught by the first auditor that was shown the real one.

An auditor needs **outbound HTTPS to the server and nothing else**: it opens
no port, and the unit forbids it to (`SocketBindDeny=any`). It works behind
NAT, on a home connection, anywhere.

If the log ever breaks a rule, the auditor logs `KEY LOG VIOLATION`, never
cosigns that log again, and exits with status 3; the unit then stays failed
(`RestartPreventExitStatus=3`) for whoever watches it to see.

## Files

| File | What it is |
|------|------------|
| `install.sh` | Installs or updates the auditor (below). |
| `e2e-kt-auditor.service` | The systemd unit: its own system user, `StateDirectory`, no capabilities, read-only system, no inbound ports. |
| `dist/` (not in git) | The binaries `e2e-kt-auditor-linux-amd64` and `-arm64`, with copies of the two files above: what is copied to the machine. |

Build `dist/` on any machine with Go (static binaries, no CGO):

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o deploy/e2e-kt-auditor/dist/e2e-kt-auditor-linux-amd64 ./cmd/e2e-kt-auditor
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o deploy/e2e-kt-auditor/dist/e2e-kt-auditor-linux-arm64 ./cmd/e2e-kt-auditor
cp deploy/e2e-kt-auditor/install.sh deploy/e2e-kt-auditor/e2e-kt-auditor.service deploy/e2e-kt-auditor/dist/
```

## Installing

1. Copy `install.sh`, `e2e-kt-auditor.service` and the binary for the
   machine (`uname -m`: `x86_64` is amd64, `aarch64` is arm64) into one
   folder on it.
2. Run, with the server's domain and a name for this auditor:

   ```
   sudo sh install.sh icq.example.org auditor-2.example.net/icq
   ```

   The name is a schema-less URL without spaces or plus signs. **Every user
   sees it** in `/e2e status` ("audited by auditor-2.example.net/icq (1 min
   ago)"), so pick one that says nothing you would rather keep to yourself -
   not a home machine's host name. It is part of the key: it cannot change
   later without a new key.
3. The script puts the binary in `/usr/local/bin/e2e-kt-auditor`, makes the
   system user `e2e-kt-auditor`, writes `/etc/e2e-kt-auditor.env` (the
   server's URL, `https://<domain>:8102/e2e/v1/`, and the name), makes the
   key on the first run, enables and starts the unit, and prints the
   auditor's **verifier key**, a line like

   ```
   auditor-2.example.net/icq+1a2b3c4d+BJ3...
   ```

   That line goes to the server's operator. Until the server has it, each
   look ends in `not cosigned this time ... 403`; that is expected.

Running `install.sh` again with the same name updates the binary and the unit
and keeps the key. `journalctl -u e2e-kt-auditor -f` shows what it does;
`systemctl status e2e-kt-auditor` whether it runs.

## The key: back it up

The auditor's identity is `/var/lib/e2e-kt-auditor/auditor.key`, a 32-byte
Ed25519 seed readable only by the `e2e-kt-auditor` user. **Copy it somewhere
off the machine** (an encrypted backup, a password manager):

```
sudo cat /var/lib/e2e-kt-auditor/auditor.key | base64
```

Lost, it cannot be made again: the auditor needs a new key and a new line on
the server, and every client that pinned the old key shows it as silent from
then on (the other auditors still vouch). To move the auditor to another
machine (or bring it back after a reinstall), run `install.sh` there with the
same name, then `sudo systemctl stop e2e-kt-auditor`, put the saved key in
place (`base64 -d`, owned by `e2e-kt-auditor`, mode 0600) and start it again;
the journal's first line names the same verifier key as before.

`/var/lib/e2e-kt-auditor/auditor.json` is what the auditor has checked so
far. It needs no backup: without it the auditor reads the whole log again.
It does hold a violation once one was found - keep it then, it is the
evidence.

## On the server: adding the key

`E2E_KT_AUDITORS` is a comma-separated list of verifier keys; the server
accepts cosignatures only from those, and lists them all on
`GET /e2e/v1/log/auditors`. With the container deployment
(`deploy/docker-compose.yaml`):

1. Add the new line to `E2E_KT_AUDITORS` in `deploy/.env` on the production
   machine, after a comma, keeping the keys already there:

   ```
   E2E_KT_AUDITORS=auditor-1.example.net/icq+...,auditor-2.example.net/icq+...
   ```

2. Redeploy the server so it reads `.env` again (the owner's procedure is in
   `deploy/OPERATIONS.md`; in general `docker compose up -d` recreates the
   server container with the new environment).
3. Check: `curl https://<domain>:8102/e2e/v1/log/auditors` lists every key,
   and within a minute or two `GET /e2e/v1/log/cosigned` holds one checkpoint
   per auditor.
4. Apply the ICQ 6.5 / 7.2 patch again on each client: it reads the list at
   Apply and pins the new keys next to the old ones (the message box lists
   what it added). Clients without the patch's `auditors =` line keep only the
   auditors they pinned on first use, until `/e2e resetlog`.

## Removing

```
sudo systemctl disable --now e2e-kt-auditor
sudo rm /etc/systemd/system/e2e-kt-auditor.service /etc/e2e-kt-auditor.env /usr/local/bin/e2e-kt-auditor
sudo systemctl daemon-reload
```

`/var/lib/e2e-kt-auditor` (the key) stays until removed by hand. Take its
key out of `E2E_KT_AUDITORS` too; clients that pinned it show it as silent,
which costs nothing while another auditor vouches.

## What it does not protect against

Auditors that the server's operator runs - wherever they are - check that
the log keeps its rules and that everyone is shown the same log, but they do
not protect anyone against the operator: whoever holds their keys can cosign
anything. Several of them on different machines, networks and providers make
the auditing survive the loss or takeover of one machine, and a server taken
over by someone else is caught by any of them. Protection against the
operator needs an auditor someone else runs, on a machine the operator cannot
touch.
