# Clients

[← Wiki home](Home.md)

| Client | Status |
|---|---|
| ICQ Pro 2003b | Works fully, including getting a new number from the client and search |
| QIP 2005 (build 8092) | Works fully |
| QIP 2012 | Profiles, search and saving your own profile |
| ICQ 6.5 | Profiles, search, messages, setting your picture, Flash avatars, tZers, voice and video calls; the patch cleans up the interface |
| Miranda NG | Works, with the ICQ plugin brought back to the current Miranda API |
| AIM 7.5 | Signs in over TLS through Kerberos |
| ICQ 95-99 | Supported by the server over the legacy UDP protocol (v2-v5); not yet tried with real clients here |
| Everything Open OSCAR Server supports | AIM 1.x-7.x, ICQ 98-5, Pidgin, TOC clients - see [its documentation](https://github.com/mk6i/open-oscar-server#readme) |

ICQ 7 and later do not work: they reach the stage of signing in and stop at a
challenge the server does not answer yet. R&Q after 2019 dropped OSCAR
altogether.

## Connecting a client

The sign-in server is set in each client's own connection settings; the
patches set it for ICQ 2003b and ICQ 6.5 and take care of the rest. Clients of
the ICQ 2000b-5.1 and QIP 2005-2012 era know no encryption and need the plain
port with SSL switched off; clients that support SSL (Miranda NG, for one) can
use the SSL port.

What each client asks of the server, dialect by dialect, is written down in
[NOTES.md](../../NOTES.md). The client patches are listed in
[tools/README.md](../../tools/README.md).
