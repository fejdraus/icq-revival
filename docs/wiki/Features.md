# Features

[← Wiki home](Home.md)

What ICQ Revival adds to [Open OSCAR Server](https://github.com/mk6i/open-oscar-server).

## On the server

- [x] Both ICQ profile dialects. ICQ 99-2003 ask for a profile one way, ICQ 6
      and everything modelled on it (QIP 2012, Miranda's MDir) another way; the
      client chooses, so the server understands both, and a profile saved in one
      reads correctly in the other.
- [x] Profile and directory search for ICQ 6.5, QIP 2012 and Miranda NG, in
      the reply layout each of them expects.
- [x] Extended profiles: marital status, origin city, verified and login
      e-mail, and tolerant parsing of what older clients send.
- [x] Signing in with an e-mail address instead of a number, as the "ICQ#/Email"
      field of the old login windows promises.
- [x] A new number from inside the client - "Get an ICQ Number" in ICQ 2003b.
- [x] Random chat: joining an interest group and being matched with someone.
- [x] Authorization answers that reach the person who asked, whichever client
      they use.
- [x] Buddy pictures every client can show: a picture too big or in a format
      an older client cannot read is handed to it scaled down, and the still of
      an ICQ 6 Flash avatar replaces it for clients that cannot play Flash.
- [x] STUN and an optional TURN relay for ICQ 6.5 voice and video calls.

## Around the server (`deploy/`)

- [x] Registration site: pick a number, set a password, attach an e-mail for
      recovery, change your number or close the account. English and
      Ukrainian, in the look of the Windows 98 era.
- [x] Admin panel: users, passwords, blocking, sessions.
- [x] Replacements for the ICQ.com pages the clients still open - the welcome
      window, "who is online", white pages, the web pager, help - and the page
      ICQ 6.5 uses to set your picture, with the image scaled to what the
      client can show, an animated avatar gallery and an avatar constructor.
- [x] A download page for the client patches and the Miranda plugins, and an
      update mirror so Miranda's plugin updater keeps our plugins current.
- [x] A TLS front that still speaks SSLv3 and TLS 1.0 for the clients of the
      2000s, next to a modern certificate for everyone else.
- [x] Daily database backups.

## On the client side (`tools/`)

- [x] `ICQ-2003b-Patch.exe` for ICQ Pro 2003b: removes the banners and the
      Google bar, points the menu items that opened ICQ.com at your server,
      and can switch the interface to Ukrainian.
- [x] `ICQ-6.5-Patch.exe` for ICQ 6.5: removes the Xtraz, advertising, SMS and
      phone parts that have nothing behind them any more, points the pages the
      client opens at your server, and can bring tZers and Flash avatars back
      with a Flash-free player.
- [x] The ICQ protocol plugin for Miranda NG, which Miranda removed, ported to
      the current API, and a Flash avatar plugin for it.

Each patch backs up what it changes and restores it on request.
[tools/README.md](../../tools/README.md) lists them by client.
