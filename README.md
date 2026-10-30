# Aimap

A from-scratch IMAP4rev2 ([RFC 9051](https://www.rfc-editor.org/rfc/rfc9051)) server for OpenBSD, written by Claude AI in C in the privilege-separated tradition of `smtpd(8)`, `httpd(8)`, and `ntpd(8)`. No third-party IMAP library.

**Status:** 0.0.1 Pre-release. Not in the OpenBSD ports tree.

## What it is

- **Written by Claude AI**
- **Privilege-separated**: `smtpd`-style, across six processes: a root *parent* reads configuration and binds the listening sockets; unprivileged *listener* and *auth* children handle the network and credential checks; *keymgr* holds the TLS private key and performs every private-key operation on request, so the process terminating TLS never has the key in its address space; a *parser* child, forked by *parent* when a *store* child asks for one and retired after a spell idle, does every parse of attacker-reachable content — `SEARCH`'s grammar and `FETCH`'s `ENVELOPE`/`BODYSTRUCTURE`/header-field parsing alike — confined to `pledge(2)` `"stdio recvfd"`: it opens nothing itself, reading each message over a descriptor the store child passes it already open; and a *store* child is forked per authenticated account, shared by all of that account's sessions, chroots into the mail spool, and drops privileges to that account's own user before ever touching a message. `pledge(2)`, `unveil(2)`, and `chroot(2)` enforce these boundaries, not just convention: only *parent* and *store* can pass a file descriptor, *parent* to hand each child its channels and *store* to give *listener* and *parser* a message already open.
- **Storage**: stock maildir format (`tmp/`/`new/`/`cur/`, atomic delivery via `rename(2)`), readable with `ls` and `grep`, and natively understood by `smtpd(8)`'s own `maildir` delivery action. IMAP's extra bookkeeping (UIDs, UIDVALIDITY, per-message mod-sequences, keywords) lives in a small, `flock(2)`-guarded, line-oriented index file per mailbox, plain colon-delimited text, not a database.
- **Transport**: STARTTLS on port 143 and implicit TLS on port 993 ([RFC 8314](https://www.rfc-editor.org/rfc/rfc8314)), via `libtls`. `AUTH=PLAIN` only, refused before TLS is established.

## Protocol coverage

`CAPABILITY`, `STARTTLS`, `AUTHENTICATE`, `ID`, `ENABLE`, `SELECT`, `EXAMINE`, `CREATE`, `DELETE`, `RENAME`, `LIST`, `LSUB`, `NAMESPACE`, `STATUS`, `FETCH` (including `ENVELOPE`, `BODYSTRUCTURE`, and MIME-part-addressed `BODY[<part>]`/`BODY.PEEK[<part>]`), `STORE`, `SEARCH` (including `RETURN (SAVE)` and the `$` saved-result-set marker, [RFC 5182](https://www.rfc-editor.org/rfc/rfc5182), folded into RFC 9051), `APPEND`, `COPY`, `MOVE`, `EXPUNGE`, `UNSELECT`, `CLOSE`, `SUBSCRIBE`, `UNSUBSCRIBE` (including LIST's [RFC 9051](https://www.rfc-editor.org/rfc/rfc9051) section 6.3.9.1 `SUBSCRIBED` selection option), the `UID`-prefixed form of every command that supports it, `IDLE` (with the cross-session caveat noted below), and the [RFC 7162](https://www.rfc-editor.org/rfc/rfc7162) `CONDSTORE`/`QRESYNC` extensions.

ACL/shared-mailbox support is deliberately left out.

**`IDLE` is a poll, not a kernel-driven push.** An `IDLE`ing session rechecks its selected mailbox every `idle poll` seconds (default 5, see `aimap.conf`), so new mail, whether delivered by an external MTA or by another IMAP session, is reported within one interval rather than instantly. Most polls are two `stat(2)` calls and no lock: the store child only re-reads the index and streams UIDs when the mailbox directory or `new/` has actually been touched. Setting `idle poll 0` disables polling entirely, which restores the earlier behaviour where an `IDLE`ing session saw nothing until it sent `DONE`.

## Requirements

OpenBSD only. This depends on `<imsg.h>`, `pledge(2)`, `unveil(2)`, and libutil's `imsgbuf_*` API, none of which exist outside OpenBSD. Links against libevent, libtls/libssl/libcrypto, and libutil, all base-system libraries.

**aimap requires OpenBSD 8.0.**

`keymgr`, the process that keeps the TLS private key out of the `listener` workers, relies on two parts of libtls that are not public API:

- `tls_config_use_fake_private_key()`. libtls exports it, but it is not declared in the installed `tls.h`; libtls keeps it visible for base-system daemons such as relayd and smtpd, so aimap declares it itself.
- libtls's undocumented tagging of the placeholder key: it stores a hash of the certificate's public key in ex_data slot 0 of the RSA or EC key object (currently in `tls_keypair_setup_pkey()` in `lib/libtls/tls.c`), which aimap reads to route each private-key operation to `keymgr`.

Neither has any compatibility promise, so a libtls change in a future OpenBSD release or patch could break TLS in aimap.

## Building and installing

```
cd src
make
doas make install
```

Installs the daemon to `/usr/local/sbin/aimap`, man pages to `/usr/local/man/man5` and `/usr/local/man/man8`, and a sample config to `/usr/local/share/examples/aimap/aimap.conf`.

The `rc.d(8)` script is not installed automatically. `install(1)`, not `cp(1)`, so the installed copy is executable regardless of the source tree's own permission bits:

```
doas install -o root -g wheel -m 555 src/rc.d/aimap /etc/rc.d/aimap
```

## Building a package locally

As an alternative to `make install` above, `port/mail/Aimap` is an unofficial OpenBSD port that builds aimap as a package from the release tarball on GitHub. It is not in the OpenBSD ports tree. It needs a checked-out ports tree in `/usr/ports`.

Copy the port into your own ports directory:

```
mkdir -p /usr/ports/mystuff/mail
cp -R port/mail/Aimap /usr/ports/mystuff/mail/
cd /usr/ports/mystuff/mail/Aimap
```

The package creates the `_aimap` and `_aimapauth` users and groups with fixed IDs, and `pkg_create(1)` refuses to build it unless both names are registered, with the same IDs, in `/usr/ports/infrastructure/db/user.list`. `pkg/PLIST` uses 908 and 909, which were free on the system the port was written on but may not be on yours. Check:

```
tail -3 /usr/ports/infrastructure/db/user.list
grep -E '^90[89] ' /usr/ports/infrastructure/db/user.list
```

If the `grep` prints anything, choose two free IDs instead and change them on the four `@newgroup` and `@newuser` lines in `pkg/PLIST`. Then register the names, using the IDs from `pkg/PLIST`:

```
printf '908 _aimap\t\t_aimap\t\tmail/aimap\n909 _aimapauth\t\t_aimapauth\tmail/aimap\n' \
    | doas tee -a /usr/ports/infrastructure/db/user.list
```

These lines are a local change to your ports tree. Check that they are still there after updating the tree, since a later update to `user.list` can conflict with them or claim the same IDs.

Build and install the package:

```
make package
make install
```

`make install` needs root; set `SUDO=doas` in `/etc/mk.conf` (see `bsd.port.mk(5)`) or run it as root. If aimap was already installed by hand with `make install` from `src/`, `pkg_add(1)` will refuse to overwrite those files: remove `/usr/local/sbin/aimap`, the two man pages, `/usr/local/share/examples/aimap/aimap.conf` and `/etc/rc.d/aimap` first. An existing `/etc/aimap.conf` and existing `_aimap`/`_aimapauth` accounts are left as they are.

The package installs the `rc.d(8)` script and creates the daemon accounts, so the "Creating the daemon accounts" step below is not needed. Its readme is installed as `/usr/local/share/doc/pkg-readmes/aimap`.

## Configuring

Copy the sample config into place with restrictive permissions. aimap refuses to start against a config with the wrong owner or mode; `aimap.conf(5)` says which are required:

```
doas install -o root -g wheel -m 600 \
    /usr/local/share/examples/aimap/aimap.conf /etc/aimap.conf
```

Every directive is documented inline in the sample file; the full reference is `aimap.conf(5)`.

## Creating the daemon accounts

aimap drops privileges to two accounts of its own and will not start until both exist. Create them once, before the first mailbox account, since the credentials file belongs to the `_aimapauth` group:

```
doas useradd -c "IMAP Daemon" -d /var/empty -s /sbin/nologin _aimap
doas useradd -c "IMAP Auth" -d /var/empty -s /sbin/nologin _aimapauth
```

Each runs in a group of its own name, which `useradd(8)` creates by default unless `/etc/usermgmt.conf` sets `group` otherwise.

## Creating an account

aimap's users aren't real system accounts. Each has a line in two `table(5)` files: the credentials file (`username $2b$...`, bcrypt via `crypt_checkpass(3)`) and the userbase file (`username uid:gid:/var/mail/aimap/username`). `smtpd(8)` can read the same two files as an `auth` table and a `userbase` table, so one copy serves both daemons; see "Mail delivery" in `aimap.conf(5)`. The EXAMPLES section of `aimap.conf(5)` shows how to add an account, with its maildir, and how to remove one.

## Running

```
doas rcctl enable aimap
doas rcctl start aimap
```

## Known limitations

- If the keymgr process, which holds the TLS private key, exits unexpectedly, it is not restarted and new TLS handshakes fail. Recovery is `rcctl restart aimap`. See `aimap(8)`.

`SIGHUP` rereads the configuration without dropping connected sessions. `aimap.conf(5)` says which settings need a restart.

aimap listens on both IPv4 and IPv6 by default (`listen on *`); use `listen on 0.0.0.0` for IPv4 only or `listen on ::` for IPv6 only. See the `listen on` directive in `aimap.conf(5)`.

## License

All of Aimap’s code was generated by Claude, an AI model, with no human authorship. Under U.S. law, as stated in Thaler v. Perlmutter (D.C. Cir. 2025) and the Copyright Office’s 2025 report on AI copyrightability, it is not protected by copyright. Some files contain code adapted from the OpenBSD base system. Those portions keep their original copyright notices and ISC or BSD licenses, which appear in the files’ headers. CREDITS says what was borrowed from where.

## More

`aimap(8)` and `aimap.conf(5)` are the authoritative technical reference.
