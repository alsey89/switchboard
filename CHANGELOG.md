# Changelog

What changed in each release, and anything you need to do about it.

## Unreleased

### Fixed

- **Upgrading no longer stops Switchboard.** `brew upgrade` was shutting down
  the background service and asking for your password to do it. Your sites
  stopped loading until you reinstalled the service by hand. Upgrades now
  leave it running.

  This fix only takes effect from the *next* upgrade onward, because the
  version you upgrade away from is the one that decides what happens. So one
  more upgrade will still stop the service. If your sites stop loading right
  after upgrading, run `switchboard daemon install` and you are back.

### Changed

- `brew uninstall` now leaves the background service alone. To remove
  everything Switchboard put on your machine, run `switchboard uninstall`
  first. Homebrew cannot remove the privileged parts on its own.

## 0.2.1

### Fixed

- **Changing a port is one command.** `switchboard add app 3001` now points
  `app.test` at the new port instead of refusing because the name already
  exists. It tells you what it replaced, so a typo does not look like a fresh
  route.

  ```
  $ switchboard add app 3001
  https://app.test → 127.0.0.1:3001 (was 127.0.0.1:3000)
  ```

- **`switchboard daemon status` tells you whether it is actually working.** It
  used to report `running` whenever the background job existed, even when
  Switchboard was crash-looping and serving nothing. It now checks that
  something is really answering, and says which part is broken.

- **Upgrades tell you when the background service is out of date.** After
  `brew upgrade`, everyday commands print one line if the running service is
  still an older build, along with the command that updates it. Previously
  only `switchboard doctor` knew, so it was easy to upgrade for a fix and hit
  the same bug.

## 0.2.0

First public release. macOS only.

- Local domains with real HTTPS: `switchboard add app 3000` gives you
  `https://app.test` with a green padlock and no certificate warnings.
- No `/etc/hosts` editing and no root proxy. A small parent process binds
  `:443` and `:80` and immediately drops to your user.
- `switchboard setup` does the whole job in one command: the local
  certificate authority, the DNS resolver, trusting the certificate, and
  installing the background service.
- `switchboard uninstall` removes all of it.
- `switchboard doctor` diagnoses setup, port and upstream problems.
- Install with `brew install alsey89/tap/switchboard`.
