# Testing the Windows service

The service runs as SYSTEM and moves between Windows sessions, so it is tested
by hand, in a virtual machine or on a spare computer — not on a development
machine. This is the checklist. Each step says what to run and what should
happen; when something else happens, the two log files are what to send back.

## Setting up

* **The VM:** Windows 10 or 11, with a user account that is an administrator
  and a second, standard account (for step 6). The VM's network can be NAT
  or bridged; the steps below note where that matters.
* **The server:** run it on the host, or anywhere the VM can reach:

  ```bash
  nearhand-server serve --bind 0.0.0.0:4433 --key server.key
  ```

  Note the fingerprint it prints. From the VM, the server is at the host's
  address — on a NAT network, usually the address of the host's virtual
  adapter, which `ipconfig` on the host shows.
* **The agent:** either the MSI — from the latest CI run's *nearhand-agent-msi*
  artifact, or built on the host with `packaging\windows\build-msi.ps1` —
  or the bare `nearhand-agent.exe` (`cargo build --release -p
  nearhand-agent`), copied into the VM to `C:\Program Files\Nearhand\`: the
  service runs it from where it was installed. Step 1 has both ways; the
  rest is the same.
* **The viewer:** on the host, `target\release\nearhand-viewer.exe`.

The logs are in the VM, in `C:\ProgramData\Nearhand\logs\`: `service.log`
(the service) and `agent.log` (the agent it runs in the console session).
Both need an administrator to read them.

## 1. Install

**With the MSI**, in an administrator terminal in the VM:

```bat
msiexec /i nearhand-agent-0.1.0-x64.msi /l*v install.log SERVER=<host address>:4433 SERVER_FINGERPRINT=<fingerprint> ACCESS_PASSWORD=<password>
```

* Windows warns that the MSI is unsigned; that is expected for now.
* It installs to `C:\Program Files\Nearhand`, and `sc query Nearhand` says
  `RUNNING`. `sc qfailure Nearhand` lists three restarts.
* `install.log` must **not** contain the password: search it for the
  password itself. Only `**********` should appear where it was.
* Without the three properties, on a machine never configured, it refuses
  to install and says which properties it needs.
* `nearhand-agent status` (as administrator, in `C:\Program Files\Nearhand`)
  shows the ID.

The checks under *Either way* below apply too. Later, check an upgrade: build a copy with the version raised in `crates\agent\Cargo.toml`,
run `msiexec /i` on it with **no** properties, and the ID stays the same.
Uninstalling from *Installed apps* removes the service and the program, and
keeps `C:\ProgramData\Nearhand`.

**Without the MSI**, in an administrator terminal in the VM:

```bat
cd "C:\Program Files\Nearhand"
nearhand-agent install --server <host address>:4433 --server-fingerprint <fingerprint>
```

* It asks for the access password twice, without showing it, and refuses
  one shorter than 10 characters.
* It prints the ID, and says it installed.
* `sc query Nearhand` says `RUNNING`.

**Either way:**

* `icacls C:\ProgramData\Nearhand` lists only `NT AUTHORITY\SYSTEM` and
  `BUILTIN\Administrators`.
* `service.log` has `service running` and `agent started`; `agent.log` has
  `registered with the server`.
* Running `nearhand-agent status` in a terminal that is *not* an
  administrator's cannot read the ID; as administrator, it shows it.

## 2. Connect

On the host:

```bash
nearhand-viewer connect <ID> --server <address>:4433 --server-fingerprint <fingerprint> --password "<access password>"
```

* The window shows the VM's desktop, as signed in; mouse, keyboard and
  clipboard work.
* The viewer's first line says whether it connected directly or through the
  relay. On a NAT network either can happen; a relayed connection is fine.
* `agent.log` has `viewer connected` and, when the viewer closes, `viewer
  left`.

## 3. Wrong passwords

Connect five times with a wrong password, then once with the right one.

* The first five are refused with "wrong password".
* The sixth is refused with "too many wrong passwords; try again later",
  although it is right.
* After 30 seconds the right password works again.

## 4. Change the password

```bat
nearhand-agent set-password
```

* The service restarts (`service.log`: `service stopped`, then `service
  running`); the ID does not change.
* The old password is refused; the new one works.

## 5. Sign out, and back in

With a viewer connected, sign out of the VM.

* The viewer's session ends. `service.log` shows the agent moving to the
  sign-in screen's session (`moving the agent`, `agent started` with a new
  session number).
* The device stays reachable: connecting again shows the sign-in screen.
  Sign in from the viewer — click, type the password — and the viewer
  follows onto the desktop without reconnecting. `service.log` shows the
  agent moving again; `agent.log` has `followed the input desktop`.

## 6. Switch users

Sign in as the second account with *Switch user*, leaving the first signed
in.

* The agent moves to the second account's session, and a viewer sees that
  desktop.
* Switching back moves it back.

## 7. Restart the VM

* After the restart, before anyone signs in, `sc query Nearhand` says
  `RUNNING`, `agent.log` shows it registered, and connecting shows the
  sign-in screen, which the viewer can use to sign in.
* After signing in, the viewer follows onto the desktop.

## 8. The secure desktop, in a session

With a viewer connected to the signed-in desktop:

* **UAC:** start something as administrator from the viewer (right-click a
  terminal, *Run as administrator*). The viewer shows the UAC prompt, and
  clicking *Yes* in the viewer works. Afterwards the picture comes back to
  the desktop by itself. `agent.log` shows `followed the input desktop` to
  `Winlogon` and back to `Default`.
* **Lock:** press Win+L in the VM itself (Windows does not take Win+L from
  injected input), or choose *Lock* on the Ctrl+Alt+Del screen below. The
  viewer shows the lock screen; unlocking from the viewer brings back the
  desktop.
* **Ctrl+Alt+Del:** in the viewer, press Ctrl+Alt+End. The VM shows its
  Ctrl+Alt+Del screen (Lock, Switch user, Sign out, Task Manager), in the
  viewer too; Esc goes back. If nothing happens, check that
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  has `SoftwareSASGeneration` set to 1 or 3 — `install` sets it — and send
  `agent.log`.
* **Elevated windows:** with an administrator terminal in front, typing into
  it from the viewer works (the portable agent cannot do this).

For comparison, the portable agent run as a normal user (`nearhand-agent
portable ...`): on a UAC prompt its viewer keeps the last picture and
input does nothing, and when the prompt closes, the picture resumes — the
session is not lost. Its log, in the terminal it was started from, says
`cannot capture this desktop; waiting`.

## 9. The session indicator

With the viewer connected to the signed-in desktop:

* A small red window, *Nearhand — remote session*, says the computer is
  being controlled remotely, by whom, and for how long. It stays on top.
* It cannot be closed: it has no close button, and Alt+F4 on it does
  nothing. Minimising it (Win+D) brings it back.
* *End session* ends the viewer's session, with the viewer saying "ended by
  the person at the device"; the window goes away.
* With no session, it is not shown — also right after signing in.
* If it never appears, `agent.log` says why (`no session indicator`) —
  likely graphics the VM cannot provide. Note which.

## 10. Stop and uninstall

```bat
sc stop Nearhand
```

* Within a few seconds `service.log` has `service stopped`, and no
  `nearhand-agent.exe` is left running (Task Manager, *Details*).
* A connected viewer is told the agent stopped, rather than freezing.

```bat
nearhand-agent uninstall
nearhand-agent install --server ... --server-fingerprint ...
```

* After uninstalling, `sc query Nearhand` says the service does not exist,
  and `C:\ProgramData\Nearhand` is still there. Installing again keeps the
  same ID.
* `nearhand-agent uninstall --purge` also removes `C:\ProgramData\Nearhand`;
  the next install gets a new ID.

## Also worth checking while the VM is up

M2 has not yet been tested across two real networks. With the VM on a NAT
network, the portable agent in the VM and the viewer on the host are on
different networks:

```bat
nearhand-agent portable --server <host address>:4433 --server-fingerprint <fingerprint>
```

* The window shows an ID and password; connecting from the host asks in the
  VM to allow the session.
* Whether it connected directly or through the relay, and the round-trip
  time the viewer prints, are worth writing down.
