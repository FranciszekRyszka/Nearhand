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

## 11. Enrollment (M5)

Everything here can also be done in the web console: open
`https://localhost/` on the host (the server prints a link for the first
administrator), and afterwards check the *Audit log* page lists each step.

On the host, with the server running (it serves the REST API on TCP 443
too), create the first administrator with
the command it printed, sign in, and make a token (`uses: 1`):

```bash
curl -k -c jar https://localhost/api/v1/login -H 'content-type: application/json' \
    -d '{"name": "admin", "password": "..."}'
curl -k -b jar https://localhost/api/v1/enroll-tokens -H 'content-type: application/json' \
    -d '{"name": "vm"}'
```

In the VM, reinstall with the token (and the server by name, if the VM can
resolve the host's):

```bat
nearhand-agent install --server <host address>:4433 --server-fingerprint <fingerprint> --token nhe_...
```

* It prints `Enrolled with the server.`; `GET /api/v1/devices` lists the VM
  under its computer name, `online: true`.
* `sc stop Nearhand`: within 15 seconds the device shows `online: false`
  and a fresh `last_seen_at`.
* Installing again with the same token fails: it was for one device.
* With the host's server stopped, install with a new token: it says it will
  enroll later. Start the server: within a few minutes the device is listed, and
  `C:\ProgramData\Nearhand\agent.toml` no longer has an `[enrollment]`
  section.

Then grants, with the VM enrolled into a device group (make the token with
`"group_id"`, or move the device with `PATCH /api/v1/devices/{id}`):

* Create a second user, a user group with them in it, and a grant from that
  group to the device group with role `view` (`docs/self-hosting.md#grants`).
  Sign in as that user and make an API token.
* `nearhand-viewer connect <ID> --server ... --server-fingerprint ... --token nht_...`
  prints `granted: view as <user>` and shows the screen; the indicator in
  the VM names the user. Typing and clicking do nothing in the VM.
* Change the grant to `control`: the next connection can type and click.
* Remove the user from the group: the next connection is refused by the
  server ("you have no grant for that device").
* `nearhand-agent set-password --none` in the VM: the access password no
  longer works, and grants still do. `nearhand-agent status` says so.
* In a browser on the host, the console's **View** beside the VM shows its
  screen. With a `control` grant, click it and type into Notepad in the
  VM: letters appear, Shift and AltGr work, scrolling scrolls. Ctrl+Alt+Del
  (the button) shows the VM's secure screen. Copy text in the VM: it pastes
  on the host; copy on the host and click the picture: it pastes in the
  VM.
* Adding `&transport=tcp` to that page's address takes the WebSocket
  instead of WebTransport: the same picture, and "over TCP" beside the
  frame rate. That is the way in for browsers without WebTransport, and
  the one to check on a network that blocks UDP.

## Updates

With a newer MSI built and signed (`nearhand-release sign --version <newer>
<msi>`, which needs the release key) and uploaded to the test server:

* `POST /api/v1/releases/<id>/offer`, then wait for the VM's agent to ask —
  or restart the service to make it ask five minutes later.
* `%ProgramData%\Nearhand\logs\agent.log` says "fetching an update" and
  "installing the update"; `update.log` is the installer's own.
* Afterwards *Installed apps* shows the new version, the service is running
  again, and the device's version in the console is the new one.
* With a session open from the viewer, the update waits: the log says so,
  and nothing is installed until the session ends.

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
