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
* **The agent:** build it on the host (`cargo build --release -p
  nearhand-agent`) and copy `target\release\nearhand-agent.exe` into the VM,
  to `C:\Program Files\Nearhand\` — the service runs it from where it was
  installed, so put it somewhere it will stay.
* **The viewer:** on the host, `target\release\nearhand-viewer.exe`.

The logs are in the VM, in `C:\ProgramData\Nearhand\logs\`: `service.log`
(the service) and `agent.log` (the agent it runs in the console session).
Both need an administrator to read them.

## 1. Install

In an administrator terminal in the VM:

```bat
cd "C:\Program Files\Nearhand"
nearhand-agent install --server <host address>:4433 --server-fingerprint <fingerprint>
```

* It asks for the access password twice, without showing it, and refuses
  one shorter than 10 characters.
* It prints the ID, and says it installed.
* `sc query Nearhand` says `RUNNING`.
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
* The device stays reachable: connecting again works, but **the sign-in
  screen itself is not expected to show yet** — capturing it is the next
  step of M3. Note what the viewer shows or says.
* Sign back in: `service.log` shows the agent moving again, and connecting
  shows the desktop.

## 6. Switch users

Sign in as the second account with *Switch user*, leaving the first signed
in.

* The agent moves to the second account's session, and a viewer sees that
  desktop.
* Switching back moves it back.

## 7. Restart the VM

* After the restart, before anyone signs in, `sc query Nearhand` says
  `RUNNING`, and `agent.log` shows it registered. (The sign-in screen does
  not show in the viewer yet; see step 5.)
* After signing in, connecting shows the desktop.

## 8. Stop and uninstall

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
