# Windows packaging

`agent.wxs` is the agent's MSI (WiX 5): it installs `nearhand-agent.exe` to
Program Files, registers the `Nearhand` service, and — given `SERVER`,
`SERVER_FINGERPRINT` and `ACCESS_PASSWORD` — runs `nearhand-agent configure`
to write the machine's configuration and key and allow Ctrl+Alt+Del:

```bat
msiexec /i nearhand-agent-0.1.0-x64.msi /qn SERVER=203.0.113.10:443 ^
    SERVER_FINGERPRINT=<fingerprint> ACCESS_PASSWORD=<password>
```

Upgrades and repairs need no properties: the configuration in
`%ProgramData%\Nearhand`, and with it the ID, stays. So it does on uninstall;
`nearhand-agent uninstall --purge` first removes it.

Build it with `build-msi.ps1` (WiX 5 and `WixToolset.Util.wixext` must be
installed; see the script). CI builds it on every push and keeps it as an
artifact.

Not yet: Authenticode signing. It is needed from the first public build,
against SmartScreen and antivirus false positives (SignPath offers free
signing for open source).
