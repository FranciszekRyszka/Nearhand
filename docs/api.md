# REST API

> **Status: M5–M6.** Accounts, tokens, devices, groups, enrollment, grants,
> the audit log, agent releases, and the web viewer's way in. The web
> console at `/` is built on this API alone.

Everything is under `/api/v1` on the server's HTTPS port, JSON in and out.
Errors are `{"error": "..."}` with a fitting status code.

## Authenticating

- **Scripts:** `Authorization: Bearer nht_...`, with a token from
  `POST /me/tokens`.
- **The console:** the `nearhand_session` cookie that `POST /login` sets.
  Requests that change something with it must come from the server's own
  pages: a browser's `Origin` naming another host is refused.

## Endpoints

| Method and path | Who | What |
| --- | --- | --- |
| `GET /health` | anyone | `{"ok": true, "version": "..."}` |
| `POST /setup` | anyone with the setup token | `{token, name, password}`: the first administrator; refused once there are users |
| `POST /login` | anyone | `{name, password, totp?}`: sets the session cookie. 401 with `"totp_needed": true` when a code is needed; 429 after too many wrong passwords |
| `POST /logout` | signed in | ends the session |
| `GET /me` | signed in | `{id, name, admin, totp, disabled}` |
| `POST /me/password` | signed in | `{current, new}`; ends every console sign-in of this account |
| `POST /me/totp` | signed in | starts TOTP: `{secret, uri}` for the authenticator app |
| `POST /me/totp/confirm` | signed in | `{code}`: turns TOTP on |
| `POST /me/totp/disable` | signed in | `{code}`: turns it off |
| `GET /me/tokens` | signed in | this user's API tokens (never the tokens themselves) |
| `POST /me/tokens` | signed in | `{name, expires_in_days?}`: `{token, details}`; the token is shown this once |
| `DELETE /me/tokens/{id}` | signed in | deletes one |
| `GET /users` | administrators | every user |
| `POST /users` | administrators | `{name, password, admin?}` |
| `PATCH /users/{id}` | administrators | `{admin?, disabled?}`; disabling ends their sign-ins |
| `DELETE /users/{id}` | administrators | deletes a user; not the last active administrator |
| `GET /server` | signed in | `{address, fingerprint}`: what agents and viewers need to reach and pin this server |
| `GET /devices` | signed in | enrolled devices — all of them for administrators, else those the user's grants reach: `{id, device_id, fingerprint, name, group_id, group, os, version, enrolled_at, last_seen_at, last_address, online, role}`, `role` being the caller's (`null` if none) |
| `GET /devices/{id}` | signed in | one device, likewise; 404 for one the caller may not see |
| `PATCH /devices/{id}` | administrators | `{name?, group_id?}`; `group_id: null` takes it out of its group |
| `DELETE /devices/{id}` | administrators | removes it from the list; a new token enrolls it again |
| `GET /device-groups` | administrators | `{id, name, devices}`, `devices` being how many |
| `POST /device-groups` | administrators | `{name}` |
| `PATCH /device-groups/{id}` | administrators | `{name}` |
| `DELETE /device-groups/{id}` | administrators | its devices stay, in no group; tokens into it are deleted |
| `GET /enroll-tokens` | administrators | tokens that still enroll (never the tokens themselves) |
| `POST /enroll-tokens` | administrators | `{name, group_id?, uses?, expires_in_days?}`: `uses` is 1 unless given, `null` for any number; 1 day unless given, at most 90. Answers `{token, details, install, msi}`: the token and the commands that use it, shown this once |
| `DELETE /enroll-tokens/{id}` | administrators | deletes one |
| `GET /user-groups` | administrators | `{id, name, members: [{id, name}]}` |
| `POST /user-groups` | administrators | `{name}` |
| `PATCH /user-groups/{id}` | administrators | `{name}` |
| `DELETE /user-groups/{id}` | administrators | deletes it and its grants; its members stay |
| `PUT /user-groups/{id}/members/{user}` | administrators | adds a user |
| `DELETE /user-groups/{id}/members/{user}` | administrators | removes one |
| `GET /grants` | administrators | `{id, user_group_id, user_group, device_group_id, device_group, role}` |
| `POST /grants` | administrators | `{user_group_id, device_group_id, role}`, role `view`, `control` or `full`; sets the role if the two have a grant already |
| `DELETE /grants/{id}` | administrators | deletes one |
| `POST /devices/{id}/grant` | signed in | a grant for the caller on that device, for the web viewer: `{device_id, fingerprint, role, grant}`, `grant` the signed grant in hex; 404 without one |
| `GET /relay` | signed in | a WebSocket, from the console's own origin: the web viewer's session when WebTransport or UDP is not there. The first message asks to be introduced (`Connect`), the answer comes back as one message, and every message after that is one packet of the session |
| `GET /webtransport` | signed in | `{url, certificate_hashes}`: where the web viewer's WebTransport goes, and the SHA-256 (hex) of the certificate to accept when it is self-signed |
| `GET /audit?before=&limit=` | administrators | newest first, `limit` up to 500 (100 unless given); `before`, an entry's id, pages back: `{id, at, actor, address, action, target, detail}` |
| `GET /releases` | administrators | agent releases held: `{id, product, platform, version, package, sha256, size, uploaded_at, offered}` |
| `POST /releases` | administrators | `multipart/form-data` with fields `package` (the MSI) and `signature` (its `.release` file); 400 unless the project's release key signed it and the package is the one signed |
| `POST /releases/{id}/offer` | administrators | offers it to agents of its product and platform older than it, in place of any other |
| `DELETE /releases/{id}/offer` | administrators | stops offering it |
| `DELETE /releases/{id}` | administrators | deletes it and its package; not while it is offered |

Connecting with a grant is not over this API: the viewer asks on the QUIC
side, with an API token (`docs/protocol.md`).

Times are Unix seconds.

## Example

```bash
# Sign in once in a browser or with curl, make a token, then:
curl https://desk.example.com/api/v1/users -H "authorization: Bearer nht_..."
```
