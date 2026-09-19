# REST API

> **Status: M5, in progress.** Accounts and tokens so far; devices, groups,
> grants and the audit log follow.

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

## Example

```bash
# Sign in once in a browser or with curl, make a token, then:
curl https://desk.example.com/api/v1/users -H "authorization: Bearer nht_..."
```
