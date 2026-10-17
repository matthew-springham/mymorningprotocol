# My Morning Protocol

www.mymorningprotocol.com, hosted on Hostinger (Node.js Web App + MySQL).

- `index.html`: the whole front end. Signed-out visitors see the sample-data preview; signed-in members see their own protocol and live WHOOP readings.
- `server.js`: Node/Express server, with email + password accounts, sessions, saved protocol and logs, and the WHOOP connection.
- `whoop.js`: WHOOP OAuth 2.0 and v2 API client.

## Hostinger setup

1. **Databases → MySQL**: create a database and user. Note the database name, username, password and host.
2. **Websites → Add website → Node.js Web App**: import from GitHub (`matthew-springham/mymorningprotocol`, branch `main`).
   - Framework: Express (or "Other"). Entry file `server.js`, start command `npm start`, Node 20 or newer.
3. Environment variables:

| Key | Value |
|---|---|
| `DB_HOST` | MySQL host from Hostinger (often `localhost`) |
| `DB_USER` | MySQL username |
| `DB_PASSWORD` | MySQL password |
| `DB_NAME` | MySQL database name |
| `APP_URL` | `https://www.mymorningprotocol.com` |
| `TOKEN_ENCRYPTION_KEY` | Optional. Encrypts stored WHOOP tokens; if unset, a random key is generated once and kept in the database |
| `WHOOP_CLIENT_ID` | From the WHOOP Developer Dashboard |
| `WHOOP_CLIENT_SECRET` | From the WHOOP Developer Dashboard |

The database tables are created automatically when the server starts. A health check runs at `/healthz`.

## WHOOP Developer Dashboard

Create an app at https://developer-dashboard.whoop.com with:

- Redirect URL: `https://www.mymorningprotocol.com/auth/whoop/callback`
- Scopes: `offline`, `read:profile`, `read:recovery`, `read:cycles`, `read:sleep`, `read:workout`, `read:body_measurement`
