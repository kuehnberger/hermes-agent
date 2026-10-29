# Sharing one Google credential across all profiles

Status: ADOPTED 2026-10-21, kanban task t_01e08697. Fleet account `j@g`
(James Maria Jenkins). Verified live on Yoda and srv979961.

## When to Use

- More than one profile — local, or on another host — must use the **same** Google account.
- The credential must be reachable from every profile without copying the secret per profile.
- You are checking that a stored token is not world-readable, or setting up a new one.

## Why

A Google OAuth token is a bearer credential. The fleet should have **one** token, in
**one** place, with **one** set of permissions — and every profile should be able to
use it without copying secrets around. A per-profile copy means N rotations and a
revoked token that stays live in the profiles nobody remembered.

## Where the files live

`setup.py` computes its paths from `get_hermes_home()`:

```python
TOKEN_PATH         = HERMES_HOME / "google_token.json"
CLIENT_SECRET_PATH = HERMES_HOME / "google_client_secret.json"
```

`get_hermes_home()` returns the shared root `~/.hermes` in normal operation (it reads
`HERMES_HOME` from the environment, else `~/.hermes`). That is the same directory as
the fleet's shared `.env`, so it is the natural home for a shared Google credential.
**Do not invent a new location.**

## Scope policy — how narrow is the grant

The scopes are *policy*, not a hardcoded constant. Resolution order, first hit wins:

1. `--services LIST` on the command line (one-off override of the consent request).
2. `HERMES_GOOGLE_SCOPES` in the environment (comma or space separated).
3. The policy sidecar `google_oauth_policy.json`, looked up next to the **resolved**
   token file and then next to `HERMES_HOME`.
4. `DEFAULT_SCOPES` — the upstream full Workspace set (8 scopes).

The sidecar lives *beside the credential*, not inside it: `google-auth` rewrites
`google_token.json` on every refresh and silently drops keys it does not know, so a
policy stored inside the token would disappear at the first refresh.

```json
{
  "services": ["calendar"]
}
```

Service names (`calendar`, `drive`, `sheets`, `docs`, `contacts`, `email`/`gmail`,
`all`) and full scope URLs are both accepted; entries are de-duplicated in order.

**The same resolved set drives both the consent request and the "missing scopes"
report.** That symmetry is the point: a deliberately narrow grant no longer produces
a permanent `AUTHENTICATED (partial): missing 7 scopes` warning in every profile
that shares the token. Measured 2026-10-21 with a calendar-only token:

| sidecar | `--check` |
|---|---|
| present (`{"services":["calendar"]}`) | `AUTHENTICATED` |
| absent | `AUTHENTICATED (partial): Token valid but missing 7 scopes` |

This host's fleet sidecar is at `~/.hermes/google_oauth_policy.json` and resolves to
exactly one scope. The upstream default is deliberately unchanged, so a stock install
elsewhere behaves exactly as before.

## Bridging profiles

A profile with its own `HERMES_HOME` (every `~/.hermes/profiles/<name>/`) resolves to
its own directory and would therefore look for its own copy of the token. Bridge with
symlinks to the shared root:

```bash
for f in google_token.json google_client_secret.json; do
  for d in ~/.hermes/profiles/*/; do
    [ -e "$d$f" ] || [ -L "$d$f" ] || ln -s "$HOME/.hermes/$f" "$d$f"
  done
done
```

- **Symlink, never copy.** One file, one rotation, and a revoked token is revoked
  everywhere at once.
- The `[ -e ] || [ -L ]` guard makes the loop safe to re-run: a profile that already
  has a live link — or a **dangling** one, which is what a pre-OAuth fleet looks like —
  is left alone.
- The sidecar does **not** need a per-profile symlink. `policy_candidates()` resolves
  the token's *real* directory and accepts it when it is inside `HERMES_HOME` or is a
  recognisable fleet root (a directory that contains `profiles/<name>`), so every
  profile that symlinks the token inherits the root sidecar automatically.

### Hosts that do not mount the shared home

A host with its own filesystem (the VPS `srv979961`) needs the file **delivered into
its own `HERMES_HOME`** — a symlink to a path that does not exist there is a broken
link, not a solution. The layout there is the same shape, but the root file is a real
file:

```
~/.hermes/google_token.json                 <- real file, copied from Yoda
~/.hermes/google_client_secret.json         <- real file, copied from Yoda
~/.hermes/google_oauth_policy.json          <- real file, same content as Yoda
~/.hermes/profiles/<p>/google_token.json   -> ~/.hermes/google_token.json
~/.hermes/profiles/<p>/google_client_secret.json -> ~/.hermes/google_client_secret.json
```

Delivery is a copy with the mode preserved (`scp -p` / `rsync -p`, then verify
`stat -c '%a'`). Keep the two hosts' copies in step after every re-consent.

## Permissions — the default is wrong

`Path.write_text()` creates files with `0666 & ~umask`. Under the common `umask 022`
that is **0644**; under this host's `umask 002` it is **0664**. Either way a live
refresh token and the OAuth client secret end up readable by every local user.

Every write in this skill goes through `write_secret()` (`_gws_policy.py`), which
forces `0600` after writing. That covers the token exchange, the token rewrite on
refresh, the client secret, the pending OAuth session (it holds the PKCE
`code_verifier`) and the last auth URL.

Verify:

```bash
stat -c '%a %n' ~/.hermes/google_token.json ~/.hermes/google_client_secret.json   # expect 600
```

**Known gap:** the mode is enforced on *write* only. A credential file that already
exists at `0644` is **not** tightened by a later `--check` — `ensure_secret_mode()` is
called from `write_secret()` and nowhere else. Fix such a file by hand (`chmod 600`)
or by rewriting it through the skill. On this fleet no credential file existed before
the fix landed, so nothing is exposed today; the gap matters only for a deployment that
ran the pre-fix script.

## Order of operations

1. Write the fleet sidecar (`{"services": ["calendar"]}`) into the credential root —
   do this **before** `--auth-url`, or the consent screen asks for all 8 scopes.
2. `--client-secret <path/to/client_secret.json>` → verify mode 600.
3. `--auth-url` → hand the URL to the user; they approve in their own browser. Confirm
   the URL's `scope=` parameter carries only what the policy asks for.
4. User pastes back the full `http://localhost:1/?code=…` URL.
5. `--auth-code "<url>"` → verify mode 600.
6. `--check` → `AUTHENTICATED`, with no "missing scopes" line.
7. Symlink into every local profile dir; deliver to non-shared hosts as a real copy.
8. Test one real write (a calendar event), then list it back — a token that is valid
   but lacks the API enabled in Cloud Console fails only at the first call, not at
   `--check`.

## Gotcha: a profile-local copy shadows this skill

`sync_skills` keys bundled skills on the frontmatter `name:` and **defers to an
existing external skill of the same name**. A profile that has its own
`skills/google-workspace/` therefore never receives the bundled
`skills/productivity/google-workspace/` — it keeps running its own older copy, silently.

Check whether a profile is on the bundled version:

```bash
md5sum ~/.hermes/profiles/<p>/skills/productivity/google-workspace/scripts/setup.py
```

If the path does not exist and `~/.hermes/profiles/<p>/skills/google-workspace/`
does, that profile is on a stale copy. As of 2026-10-21 this is the case for the
`research` profile on Yoda; its local copy already carries the `0600` chmods and a
calendar-only `SCOPES` list, so it is not a security exposure — but it will not pick
up later fixes to this skill. Consolidating it is a separate decision (it means
touching another profile's skills).
