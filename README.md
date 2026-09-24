# winrc.ps1

A single-file PowerShell profile/environment bootstrap script, dot-sourced into your
PowerShell profile. It tunes the terminal experience, writes idempotent `SHELLRC`
fenced config blocks for the tools you use, and can self-update from this repo.

## Quick start

1. Clone this repo somewhere stable, e.g. `C:\Users\<you>\winrc` or a `~/dotfiles` dir.
2. Open a PowerShell prompt and run:

   ```powershell
   . .\winrc.ps1
   ```

   This runs `Main`, which installs/updates your PowerShell profile (backing up an
   existing one), applies PSReadLine tuning, and — on this first run — writes the
   fenced config sections described below. Running it again is safe: every step is
   idempotent, and the config sections are only re-applied when `winrc.ps1` changes
   (see [When config sections are applied](#when-config-sections-are-applied)).

Once installed, your `$PROFILE` contains a `BEGIN_SHELLRC`/`END_SHELLRC` fenced block that
dot-sources `winrc.ps1` on every new terminal, so the functions below are available in
every session.

## Terminal experience

The `prompt` function is a colorful, informative prompt that shows:

- a **last-exit-code indicator** — green `✔` on success, red `✘ <code>` after a failed command,
- **user@host** and the current working directory (with `~` substitution and long-path collapsing),
- a **lazy git segment** — `(branch)` or `(branch *)` when the directory is a git work tree;
  results are cached per directory so it only spawns `git` when you change folders.

`Set-ConfigPowershell` configures PSReadLine:
reverse/forward history search on the arrow keys and Tab completion.

## Self-update

`Update-Winrc` pulls the latest `winrc.ps1` from GitHub and, when it differs, atomically
replaces the file on disk and reloads it into the current session — no shell restart.

```powershell
Update-Winrc                # update to latest (release preferred, raw fallback)
Update-Winrc -CheckOnly     # report whether an update is available, apply nothing
Update-Winrc -Force         # force re-download + reload even if unchanged
Update-Winrc -Source raw    # update straight from the branch file (skip release lookup)
```

Update sources (controlled by `$script:WinrcUpdateSource`, default `auto`):

- `auto` – try the **latest GitHub release** asset named `winrc.ps1`; if the repo has no
  release/asset, fall back to the **raw branch** file.
- `release` – release asset only.
- `raw` – raw branch file only (`https://raw.githubusercontent.com/tmslnz/winrc/main/winrc.ps1`).

A SHA-256 content hash decides whether an update is needed; the previous file is kept as
`winrc.ps1.bak`.

### Periodic auto-check

When enabled (default), winrc checks for updates **automatically** on shell start, at most
once every few days, as a **background job** — so it never delays prompt startup and never
interrupts a running command. When an update is found it is staged to disk and a one-line
notice is printed on the next shell; the new code takes effect in a new shell
(`Update-Winrc` applies it to the current session without restarting).

Configuration (edit `winrc.ps1` near the top):

```powershell
$script:WinrcAutoCheck             = $true   # set $false to disable
$script:WinrcAutoCheckIntervalDays = 3       # minimum days between checks
```

The last-check timestamp and the one-shot "staged update" notice are stored under
`%LOCALAPPDATA%\winrc\`.

## SHELLRC fenced config sections

`Set-ConfigSection -Path <file> -String <block>` (with a `BEGIN_SHELLRC`/`END_SHELLRC`
fence) is the core helper. It is idempotent:

- creates the file (and parent dirs) if missing,
- **replaces** the existing fenced block in place if the markers are present,
- otherwise **prepends** the block (`-Append` to append instead),

and returns `$true` only when the file actually changed. Fence lines may start with `#`,
`;`, or `/` so the same mechanism works for `.npmrc`, `git config`, `~/.ssh/config`, etc.

Built-in config setters currently cover **npm**, **git** (config/ignore/attributes),
**ssh**, and the **PowerShell profile** itself. Add more by writing a small function that
calls `Set-ConfigSection`.

> Note: the old `New-ConfigSection` / `Update-ConfigSection` are kept as thin aliases of
> `Set-ConfigSection` so previously dot-sourced callers still work.

## When config sections are applied

The config setters are the repository of each tool's parameters, but they are **not**
run on every shell — that would make profile loading slow. Instead, `Main` calls
`Invoke-WinrcConfigureIfNeeded`, which hashes `winrc.ps1` (content plus its path) and
runs `Invoke-WinrcConfigure` only when the hash differs from the one stored in
`%LOCALAPPDATA%\winrc\winrc.state.json`. So the sections are re-applied exactly once
whenever `winrc.ps1` changes:

- `Update-Winrc` (interactive or the background updater),
- `git pull` in the dotfiles repo,
- or a manual edit of `winrc.ps1`.

Because the hash includes the script's path, moving or renaming the repo also triggers
a re-run, which re-points the profile loader at the new location.

Per-session-only work stays in `Main`: the PSReadLine tuning and the zoxide hook are
re-applied on every shell (they do not persist to disk).

To force a re-apply without editing the file:

```powershell
Invoke-WinrcConfigureIfNeeded -Force   # or Invoke-WinrcConfigure to run the setters
```

## Platform notes

- Fully supports **PowerShell 7+** and stays functional on **Windows PowerShell 5.1**
  (a lightweight `$PSStyle` shim is provided where the real one is unavailable).
- `Test-IsWindows` / `Test-IsLinux` / `Test-IsMacOS` are the modern guards used
  throughout for platform-specific steps.

## Roadmap

- [ ] Support configuring specific apps through ad-hoc functions on top of `Set-ConfigSection`.
- [ ] Allow gathering/exporting configurations through helper functions.