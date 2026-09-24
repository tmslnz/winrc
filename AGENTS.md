# AGENTS.md

Single-file PowerShell dotfiles bootstrap. `winrc.ps1` is dot-sourced from the user's
PowerShell profile; `README.md` is the user-facing doc. No build, tests, lint config,
manifest, or CI — the script is the whole product.

## Running / verifying

- `Main` is called unconditionally at the bottom of `winrc.ps1` (last line). Simply
  running or dot-sourcing the file executes it, which **writes real profile/config files
  on the host and may start a background update job**. Do not run it just to check edits.
- Syntax-check without side effects via the parser:
  ```powershell
  $e = $null; [System.Management.Automation.Language.Parser]::ParseFile("$PWD/winrc.ps1", [ref]$null, [ref]$e); $e
  ```
- Test individual functions by dot-sourcing in a throwaway pwsh session and calling them
  directly, or by extracting the function, rather than invoking `Main`.

## Constraints

- Must run on **both PowerShell 7+ and Windows PowerShell 5.1**. Avoid PS7-only syntax.
  `$IsWindows`/`$IsLinux`/`$IsMacOS` are undefined on 5.1 — use `Test-IsWindows` /
  `Test-IsLinux` / `Test-IsMacOS`. A `$PSStyle` shim exists for 5.1 (near the
  "PLATFORM & ENVIRONMENT HELPERS" section).
- All config-file writes must go through `Set-ConfigSection` (BEGIN_SHELLRC /
  END_SHELLRC fenced, idempotent, returns `$true` only when the file actually changed).
  Do not write config files directly.
- Persistent config setters are **not** run per shell. Register every new persistent
  `Set-Config*` / `Install-PowerShellProfile` call inside `Invoke-WinrcConfigure`, never
  in `Main`. `Main` runs `Invoke-WinrcConfigureIfNeeded`, which content-hash-gates the
  configure pass; keep only per-session work (PSReadLine tuning, zoxide hook) in `Main`.
- `Write-WinrcState` **merges** fields (`LastCheckUtc`, `LastConfiguredHash`) and must
  keep doing so — writing the state file with a single field clobbers the other.
- Non-standard function verbs (`Set-Config*`, `Get-ShortPath`, `Update-Winrc`, …) are
  intentional; do not "fix" them for PSScriptAnalyzer.
- Section header comments are numbered but appear out of file order (1, 5, 4, 3, 2, 6,
  7, 8). Numeric order does not match file order.

## Self-update

- Update detection is **content-hash based** (SHA-256 of the whole file), not version
  based. `$script:WinrcVersion` (near the top) is informational but must be kept in sync
  with the version released on GitHub.
- Release flow: publish a GitHub release whose asset is named exactly `winrc.ps1`;
  otherwise `auto`/`release` falls back to the raw `main` branch file.
- `winrc.ps1.bak` is an untracked local backup written by the self-updater. Never commit
  it (only `winrc.ps1` and `README.md` are tracked).

## Conventions

- Commits: short, lowercase, imperative, no conventional-commit prefix (e.g.
  `fix exit code in prompt`, `shorten scoop list`). Branch: `main`.
- Keep `README.md` in sync when user-facing behavior changes.
