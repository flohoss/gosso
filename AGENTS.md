# Agent Guidance

Read before making changes. Rule-oriented and self-contained.

## Principles

- **CLEAN code.** Small functions, single responsibility, descriptive names, no dead code, no overengineering.
- **No comments.** Use descriptive function or service names instead.
- **Test comments are allowed** when the tested behaviour is not obvious from the test name.
- **No code markers** like `// ... existing code ...` in edits.
- Go imports: stdlib, then external, each block alphabetical.
- This is a library: the exported surface is the contract for godash, gocron and chat. Avoid breaking changes; additive changes only.

## Tooling — always on the host

- **Build:** `docker compose run --rm go build ./...`
- **Tests:** `docker compose run --rm go test ./...`
- **Format:** `docker compose run --rm go fmt ./...`
- **Vet:** `docker compose run --rm go vet ./...`

Only commit if format and tests pass.

## Git

- Do not commit automatically — wait until explicitly asked.
- One commit per concern — never batch unrelated changes.
- Title only, no body. Capitalize first letter after the prefix:
  - `[fix]` bug fix
  - `[feature]` new functionality
  - `[improve]` improvement to existing functionality
  - `[refactor]` formatting, renaming, structural-only
  - `[meta]` deployment, CI
  - `[docs]` documentation
