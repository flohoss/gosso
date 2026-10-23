# Agent Guidance

Read before making changes. Rule-oriented and self-contained.

## Principles

- **CLEAN code.** Small functions, single responsibility, descriptive names, no dead code, no overengineering.
- **No comments.** Use descriptive function or service names instead.
- **No code markers** like `// ... existing code ...` in edits.
- Go imports: stdlib → external → internal, each block alphabetical.

## Git

- Do not commit automatically — wait until explicitly asked.
- Never add a `Co-authored-by` trailer, including for Copilot or any other agent.
- One commit per concern — never batch unrelated changes.
- Title only, no body. Capitalize first letter after the prefix:
  - `[fix]` bug fix
  - `[feature]` new functionality
  - `[improve]` improvement to existing functionality
  - `[refactor]` formatting, renaming, structural-only
  - `[meta]` deployment, CI
  - `[docs]` documentation
