# Contributing

Thanks for helping improve MCP Guardian.

## Development

```bash
npm install
npm run build
npm test
```

Run the full local check before opening a pull request:

```bash
npm run check
```

## Documentation Changes

Documentation should be practical, copy-pasteable, and explicit about security boundaries. Avoid implying that Guardian is a sandbox or that it can make arbitrary untrusted MCP servers safe by itself.

When adding examples:

- Prefer least-privilege policies.
- Keep monitor-mode rollout examples separate from enforce-mode production examples.
- Redact secrets and internal hostnames.
- Include a short explanation of when the example should be used.

## Code Changes

Keep policy behavior deterministic and auditable. Security-sensitive changes should include tests for allow, warn, block, and redaction behavior where applicable.

## Pull Request Checklist

- The change is scoped and documented.
- Tests or examples cover the changed behavior.
- Security boundaries are stated clearly.
- New policy exceptions are justified.
- Generated files are not committed unless they are intentional release assets.
