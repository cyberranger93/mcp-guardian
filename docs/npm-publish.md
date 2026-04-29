# NPM Publish

The unscoped `mcp-guardian` package name is already used on npm, so this project publishes as:

```text
@cyberranger93/mcp-guardian
```

The CLI binary remains:

```bash
mcp-guardian
```

## One-Time Login

```bash
npm login
```

Use an npm account that can publish under the `@cyberranger93` scope.

## Verify Before Publishing

```bash
npm run check
npm audit --audit-level=moderate
node dist/cli.js scan . --config .mcp-guardian.json --fail-on high
npm pack --dry-run
```

## Publish

```bash
npm publish --access public
```

## Verify Public Install

```bash
npm view @cyberranger93/mcp-guardian version
npm install -g @cyberranger93/mcp-guardian
mcp-guardian --help
```

## Release Checklist

- Bump `package.json` version.
- Update `CHANGELOG.md`.
- Commit and push.
- Tag the release, for example `v0.1.2`.
- Move the `v0` GitHub Action channel tag if the action changed.
- Create a GitHub release.
