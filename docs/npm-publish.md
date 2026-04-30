# NPM Publish

The unscoped `mcp-guardian` package name is already used on npm, so this project publishes as:

```text
@cyberranger/mcp-guardian
```

The CLI binary remains:

```bash
mcp-guardian
```

## Publishing Options

### Trusted Publishing

Preferred path: configure npm trusted publishing for:

- Package: `@cyberranger/mcp-guardian`
- GitHub owner: `cyberranger93`
- Repository: `mcp-guardian`
- Workflow filename: `npm-publish.yml`
- Environment: leave blank unless the GitHub workflow is later changed to use one

Then run the `Publish Package to npm` GitHub Actions workflow.

### Manual Login

```bash
npm login
```

Use an npm account that can publish under the `@cyberranger` scope. Manual `npm publish` requires npm publish-grade 2FA or a granular access token with publish permissions.

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

If npm uses passkey/PIN auth instead of an authenticator app, complete the browser challenge and use the generated one-time token when prompted by the CLI.

## Verify Public Install

```bash
npm view @cyberranger/mcp-guardian version
npm install -g @cyberranger/mcp-guardian
mcp-guardian --help
```

## Release Checklist

- Bump `package.json` version.
- Update `CHANGELOG.md`.
- Commit and push.
- Tag the release, for example `v0.1.2`.
- Move the `v0` GitHub Action channel tag if the action changed.
- Create a GitHub release.
