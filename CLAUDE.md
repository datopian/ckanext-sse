# ckanext-sse

CKAN 2.10 extension for the SSEN Distribution Data Portal: custom actions, validators, permission labels, views and background jobs. See `README.md`.

## Commits: Conventional Commits only

Every commit message MUST follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Releases are cut automatically from these messages by semantic-release (`.releaserc.json`, `.github/workflows/release.yml`), so a malformed message means a missing or wrong release.

Format:

```
<type>(<optional scope>)<optional !>: <description>

<optional body>

<optional footer(s)>
```

- `type` is one of: `feat`, `fix`, `perf`, `refactor`, `docs`, `style`, `test`, `build`, `ci`, `chore`, `revert`.
- `description`: imperative, lower case, no trailing period, under ~72 characters.
- `scope` is optional and names the area, e.g. `fix(auth): ...`, `feat(validators): ...`, `chore(deps): ...`.
- Breaking changes: add `!` after the type/scope (`feat(api)!: ...`) and/or a `BREAKING CHANGE: <what and how to migrate>` footer. Use this for anything that needs a matching change where the extension is deployed: removed or renamed actions or config options, schema changes, required migrations.

How types map to releases on `main`:

| Commit | Release |
|---|---|
| `feat` | minor (`v1.2.0` -> `v1.3.0`) |
| `fix`, `perf` | patch (`v1.2.0` -> `v1.2.1`) |
| `!` or `BREAKING CHANGE:` footer | major |
| anything else | no release |

Pick the type by user-visible effect: a dependency bump that fixes a vulnerability is `fix(deps):`, one that changes nothing visible is `chore(deps):`.

Merge commits are ignored by the release analysis, so every commit on a branch counts. If a PR is squash-merged, its title becomes the commit message and must follow the same format.

Releases are git tags and GitHub releases only. The `version` in `setup.cfg` is not bumped.
