# Contributing

Thanks for helping improve `safe-redact-log`!

1. Fork the repo and create a branch: `git checkout -b feat/my-change`
2. Make your change in `src/` and add tests in `test/`.
3. Run `npm test` (Node >= 18). All tests must pass.
4. Update `README.md`, `src/index.d.ts` and `CHANGELOG.md` if the public API changes.
5. Open a pull request describing *what* changed and *why*.

Guidelines: keep the package zero-dependency, never mutate caller input,
and prefer small, focused pull requests. Please report security issues privately
via the repository's Security tab rather than a public issue.
