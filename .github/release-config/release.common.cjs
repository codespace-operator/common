const releaseScopes = /(?:^|,)\s*(rbac|common|auth)\s*(?:,|$)/;
const nonReleasingTypes = /^(docs|chore|build|ci|test|refactor)$/;

module.exports = {
  branches: ["main"],
  tagFormat: "v${version}",
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        parserOpts: {
          noteKeywords: ["BREAKING CHANGE", "BREAKING CHANGES", "BREAKING"],
        },
        releaseRules: [
          { breaking: true, scope: releaseScopes, release: "major" },
          { type: "feat", scope: releaseScopes, release: "minor" },
          { type: "fix", scope: releaseScopes, release: "patch" },
          { type: "perf", scope: releaseScopes, release: "patch" },
          { type: "revert", scope: releaseScopes, release: "patch" },
          { type: nonReleasingTypes, release: false },
          { type: /.*/, release: false },
        ],
      },
    ],
    "@semantic-release/release-notes-generator",
    [
      "@semantic-release/changelog",
      { changelogFile: "CHANGELOG.md" },
    ],
    [
      "@semantic-release/git",
      {
        assets: ["CHANGELOG.md"],
        message:
          "chore(release): common ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}",
      },
    ],
    "@semantic-release/github",
  ],
};
