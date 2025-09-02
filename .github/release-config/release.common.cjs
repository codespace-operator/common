const nonReleasingTypes = /^(docs|chore|build|ci|test|refactor)$/;
const commonScopes = /^(rbac|auth|common|oauth|oidc|ldap)$/;

module.exports = {
  branches: ['main'],
  tagFormat: 'v${version}',
  plugins: [
    ['@semantic-release/commit-analyzer', {
      preset: 'conventionalcommits',
      parserOpts: { noteKeywords: ['BREAKING CHANGE', 'BREAKING CHANGES', 'BREAKING'] },
      releaseRules: [
        { breaking: true,              release: 'major' },
        { type: 'feat',  scope: commonScopes, release: 'minor' },
        { type: 'fix',   scope: commonScopes, release: 'patch' },
        { type: 'perf',  scope: commonScopes, release: 'patch' },
        { type: 'revert',scope: commonScopes, release: 'patch' },
        { type: nonReleasingTypes,             release: false },
        { type: /.*/,                          release: false }
      ]
    }],
    '@semantic-release/release-notes-generator',
    ['@semantic-release/changelog', { changelogFile: 'CHANGELOG.md' }],
    ['@semantic-release/git', {
      assets: ['CHANGELOG.md'],
      message: 'chore(release): common ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}'
    }],
    '@semantic-release/github'
  ]
};
