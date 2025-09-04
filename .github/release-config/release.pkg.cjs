const modPath = process.env.MOD_PATH;   // "auth" or "rbac"
const modName = process.env.MOD_NAME;   // "auth" or "rbac"
if (!modPath || !modName) throw new Error('MOD_PATH and MOD_NAME must be set');

// Allow typical scopes for your repo; you can tighten later
const scopeRegex = new RegExp(`(^|,|\\s)(${modName}|auth|rbac|common)(?=,|\\s|$)`);
const ignoreTypes = /^(docs|chore|build|ci|test|refactor|repo)$/;

module.exports = {
  branches: ['main'],
  // IMPORTANT: tag prefix must include subdirectory to match the module root
  tagFormat: `${modPath}/v\${version}`,   // -> auth/v1.2.3
  plugins: [
    ['@semantic-release/commit-analyzer', {
      preset: 'conventionalcommits',
      parserOpts: { noteKeywords: ['BREAKING CHANGE', 'BREAKING CHANGES', 'BREAKING'] },
      releaseRules: [
        { breaking: true,                    release: 'major' },
        { type: 'feat',  scope: scopeRegex,  release: 'minor' },
        { type: 'fix',   scope: scopeRegex,  release: 'patch' },
        { type: 'perf',  scope: scopeRegex,  release: 'patch' },
        { type: 'revert',                     release: 'patch' },
        { type: ignoreTypes,                  release: false }
      ]
    }],
    '@semantic-release/release-notes-generator',
    ['@semantic-release/changelog', {
      changelogFile: `changelogs/CHANGELOG.${modName}.md`
    }],
    ['@semantic-release/git', {
      assets: [`changelogs/CHANGELOG.${modName}.md`],
      message: `chore(release): ${modName} \${nextRelease.version} [skip ci]\n\n\${nextRelease.notes}`
    }],
    '@semantic-release/github'
  ],
};
