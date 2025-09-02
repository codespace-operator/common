// commitlint.config.js
// Enforces Conventional Commit rules for PR titles and commit messages
// Examples:
//   feat(operator): add new reconciliation loop
//   fix(crd): correct schema for Foo
//   chore(ci): bump actions/checkout version

module.exports = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    // ✅ Restrict commit scopes to meaningful areas in the repo
    "scope-enum": [
      2,
      "always",
      ["auth", "oidc", "ldap", "rbac", "api", "repo", "ci", "test", "common"],
    ],

    // ✅ Restrict commit types to Conventional Commit "verbs"
    "type-enum": [
      2,
      "always",
      [
        "feat", // New feature
        "fix", // Bug fix
        "perf", // Performance improvement
        "refactor", // Code restructure without changing behavior
        "docs", // Documentation changes only
        "chore", // Misc maintenance (deps, cleanup, tooling)
        "ci", // CI/CD config or script changes
        "build", // Build system or dependency changes
        "test", // Adding or adjusting tests
      ],
    ],
  },
};
