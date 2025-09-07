# [1.1.0](https://github.com/codespace-operator/common/compare/common/v1.0.1...common/v1.1.0) (2025-09-07)


### Bug Fixes

* **auth:** add missing adapters ([bf9f4bd](https://github.com/codespace-operator/common/commit/bf9f4bdf4d3a3e45d7376f81bcedd86bb15c89f1))
* **auth:** centralize token management to `AuthManager` ([5ebf685](https://github.com/codespace-operator/common/commit/5ebf685e7d47b67b927abafbd0bfdee9e907e2f1))
* **auth:** config missing tags for unmarshaling ([47e1425](https://github.com/codespace-operator/common/commit/47e14254af636b82437ca2e8cb027b19c2671013))
* **auth:** enforce cfg paths as configured ([0f6aef7](https://github.com/codespace-operator/common/commit/0f6aef70968802c9f923662220f1e9d0d96deeba))
* **auth:** external functions stay standard ([8e8ceb5](https://github.com/codespace-operator/common/commit/8e8ceb5446cb6a443c0c30f6c2753812f67737be))
* **auth:** loader sanitize types ([3e835e5](https://github.com/codespace-operator/common/commit/3e835e5dc9f51afcdd5e55970bc4652f7c13f600))
* **auth:** make AuthFileConfig public for typehints ([6427d20](https://github.com/codespace-operator/common/commit/6427d20b51d466e413347157b0ada5277c2f75dd))
* **auth:** session is manager ([c4e8a88](https://github.com/codespace-operator/common/commit/c4e8a88d4a64f6f7f7a2fe733487c82668280b1f))
* **common:** remove unnecessary logging ([1c20340](https://github.com/codespace-operator/common/commit/1c20340032fb47ab135a5866e31bfe217bcb02bf))


### Features

* **auth:** add public helpers ([3ddb4cd](https://github.com/codespace-operator/common/commit/3ddb4cda02553a8f15dede37c4dc84d29f4eaad8))
* **auth:** config loader for auths ([b8d0c55](https://github.com/codespace-operator/common/commit/b8d0c553845934d492f69c77810332d6d34c8036))
* **auth:** env bindings directly ([78b127f](https://github.com/codespace-operator/common/commit/78b127f050d6ce843bb1e9e538865c8838ee7474))
* **rbac:** decouple from auth, use a `Principal` ([e481cdf](https://github.com/codespace-operator/common/commit/e481cdf9490f1526d88a6d2312eb53d936e10dd5))

## [1.0.1](https://github.com/codespace-operator/common/compare/common/v1.0.0...common/v1.0.1) (2025-09-04)


### Bug Fixes

* **common:** fix common pkg structure ([ecb7f31](https://github.com/codespace-operator/common/commit/ecb7f317bbe9def0503c8bc4a57f3e3449dc384c))

# 1.0.0 (2025-09-04)


### Bug Fixes

* **rbac:** stub push ([b36bc71](https://github.com/codespace-operator/common/commit/b36bc714a61e34716f17effb7e8a3335e25c045b))
* **repo:** non breaking 1.22->1.25 ([0fe84ae](https://github.com/codespace-operator/common/commit/0fe84ae56947c2daa313d747da1cda0f2aef93bd))
* **repo:** remove unused watches ([152fca9](https://github.com/codespace-operator/common/commit/152fca954c68cf0b33d4337c7921197cd250d7d4))


### Features

* **auth,rbac:** release ([b4a0497](https://github.com/codespace-operator/common/commit/b4a04972a579a2863dc5696a363d0eeb7a9559e9))
* **auth:** auth pkg bump due to immutability ([d160b68](https://github.com/codespace-operator/common/commit/d160b683b96901b8627d674b357e9ffb4fdced6d))
* **auth:** auth pkg bump due to immutability ([02c7404](https://github.com/codespace-operator/common/commit/02c7404aefcb4eb108d14179b79e034d7553bc86))
* **common:** init common pkg ([7c195f3](https://github.com/codespace-operator/common/commit/7c195f3028319980a331c33de243864a9617a288))
* **common:** init packages ([2557b1f](https://github.com/codespace-operator/common/commit/2557b1f4ec3846e092a3b3a90bfcd61dc2261d47))
* **common:** release ([6303539](https://github.com/codespace-operator/common/commit/63035393e97c76189fb9096f85b2bb3f632ea5b3))
* **rbac:** appName as constant for modelpath ([343d85a](https://github.com/codespace-operator/common/commit/343d85a5228ef17cd89c7d43e7e080651039e1d5))
