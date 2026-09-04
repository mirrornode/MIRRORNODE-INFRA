## Scope

Describe the bounded infrastructure change and explicit non-scope.

## Verification

- [ ] Applicable INFRA workflows pass on the current head
- [ ] Machine-readable manifests parse
- [ ] No secrets, credentials, or private identifiers are committed

## Repo Steward / authority boundary

- [ ] Any repository-administration capability remains Operator-gated
- [ ] No bot-only or advisory-model-only mutation path is introduced
- [ ] CI/review evidence is not represented as approval or merge authority
- [ ] Any changed head is re-reviewed where exact-head policy requires it

## Merge discipline

- [ ] No direct default-branch write
- [ ] Operator retains merge authority
