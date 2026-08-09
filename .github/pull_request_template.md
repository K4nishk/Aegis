## Summary

<!-- Describe the change and why it was made. Link the Linear issue. -->

Closes #<!-- issue number -->
Linear: <!-- e.g. KCH-XX -->

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor
- [ ] CI/CD / infra
- [ ] Documentation
- [ ] Security fix

---

## Acceptance Criteria Checklist

<!-- Check every AC item from the linked Linear issue. -->

- [ ] AC 1: <!-- copy from issue -->
- [ ] AC 2: <!-- copy from issue -->
- [ ] AC 3: <!-- copy from issue -->

---

## Audit-Coverage Proof

<!--
Paste the pytest coverage summary (or a link to the CI artifact) showing
that new code is covered. Example:

```
---------- coverage: platform linux, python 3.12 ----------
TOTAL   347   12   97%
```

If this PR contains no testable logic, explain why.
-->

**Coverage report:**

```
<paste pytest --cov output here>
```

---

## Security Checklist

- [ ] No secrets, credentials, or PII committed
- [ ] Dependencies reviewed (no new high/critical CVEs)
- [ ] Input validation added where applicable
- [ ] `bandit` / `safety` scans passed (see Aegis Gate workflow)

---

## Testing

- [ ] Unit tests added / updated
- [ ] Integration tests pass
- [ ] Manual testing performed (describe below)

**Manual test notes:**

<!-- What did you test manually? -->

---

## Deployment Notes

<!-- Anything reviewers or the deployment pipeline need to know: migrations, env vars, feature flags, etc. -->

---

## Reviewer Checklist (for code reviewers)

- [ ] Logic is correct and matches the AC
- [ ] No obvious security issues
- [ ] Tests are meaningful, not just coverage padding
- [ ] CI / Aegis Gate is green
