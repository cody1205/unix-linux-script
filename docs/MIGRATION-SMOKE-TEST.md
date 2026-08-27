# Migration smoke test

**Code word: "smoke test".** This file is the thing that phrase refers to.

Read this before migrating the project from a personal GitHub repository to a
Grant Thornton corporate one, and before building the release workflow described
under *Delivering the tool to a client* in the README.

The purpose is narrow: establish that the corporate GitHub instance can actually
run a workflow, that whoever cuts releases can push a tag, and that a workflow
can publish a Release. Everything else about the migration is ordinary; these
three are the ones that can quietly turn out to be blocked by policy.

---

## First: two things that look alike and are not

**CI builds the bundle, and the auditor downloads it.** This works on a private
corporate repository. The person cutting the release is authenticated and has
access. This is the part that removes the need for a Unix shell on a Windows
laptop, and it is the reason to do any of this.

**The client downloads the bundle from GitHub directly** — Method 2 in the
README. This will almost certainly **stop working** after migration. A corporate
repository will be private, so release assets are not publicly reachable, and no
audit client is going to be given an account on the firm's GitHub org. If the
firm runs GitHub Enterprise *Server* on an internal hostname, clients cannot
reach it at all.

That is not a problem to solve, just one to expect. Method 1 — build the bundle
and send it — was always the default and works everywhere, including air-gapped
client estates. Plan on Method 2 going away at migration rather than being
surprised by it.

---

## Step 1 — Identify which GitHub product it is

The URL answers it, and it determines how much work is involved:

| URL | Product | Consequence |
| --- | --- | --- |
| `github.com/<org>/…` | Enterprise Cloud | GitHub-hosted runners available; `runs-on: ubuntu-latest` works as written |
| `*.ghe.com` | Enterprise Cloud with data residency | Usually the same |
| An internal hostname | Enterprise **Server** | Actions may not be enabled at all, and GitHub-hosted runners do not exist — a self-hosted Linux runner has to be provisioned |

Enterprise Server is the case that needs real lead time, so establish this first.

---

## Step 2 — Questions for the platform / DevOps team

These determine feasibility. Sending them verbatim is fine:

> - Are GitHub Actions enabled for our organisation, and for new repositories by
>   default?
> - Are GitHub-hosted runners available, or do we use self-hosted runners? If
>   self-hosted, what labels should `runs-on:` use, and is a Linux runner
>   available?
> - Is there an allow-list restricting which Actions may run? We use only
>   `actions/checkout`, which is GitHub-authored.
> - What is the default `GITHUB_TOKEN` permission for workflows — read-only, or
>   read/write?
> - Are there tag protection rules or rulesets restricting who can create tags
>   matching `v*`?
> - What repository role is needed to create tags and publish Releases?

**The fourth question is the one that quietly bites.** Many corporate orgs set
the default `GITHUB_TOKEN` permission to read-only, which silently prevents a
workflow from creating a Release. It is fixable — an org setting, or
`permissions: contents: write` in the workflow — but it is much better known in
advance than discovered while debugging under deadline.

---

## Step 3 — Do not trust the answers; smoke test them

This is the actual verification, and it takes about fifteen minutes. Ask for a
scratch repository in the corporate org — `sox-collector-pilot` or similar.

**Commit the entire workflow first, then push one tag.** All three questions get
answered by that single tag push, and they have to be: a tag push fires its event
exactly once, so editing the workflow afterwards does not re-run it against a tag
that is already pushed. Building the test up in stages — workflow, then tag, then
add the Release step — reports a missing Release even when every permission is
correctly configured, which is a false failure that costs an afternoon.

**1. Commit this workflow** to the scratch repository's default branch as
`.github/workflows/smoke-test.yml`, substituting the runner label from Step 2 if
the firm is self-hosted:

```yaml
name: Smoke test
on:
  push:
    tags: ['v*']

permissions:
  contents: write        # explicit on purpose - see the note below

jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
      - run: date > artifact.txt
      - run: gh release create "$GITHUB_REF_NAME" artifact.txt
        env:
          GH_TOKEN: ${{ github.token }}
```

**2. Push one tag.** This is the moment the test happens:

```
git tag v0.0.1-test
git push origin v0.0.1-test
```

**3. Read all three answers off that one run:**

| Observation | What it establishes |
| --- | --- |
| The `git push` succeeds | Tag creation is permitted for this account, and no ruleset blocks `v*` |
| The run appears under Actions and reaches `echo hello` | Actions are enabled and the runner label is valid |
| Release `v0.0.1-test` exists with `artifact.txt` attached | The workflow token can write to the repository |

**A retry needs a NEW tag.** Re-pushing `v0.0.1-test` after a fix does nothing —
the tag already exists, so no event fires. Delete it, fix the workflow, and use
`v0.0.2-test`. Every attempt costs a fresh tag; that is normal, not a sign
anything is wrong.

### Two deliberate choices in that workflow

**`permissions: contents: write` is set explicitly** so the test does not depend
on the organisation default. That is correct for a real workflow, but it means a
pass here does *not* tell you what the default is — so still ask the fourth
question in Step 2 rather than inferring an answer. To find out empirically
instead, delete the `permissions:` block, push a new tag, and see whether the
release step fails with a 403; that failure is the answer.

**The Release is created with the GitHub CLI rather than a third-party Action.**
`gh` is pre-installed on GitHub-hosted runners and uses the same token, so the
test stays clean under an Actions allow-list — the only Action referenced is
`actions/checkout`, which is GitHub-authored. On a self-hosted runner `gh` may
not be installed; if the step fails with `gh: command not found`, that is a
runner-image gap, not a permissions problem, and the run still answered the first
two questions.

If all three observations hold, everything the release workflow needs is present
and it can be written as designed. If one fails, the failure names exactly which
conversation to have — with a reproducible example rather than a hypothetical.

Do this **before** the migration, on the scratch repository. Discovering a
blocker during the migration itself is considerably more expensive.

---

## Raise early, because they have lead times

- **A Linux runner**, if the firm is self-hosted only. Someone has to provision
  it; that is a request with a queue, not a checkbox.
- **Repository visibility.** Confirm the repo will be private, and that it is not
  being made internal-visible to the whole firm by default without a decision.

---

## When the smoke test is done

Bring the results back — runner labels, whether the token is read-only, and any
Action allow-list — and the release workflow can be written to match: correct
`runs-on` labels, explicit `permissions:` if the token defaults to read-only, and
no third-party Actions if there is an allow-list.

The workflow should also refuse to publish unless the full test suite passed on
that commit, so a broken bundle cannot reach a client.
