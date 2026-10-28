This page is for engineers who use Claude on Tier 2 code: Terraform, Kubernetes manifests, Helm charts, Dockerfiles, CI workflows, and authentication, crypto or access-control code. You'll see how to plan the change, what the approval prompts look like, what Claude can never run, and how the change gets reviewed and deployed.

## The short version

1. Start in **Plan** mode. Switch to **Manual** to make the edits.
2. Expect a ✋ approval prompt for every edit to these paths, even in accept-edits or auto mode.
3. Claude can't apply, destroy or deploy anything. ⛔ `terraform apply`, `kubectl delete`, `helm push`, `docker push` and friends are denied.
4. Run `terraform plan` yourself and attach the output to the pull request.
5. A code owner reviews and approves. CI deploys after merge; nobody deploys from an agent shell.

Source: [policy §0, §1 and §3](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#3-code-review-human-in-the-loop-hitl).

## Which paths count as Tier 2

`file_guard` decides from the file path. The patterns live in [`.claude/hooks/guard_common.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/hooks/guard_common.py).

| Area | Paths that trigger ✋ Ask | Rule name |
|---|---|---|
| Infrastructure-as-code | `*.tf`, `*.tfvars`, `*.hcl`, `*.bicep`; `Dockerfile*`, `Containerfile*`; `compose*.yml`, `docker-compose*.yml`; `serverless.yml`, `skaffold.yml`, `template.yml`, `*.template.json`/`.yaml`; YAML, JSON, `.j2`, `.ts` or `.py` files under a `k8s/`, `kubernetes/`, `manifests/`, `helm/`, `charts/`, `kustomize/`, `deploy/`, `deployment/`, `infra/`, `terraform/`, `ansible/`, `cloudformation/` or `cdk/` folder | `iac_change` |
| Security-critical code | Folders or file names starting with `auth`, `oauth` or `crypto`, or named `sso`, `saml`, `security`, `iam`, `rbac`, `acl`, `permission(s)`, `secret(s)` or `key(s)`; for example `src/auth/session.py`, `src/oauth_client.py`, `src/billing/permissions.py`. (A `secrets/` **folder** counts as secret material, so writes there are ⛔ denied, not asked.) | `security_critical_change` |
| CI workflows | `.github/workflows/` | `guardrail_change` |
| The guardrails | `.claude/`, `.mcp.json`, `CLAUDE.md`, pre-commit config, policy file, `enterprise/`, guardrail scripts and docs, `CODEOWNERS` | `guardrail_change` |

> **Payment and data-retention logic** is Tier 2 by policy, but no path pattern detects it. `app/payments/charge.py` gets no automatic prompt. Treat it as Tier 2 yourself: Plan mode, Manual mode, and ask for a code-owner review.

## Step 1: Plan first

Switch to Plan mode (`Shift+Tab`) and describe the change. In Plan mode Claude reads and proposes, but doesn't edit. Ask it to cover:

- Which files change, and why.
- The security impact in plain words: new access, new exposure, new data flows.
- How you'll verify it (`terraform plan`, `kubectl diff`, tests).

Read the plan. If it touches more than you expected, narrow it now; it's cheaper than reviewing a big diff later.

## Step 2: Make the edits in Manual mode, and read each prompt

Switch to Manual (`default`) and let Claude make the edits. Each edit to a Tier 2 path stops for approval. These are the real messages:

```text
[AI guardrail] `infra/main.tf`: infrastructure-as-code: AI-generated changes require human review before merge (HITL)
```

```text
[AI guardrail] `k8s/deployment.yaml`: infrastructure-as-code: AI-generated changes require human review before merge (HITL)
```

```text
[AI guardrail] `charts/web/templates/deployment.yaml`: infrastructure-as-code: AI-generated changes require human review before merge (HITL)
```

```text
[AI guardrail] `Dockerfile`: infrastructure-as-code: AI-generated changes require human review before merge (HITL)
```

```text
[AI guardrail] `.github/workflows/deploy.yml`: this file is part of the AI guardrails; changes need security review (CODEOWNERS)
```

```text
[AI guardrail] `src/crypto/envelope.py`: security-critical code (auth/crypto/access control): human review required (HITL)
```

The project settings also carry `Edit(...)` ask rules for the common cases (`**/*.tf`, `**/Dockerfile*`, `**/k8s/**`, `**/helm/**`, `**/auth/**` and so on), so you may get a prompt from the rule as well as from the hook. Either way, a human approves.

What to check before you approve:

- Does the change match the plan?
- Does it widen access? Look for `0.0.0.0/0`, `*` in IAM actions or resources, public buckets, `privileged: true`, `hostNetwork`, disabled TLS verification, new secrets in plain text.
- Does a CI workflow change add permissions, new secrets, or third-party actions that aren't pinned to a commit?

"Yes, and don't ask again" is fine for commands you'd run yourself. It's not fine for anything that deploys, deletes, pushes or reaches the network.

## What Claude can never run

`bash_guard` parses the real command, so wrappers such as `bash -c '…'`, `env …`, `timeout …` or `$(…)` don't get around these.

| Command | Decision | Message |
|---|---|---|
| `terraform apply`, `terraform apply tfplan`, `terraform apply -auto-approve` | ⛔ | ``` `terraform apply` mutates real infrastructure; run it through the reviewed CI pipeline ``` |
| `terraform destroy` | ⛔ | ``` `terraform destroy` mutates real infrastructure; … ``` |
| `terraform state rm/mv/push/replace-provider`, `import`, `taint`, `untaint`, `force-unlock`, `run-all`; the same for `tofu` and `terragrunt` | ⛔ | ``` `terraform state` mutates real infrastructure; … ``` |
| `pulumi up/update/destroy/refresh/import/cancel` | ⛔ | `pulumi stack mutation; run it through CI` |
| `cdk deploy`, `cdk destroy` | ⛔ | `CDK deploy/destroy; run it through CI` |
| `kubectl`/`oc` `delete`, `drain`, `cordon`, `taint`, `replace` | ⛔ | ``` `kubectl delete` against a cluster ``` |
| `kubectl get secret … -o yaml` (any Secret dump) | ⛔ | `Kubernetes Secret dump` |
| `docker push`, `helm push`, `npm publish`, `twine upload`, `mvn deploy`, … | ⛔ | ``` `docker push` publishes artifacts (supply-chain risk); release through CI ``` |
| `docker run --privileged`, host mounts, `--pid=host`, `--network=host`, the Docker socket, `docker login` | ⛔ | `privileged/host-mounted container or registry login` |
| `vault read`, `aws secretsmanager get-secret-value`, `gcloud secrets versions access`, `az keyvault secret show`, `op read` | ⛔ | `… would place secret values in the AI context` |

Every deny ends with `See docs/claude-guardrails.md#4-tooling-controls`. The organisation policy also denies `terraform apply` and `terraform destroy` as managed rules, which no project or user setting can override.

## What asks

| Command | Source | Message (if from a hook) |
|---|---|---|
| `kubectl apply`, `create`, `edit`, `patch`, `scale`, `rollout`, `exec`, `cp`, `port-forward`, `set`, `label`, `annotate`, `debug` | Hook + `Bash(kubectl *)` | ``` `kubectl apply` against a cluster ``` |
| `helm install`, `upgrade`, `uninstall`, `delete`, `rollback` | Hook + `Bash(helm *)` | `helm release change` |
| `terraform workspace new/delete` | Hook | ``` `terraform workspace` change ``` |
| `aws`/`gcloud`/`az` calls that delete resources or change access control (`delete`, `terminate`, `revoke`, `set-iam-policy`, `add-iam-policy-binding`, `create-access-key`, …) | Hook + `Bash(aws *)` etc. | `aws call that deletes resources or changes access control` |
| Any other `kubectl`, `helm`, `docker`, `aws`, `gcloud`, `az` or `gh` command, including read-only ones such as `kubectl get` or `helm template` | `ask` rule in settings | |
| `terraform plan …`, `terraform init …` | `ask` rule in settings | |

## Step 3: Validate locally

What Claude can run without a prompt:

```bash
terraform fmt -check -recursive
terraform validate
pre-commit run --all-files
```

`pre-commit` includes **checkov**, which scans Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles, Bicep and GitHub Actions workflows for misconfigurations.

Run `terraform plan` (and `terraform init`, if needed) **yourself, in your own terminal**:

```bash
terraform init
terraform plan -out=tfplan
terraform show -no-color tfplan > plan.txt
```

Why not inside Claude Code? `plan` asks for approval anyway, and it needs cloud credentials and provider downloads. The sandbox only lets Bash reach `github.com`, the npm, PyPI and Go registries and your internal artifact registry, and it hides credential directories such as `~/.aws`. Running it yourself keeps your credentials out of the agent's shell. Review the plan, remove anything sensitive, and attach it to the pull request.

For Kubernetes, `kubectl diff -f k8s/` and `helm template` are read-only but still ask in Claude Code (`Bash(kubectl *)`, `Bash(helm *)`). Running them yourself is often simpler.

## Step 4: Open the pull request

For Tier 2 pull requests the policy asks you to:

1. Say that AI assistance was used, and for which parts. Keep the `Co-Authored-By: Claude` trailer that Claude Code adds to commits.
2. Attach the `terraform plan` output (or the equivalent dry run).
3. Explain the security impact in plain words.

## Step 5: Code-owner review

[`.github/CODEOWNERS`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/CODEOWNERS) assigns these paths to reviewers:

| Paths | Reviewer in the template |
|---|---|
| `*.tf`, `*.tfvars`, `*.hcl`, `Dockerfile*`, `**/k8s/`, `**/helm/`, `.github/workflows/` | `@pixelofsoftware` |
| `**/auth/`, `**/security/`, `**/crypto/` | `@pixelofsoftware` |
| The guardrail files | `@pixelofsoftware` |

The policy names Platform Engineering for infrastructure and AppSec for security code. Those are placeholders: replace `@pixelofsoftware` with your own teams. CODEOWNERS only blocks merges when branch protection requires code-owner review; see [Organisation rollout](Use-Case-Organisation-Rollout#7-protect-main-with-two-rulesets).

CI runs the `guardrails` job (shown as `ai-guardrails / guardrails`) on the pull request: the test suite plus every pre-commit check, so checkov and the secret scanners run even if someone committed with `--no-verify`.

## Step 6: Deploy through CI only

After merge, your deployment pipeline applies the change. This repository doesn't ship a deploy workflow, because deployment is specific to your organisation. Whatever you use, keep two properties:

- The apply runs from reviewed code on `main`, not from a laptop.
- Unattended or headless agent runs (`claude -p`, CI agents) run only in ephemeral containers with no production credentials ([policy §1](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#1-execution-controls)).

## Related pages

- [File guard](Guardrail-File-Guard)
- [Bash guard](Guardrail-Bash-Guard)
- [Commit and merge gates](Guardrail-Commit-and-Merge-Gates)
- [Organisation rollout](Use-Case-Organisation-Rollout)
- [Daily development](Use-Case-Daily-Development)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
