
# ESL Bitbucket → ADO Migration Script

This tool migrates ESL-scoped Bitbucket Cloud repositories (and pipeline-related bits) into a target Azure DevOps project.

## What it moves
- **Repositories** (full history: branches & tags) via Git mirror
- **Pipelines (YAML)**: If `azure-pipelines.yml` exists, it creates an ADO Pipeline. If only `bitbucket-pipelines.yml` is found, you can optionally copy it into the repo as `azure-pipelines.yml` (manual conversion required).
- **Variables**: If `variables.csv` is present, creates an ADO Variable Group per repo (`{repo}-migrated-vars`). Marked secrets are created as empty placeholders unless `--push-secrets` is used.

> ⚠️ Service connections, environment approvals, and third-party integrations must be re-created manually in ADO.

## Inputs
Place the analysis CSVs alongside the script (or pass their paths):
- `projects.csv` (must include `project_key`, `project_name`)
- `repos.csv` (must include `workspace`, `project_key`, `repo_slug`, `repo_name`)
- `variables.csv` (optional: `workspace`, `project_key`, `repo_slug`, `name`, `value`, `is_secret`)

Only the **ESL** project (where `project_name == "ESL"` or `project_key == "esl"`) is migrated.

## Config
Copy and edit `migration_config.example.ini` to `migration_config.ini`:

```
[bitbucket]
workspace = YOUR_BB_WORKSPACE
username  = YOUR_BB_USERNAME
app_password = YOUR_BB_APP_PASSWORD

[ado]
org = YOUR_ADO_ORG
pat = YOUR_ADO_PAT
```

Bitbucket App Password requires: `repo:read` and `pipelines:read` scopes.
ADO PAT requires: `Code (Read & write)`, `Build (Read & execute)`, `Release (Read)`, `Variable Groups (Read & manage)`.

## Usage

Dry-run first:
```
python migrate_esl_bitbucket_to_ado.py --config migration_config.ini   --ado-project ESL_Migrated --bb-workspace YOUR_WS --dry-run
```

Execute for real:
```
python migrate_esl_bitbucket_to_ado.py --config migration_config.ini   --ado-project ESL_Migrated --bb-workspace YOUR_WS
```

Create ADO pipelines from YAML (and copy Bitbucket YAMLs when needed):
```
python migrate_esl_bitbucket_to_ado.py --config migration_config.ini   --ado-project ESL_Migrated --bb-workspace YOUR_WS --convert-bb-yaml
```

Include secret values from `variables.csv` (use with caution):
```
python migrate_esl_bitbucket_to_ado.py --config migration_config.ini   --ado-project ESL_Migrated --bb-workspace YOUR_WS --push-secrets
```

## Notes & Recommendations
- Ensure `git` is installed and you’re authenticated to ADO (or be ready to enter credentials on first push).
- Repo names that collide in ADO will be reused; rename in Bitbucket or adjust in ADO if needed.
- YAML conversion is **not automatic**. Review and update `azure-pipelines.yml` after migration.
- Consider creating service connections in ADO before first pipeline run.
- If `repos.csv` or `projects.csv` are missing, the script will query Bitbucket’s API and filter by `--bb-project-key esl`.
