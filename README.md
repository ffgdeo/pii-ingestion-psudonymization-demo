# PII ingestion, ABAC secure-by-default and reversible pseudonymization on Databricks

A Declarative Automation Bundle that demonstrates:

* **Secure by default with ABAC**: every column masked and every row filtered in the restricted zones for all account users, except the pipeline service principal.
* **Contract-driven ingestion** (steps 0-6 of the PII Ingestion Architecture): schema enforcement, PII tagging, cleartext data quality with quarantine, normalization, pseudonymization, verification gate, publish.
* **Reversible pseudonymization, two patterns**:
  * Pattern A, field-level encryption: AES-256-GCM via Unity Catalog Python UDFs that declare **Unity Catalog secrets** in a `SECRETS` clause (callers never see key material), plus an HMAC column to keep encrypted values joinable.
  * Pattern B, token vault: one `uuid()` token per normalized value in restricted vault tables.
* Everything runs as one **service principal**, the only identity that can see cleartext or re-identify.

## Zones (schemas in one catalog)

| Schema | Contents | Access |
| --- | --- | --- |
| `pii_raw` | Simulated Lakeflow Connect SQL Server landing (`lfc_customers`, `lfc_transactions`), valid/quarantine/protected staging | ABAC: all columns masked, all rows filtered, except the SP |
| `pii_vault` | UC secrets, encrypt/decrypt/HMAC UDFs, token vault tables | No grants + same ABAC lockdown, except the SP |
| `pii_governance` | `pii_contract` (column allow-list + method), `batch_control` (gate results) | Read for account users, no PII |
| `pii_analytics` | Published pseudonymized tables | Read for account users |

The account had no room for new governed tags, so the demo uses the **system governed `class.*` tags** (the ones Data Classification writes) on the raw columns, and policies without a `WHEN` clause so they cover every current and future table in the schema. Output columns get ungoverned tags (`pii_protection`, `source_pii_type`).

## Flow

```
pii_setup_job (once):  schemas + contract -> secrets + UDFs (self-test) -> seed landing -> class.* tags + ABAC policies
pii_main_job:          raw pipeline -> verify pipeline -> publish pipeline -> tag outputs -> re-identification check
pii_scenarios_job:     land batch 2 (undeclared column, bad emails, orphan txn, planted email leak) -> pii_main_job
```

* **Raw pipeline** (`src/pipelines/raw`): contract schema check (`_rescued_data`), expectations + quarantine flows, normalization (lower_trim, E.164, digits_only), `pii_protect` encryption, vault streaming tables (`pipelines.reset.allowed=false`), `customers_pseudo`.
* **Verify pipeline** (`src/pipelines/verify`): `batch_control`, one row per table and batch. 8 checks: counts reconcile, every valid row pseudonymized, no unprotected PII column, no null-on-value, no token equal to its source, every token resolves, no vault conflicts, regex leak scan.
* **Publish pipeline** (`src/pipelines/publish`): only `VERIFIED` batches, only contract allow-listed columns, business-rule expectations, example gold aggregate.

## Deploy

One-time admin bootstrap (outside the bundle):

1. Create the service principal and enable its **Workspace access** entitlement.
2. Give yourself the **Service Principal User** role on it (needed to deploy with `run_as`).
3. `GRANT USE CATALOG, CREATE SCHEMA ON CATALOG <catalog> TO <sp-application-id>`.
4. Give the SP read access to this Git folder (source-linked deployment runs the files from here).
5. Set `sp_application_id` (and `catalog`) in `databricks.yml`.

Then:

```
databricks bundle deploy -t dev
databricks bundle run pii_setup_job -t dev
databricks bundle run pii_main_job -t dev
databricks bundle run pii_scenarios_job -t dev
```

## Notes and limitations

* UC Python UDFs with `SECRETS` need environment version 6+. In a pipeline they currently work on the `PREVIEW` channel (the raw pipeline uses it). `CURRENT` fails with `SECRETS_NOT_ENABLED`.
* A query can call at most 5 UC Python UDFs (public preview), so `pii_protect` returns ciphertext and HMAC in one call.
* ABAC does not govern secrets or functions. Anyone with `ALL PRIVILEGES` on the catalog inherits `READ SECRET` and `EXECUTE`. For real separation of duties, put `pii_vault` in its own catalog and grant it only to the SP.
* Full refresh never regenerates tokens: the vault tables and `customers_valid` are not resettable.
* Synthetic data only.
