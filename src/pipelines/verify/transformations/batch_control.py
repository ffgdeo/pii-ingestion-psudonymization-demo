"""Step 5: verification gate. Nothing reaches pii_analytics unless its batch is VERIFIED here.

One row per (table, batch). Every check is a count; no values are ever written or logged.
The publish pipeline reads only batches with status = 'VERIFIED'.
"""
from functools import reduce

from pyspark import pipelines as dp
from pyspark.sql import functions as F

CAT = spark.conf.get("pii.catalog")
RAW, VAULT, GOV = f"{CAT}.pii_raw", f"{CAT}.pii_vault", f"{CAT}.pii_governance"

# Regex leak scan for undeclared cleartext PII in any string column that is not a known protected column.
LEAK_PATTERNS = {
    "email": "[^@ ]+@[^@ ]+[.][A-Za-z]{2,}",
    "ssn": "[0-9]{3}-[0-9]{2}-[0-9]{4}",
    "card": "[0-9]{13,19}",
    "phone": "([(]?[0-9]{3}[)]?[-. ][0-9]{3}[-. ][0-9]{4})|([+][0-9]{11,15})",
}
SOURCES = [
    # table, natural key, landing, valid, quarantine, pseudonymized candidate
    ("customers", "customer_id", "lfc_customers", "customers_valid", "customers_quarantine", "customers_pseudo"),
    ("transactions", "txn_id", "lfc_transactions", "transactions_valid", "transactions_quarantine", "transactions_pseudo"),
]


def _contract(table):
    rows = spark.read.table(f"{GOV}.pii_contract").where((F.col("table_name") == table) & F.col("active")).collect()
    return {r.column_name: r.asDict() for r in rows}


def _any(exprs):
    return " OR ".join(f"coalesce(({e}), false)" for e in exprs) if exprs else "false"


def _counts(table_name, alias):
    return spark.read.table(f"{RAW}.{table_name}").groupBy("_batch_id").agg(F.count("*").alias(alias))


def _metrics(table, key, landing, valid, quarantine, pseudo_name):
    con = _contract(table)
    enc = [c for c, s in con.items() if s["method"] == "encrypt"]
    tok = {c: s["key_or_vault"] for c, s in con.items() if s["method"] == "tokenize"}
    pii = [c for c, s in con.items() if s["method"] != "keep"]

    pseudo = spark.read.table(f"{RAW}.{pseudo_name}")
    protected = {f"{c}_enc" for c in enc} | {f"{c}_hmac" for c in enc} | {f"{c}_token" for c in tok}
    unprotected_columns = len([c for c in pseudo.columns if c in pii or c == "_rescued_data"])
    scan = [f.name for f in pseudo.schema.fields if f.dataType.typeName() == "string" and f.name not in protected]
    leak = _any([f"`{c}` RLIKE '{p}'" for c in scan for p in LEAK_PATTERNS.values()])
    missing_token = _any([f"`{c}_token` IS NULL" for c in tok])

    candidates = pseudo.groupBy("_batch_id").agg(
        F.count("*").alias("candidate_rows"),
        F.sum(F.expr(f"CASE WHEN {leak} THEN 1 ELSE 0 END")).alias("leak_rows"),
        F.sum(F.expr(f"CASE WHEN {missing_token} THEN 1 ELSE 0 END")).alias("missing_token_rows"))

    # Checks that compare against the cleartext source (allowed here: this pipeline runs as the SP).
    null_on_value = _any([f"v.`{c}` IS NOT NULL AND p.`{c}_enc` IS NULL" for c in enc] +
                         [f"v.`{c}` IS NOT NULL AND p.`{c}_token` IS NULL" for c in tok])
    equals_source = _any([f"p.`{c}_enc` = CAST(v.`{c}` AS STRING)" for c in enc] +
                         [f"p.`{c}_token` = v.`{c}`" for c in tok])
    compared = (spark.read.table(f"{RAW}.{valid}").alias("v")
                .join(pseudo.alias("p"), [key, "_batch_id"], "left")
                .groupBy("_batch_id").agg(
                    F.sum(F.expr(f"CASE WHEN {null_on_value} THEN 1 ELSE 0 END")).alias("null_on_value_rows"),
                    F.sum(F.expr(f"CASE WHEN {equals_source} THEN 1 ELSE 0 END")).alias("token_equals_source_rows")))

    # Vault integrity (global): a token with several values, or a value with several tokens.
    conflicts = spark.range(1).select(F.lit(0).alias("vault_conflicts"))
    for vault_table in tok.values():
        v = spark.read.table(f"{VAULT}.{vault_table}")
        c1 = v.groupBy("token").agg(F.countDistinct("value").alias("n")).where("n > 1").select(F.count("*").alias("a"))
        c2 = v.groupBy("value").agg(F.countDistinct("token").alias("n")).where("n > 1").select(F.count("*").alias("b"))
        conflicts = conflicts.crossJoin(c1).crossJoin(c2).select((F.col("vault_conflicts") + F.col("a") + F.col("b")).alias("vault_conflicts"))

    # Referential integrity (informational, not gating): transactions whose customer is unknown.
    if table == "transactions":
        orphans = (pseudo.join(spark.read.table(f"{RAW}.customers_pseudo").select("customer_id").distinct(), "customer_id", "left_anti")
                   .groupBy("_batch_id").agg(F.count("*").alias("orphan_rows")))
    else:
        orphans = spark.read.table(f"{RAW}.{landing}").select("_batch_id").distinct().withColumn("orphan_rows", F.lit(0).cast("long"))

    df = reduce(lambda a, b: a.join(b, "_batch_id", "left"), [
        _counts(landing, "landed_rows"), _counts(valid, "valid_rows"), _counts(quarantine, "quarantined_rows"),
        candidates, compared, orphans])
    metric_cols = ["valid_rows", "quarantined_rows", "candidate_rows", "leak_rows", "missing_token_rows",
                   "null_on_value_rows", "token_equals_source_rows", "orphan_rows"]
    return (df.na.fill(0, metric_cols).crossJoin(conflicts)
            .withColumn("table_name", F.lit(table))
            .withColumn("unprotected_columns", F.lit(unprotected_columns)))


GATE = {
    "counts_reconcile": "landed_rows = valid_rows + quarantined_rows",
    "every_valid_row_pseudonymized": "candidate_rows = valid_rows",
    "every_pii_column_protected": "unprotected_columns = 0",
    "no_null_on_value": "null_on_value_rows = 0",
    "no_token_equals_source": "token_equals_source_rows = 0",
    "every_token_resolves": "missing_token_rows = 0",
    "vault_has_no_conflicts": "vault_conflicts = 0",
    "no_cleartext_leak": "leak_rows = 0",
}


@dp.materialized_view(name="batch_control", comment="Verification gate results per table and batch. Publish reads only VERIFIED batches.")
@dp.expect_all(GATE)
def batch_control():
    df = reduce(lambda a, b: a.unionByName(b), [_metrics(*s) for s in SOURCES])
    passed = " AND ".join(f"({e})" for e in GATE.values())
    failed = F.array_compact(F.array(*[F.when(~F.expr(e), F.lit(n)) for n, e in GATE.items()]))
    return (df.withColumn("failed_checks", failed)
              .withColumn("status", F.when(F.expr(passed), F.lit("VERIFIED")).otherwise(F.lit("FAILED")))
              .withColumn("verified_at", F.current_timestamp())
              .select("table_name", F.col("_batch_id").alias("batch_id"), "status", "failed_checks", "landed_rows",
                      "valid_rows", "quarantined_rows", "candidate_rows", "leak_rows", "missing_token_rows",
                      "null_on_value_rows", "token_equals_source_rows", "vault_conflicts", "unprotected_columns",
                      "orphan_rows", "verified_at"))
