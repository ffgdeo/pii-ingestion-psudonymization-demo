"""Contract-driven helpers for the raw (restricted-zone) pipeline.

The PII contract (pii_governance.pii_contract) is the single source of truth: it is the column allow-list,
and it says how each column is normalized and protected (keep | tokenize | encrypt | drop).
"""
from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F

LINEAGE_COLUMNS = ["_source_system", "_ingest_ts", "_batch_id"]


def load_contract(spark, gov_schema: str, table_name: str) -> dict:
    """Active contract entries for one source table, keyed by column name (read once at graph build)."""
    rows = (spark.read.table(f"{gov_schema}.pii_contract")
            .where((F.col("table_name") == table_name) & F.col("active"))
            .collect())
    return {r.column_name: r.asDict() for r in rows}


def _normalize(col: str, rule: str) -> Column:
    """Step 3b: normalization before tokenizing, so one person always gets one token."""
    c = F.col(col)
    if rule == "lower_trim":
        return F.lower(F.trim(c))
    if rule == "digits_only":
        return F.regexp_replace(c.cast("string"), "[^0-9]", "")
    if rule == "e164":
        d = F.regexp_replace(c.cast("string"), "[^0-9]", "")
        return (F.when(F.length(d) == 10, F.concat(F.lit("+1"), d))
                 .when((F.length(d) == 11) & d.startswith("1"), F.concat(F.lit("+"), d)))
    if rule == "name":
        return F.initcap(F.regexp_replace(F.trim(c), " +", " "))
    return c


def conform(df: DataFrame, contract: dict) -> DataFrame:
    """Step 1: schema enforcement against the contract.

    Contract columns are selected, cast and normalized. Any column the contract does not declare is packed
    into _rescued_data (treated as PII) so it can never flow downstream; the row is then quarantined.
    """
    undeclared = [c for c in df.columns if c not in contract and c not in LINEAGE_COLUMNS]
    if undeclared:
        any_value = F.coalesce(*[F.col(c).cast("string") for c in undeclared])
        rescued = F.when(any_value.isNotNull(), F.to_json(F.struct(*[F.col(c) for c in undeclared])))
    else:
        rescued = F.lit(None).cast("string")
    cols = []
    for name, spec in contract.items():
        expr = _normalize(name, spec["normalize_rule"]) if name in df.columns else F.lit(None)
        cols.append(expr.cast(spec["data_type"]).alias(name))
    lineage = [F.col(c) for c in LINEAGE_COLUMNS if c in df.columns]
    return df.select(*cols, *lineage, rescued.alias("_rescued_data"))


def all_rules_pass(rules: dict) -> str:
    return " AND ".join(f"coalesce(({e}), false)" for e in rules.values())


def failed_rules(rules: dict) -> Column:
    """Names of the rules a quarantined row failed (counts and names only, never values)."""
    return F.array_compact(F.array(*[
        F.when(~F.coalesce(F.expr(e), F.lit(False)), F.lit(n)) for n, e in rules.items()]))


def protect(df: DataFrame, contract: dict, vault_schema: str) -> DataFrame:
    """Step 4 (Pattern A + data minimization): encrypt and drop per the contract.

    encrypt -> <col>_enc (AES-256-GCM via a UC UDF that reads the key from a UC secret) + <col>_hmac (joinable)
    drop    -> removed. tokenize columns are left for the vault join (Pattern B).

    pii_protect returns both values in one call (a query may call at most 5 UC Python UDFs during the
    public preview). The result is stored as a struct <col>_protected and flattened downstream by
    flatten_protected(), so the optimizer never duplicates the UDF call (which would also change the IV).
    """
    for name, spec in contract.items():
        if spec["method"] == "encrypt":
            df = (df.withColumn(f"{name}_protected", F.expr(
                        f"{vault_schema}.pii_protect(CAST(`{name}` AS STRING), '{spec['key_or_vault']}')"))
                    .drop(name))
        elif spec["method"] == "drop":
            df = df.drop(name)
    return df.drop("_rescued_data").withColumn("pii_key_version", F.lit(1))


def flatten_protected(df: DataFrame, contract: dict) -> DataFrame:
    """<col>_protected struct -> <col>_enc + <col>_hmac."""
    for name, spec in contract.items():
        if spec["method"] == "encrypt":
            s = f"{name}_protected"
            df = (df.withColumn(f"{name}_enc", F.col(f"{s}.enc"))
                    .withColumn(f"{name}_hmac", F.col(f"{s}.hmac"))
                    .drop(s))
    return df
