"""Customers: steps 1-4 in the restricted zone (pii_raw / pii_vault).

lfc_customers (landing) -> customers_conformed (schema check + normalization)
  -> customers_valid (cleartext DQ, drop) / customers_quarantine (failed rows, stays in pii_raw)
  -> customers_protected (Pattern A encryption + HMAC, drop street_address)
  -> pii_vault.tokmap_* (Pattern B token vault, one token per normalized value)
  -> customers_pseudo (tokens swapped in, no cleartext left; checked by the verify pipeline)
"""
from pyspark import pipelines as dp
from pyspark.sql import functions as F

from utilities.pii_contract import all_rules_pass, conform, failed_rules, flatten_protected, load_contract, protect

CAT = spark.conf.get("pii.catalog")
RAW, VAULT, GOV = f"{CAT}.pii_raw", f"{CAT}.pii_vault", f"{CAT}.pii_governance"
CONTRACT = load_contract(spark, GOV, "customers")
TOKENIZE = {c: s for c, s in CONTRACT.items() if s["method"] == "tokenize"}

# Step 3a: checks that need the real (normalized) values. Patterns avoid backslashes on purpose.
RULES = {
    "customer_id_present": "customer_id IS NOT NULL",
    "name_present": "full_name IS NOT NULL AND full_name <> ''",
    "valid_email": "email RLIKE '^[^@ ]+@[^@ ]+[.][a-z]{2,}$'",
    "valid_phone_e164": "phone RLIKE '^[+][0-9]{11,15}$'",
    "valid_ssn": "length(ssn) = 9 AND ssn NOT LIKE '000%' AND substr(ssn, 4, 2) <> '00'",
    "no_rescued_data": "_rescued_data IS NULL",
}
RAW_ZONE_PROPS = {"delta.deletedFileRetentionDuration": "interval 7 days", "delta.logRetentionDuration": "interval 7 days"}


@dp.temporary_view(name="customers_conformed")
def customers_conformed():
    return conform(spark.readStream.table(f"{RAW}.lfc_customers"), CONTRACT)


# Not resettable: the token vault streams from this table, and a reset would regenerate tokens.
@dp.table(name="customers_valid", comment="Cleartext rows that passed DQ (restricted zone).",
          table_properties={**RAW_ZONE_PROPS, "pipelines.reset.allowed": "false"})
@dp.expect_all_or_drop({k: f"coalesce(({v}), false)" for k, v in RULES.items()})
def customers_valid():
    return spark.readStream.table("customers_conformed")


@dp.table(name="customers_quarantine", comment="Rows that failed DQ or carried undeclared columns. Contains PII: restricted zone only.",
          table_properties=RAW_ZONE_PROPS)
def customers_quarantine():
    return (spark.readStream.table("customers_conformed")
            .where(f"NOT ({all_rules_pass(RULES)})")
            .withColumn("_failed_rules", failed_rules(RULES))
            .withColumn("_quarantined_at", F.current_timestamp()))


@dp.table(name="customers_protected", comment="Pattern A applied: ssn/phone/dob encrypted + HMAC, street_address dropped.",
          table_properties=RAW_ZONE_PROPS)
def customers_protected():
    return protect(spark.readStream.table("customers_valid"), CONTRACT, VAULT)


def _vault_table(column: str, vault_table: str):
    """Pattern B vault: one uuid token per distinct normalized value, assigned once and never regenerated."""
    @dp.table(name=f"{VAULT}.{vault_table}", comment=f"Token vault for customers.{column}. Restricted: pseudonymization SP only.",
              table_properties={"pipelines.reset.allowed": "false"})
    def _vault():
        return (spark.readStream.table("customers_valid")
                .select(F.col(column).alias("value"))
                .where("value IS NOT NULL")
                .dropDuplicates(["value"])
                .select(F.expr("uuid()").alias("token"), "value", F.current_timestamp().alias("created_at")))


for _col, _spec in TOKENIZE.items():
    _vault_table(_col, _spec["key_or_vault"])


@dp.materialized_view(name="customers_pseudo", comment="Fully pseudonymized customers, pending the verification gate.",
                      table_properties=RAW_ZONE_PROPS)
def customers_pseudo():
    df = flatten_protected(spark.read.table("customers_protected"), CONTRACT)
    for col, spec in TOKENIZE.items():
        tokens = spark.read.table(f"{VAULT}.{spec['key_or_vault']}").select(
            F.col("value").alias(col), F.col("token").alias(f"{col}_token"))
        df = df.join(tokens, col, "left").drop(col)
    return df
