"""Transactions: steps 1-4 in the restricted zone.

lfc_transactions -> transactions_conformed -> transactions_valid / transactions_quarantine
  -> transactions_pseudo (card_number dropped per the contract)
"""
from pyspark import pipelines as dp
from pyspark.sql import functions as F

from utilities.pii_contract import all_rules_pass, conform, failed_rules, load_contract, protect

CAT = spark.conf.get("pii.catalog")
RAW, VAULT, GOV = f"{CAT}.pii_raw", f"{CAT}.pii_vault", f"{CAT}.pii_governance"
CONTRACT = load_contract(spark, GOV, "transactions")

RULES = {
    "txn_id_present": "txn_id IS NOT NULL",
    "customer_id_present": "customer_id IS NOT NULL",
    "positive_amount": "amount > 0",
    "known_currency": "currency IN ('EUR', 'USD', 'GBP')",
    "no_rescued_data": "_rescued_data IS NULL",
}
RAW_ZONE_PROPS = {"delta.deletedFileRetentionDuration": "interval 7 days", "delta.logRetentionDuration": "interval 7 days"}


@dp.temporary_view(name="transactions_conformed")
def transactions_conformed():
    return conform(spark.readStream.table(f"{RAW}.lfc_transactions"), CONTRACT)


@dp.table(name="transactions_valid", comment="Cleartext transactions that passed DQ (restricted zone).",
          table_properties=RAW_ZONE_PROPS)
@dp.expect_all_or_drop({k: f"coalesce(({v}), false)" for k, v in RULES.items()})
def transactions_valid():
    return spark.readStream.table("transactions_conformed")


@dp.table(name="transactions_quarantine", comment="Failed transactions. Contains PII (card numbers): restricted zone only.",
          table_properties=RAW_ZONE_PROPS)
def transactions_quarantine():
    return (spark.readStream.table("transactions_conformed")
            .where(f"NOT ({all_rules_pass(RULES)})")
            .withColumn("_failed_rules", failed_rules(RULES))
            .withColumn("_quarantined_at", F.current_timestamp()))


@dp.table(name="transactions_pseudo", comment="Transactions with PII removed per the contract, pending the verification gate.",
          table_properties=RAW_ZONE_PROPS)
def transactions_pseudo():
    return protect(spark.readStream.table("transactions_valid"), CONTRACT, VAULT)
