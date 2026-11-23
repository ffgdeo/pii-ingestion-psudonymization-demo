"""Step 6: publish to the pseudonymized zone (pii_analytics).

Only VERIFIED batches (pii_governance.batch_control) and only contract allow-listed output columns are published.
_rescued_data, quarantine and cleartext columns can never reach this zone. Business-rule checks that do not
need cleartext run here.
"""
from pyspark import pipelines as dp
from pyspark.sql import Window
from pyspark.sql import functions as F

CAT = spark.conf.get("pii.catalog")
RAW, GOV = f"{CAT}.pii_raw", f"{CAT}.pii_governance"
OUTPUT_LINEAGE = ["_batch_id", "_ingest_ts"]


def _allow_list(table):
    """Output columns derived from the contract: keep columns + their protected forms. Nothing else."""
    rows = spark.read.table(f"{GOV}.pii_contract").where((F.col("table_name") == table) & F.col("active")).collect()
    cols = []
    for r in rows:
        if r.method == "keep":
            cols.append(r.column_name)
        elif r.method == "encrypt":
            cols += [f"{r.column_name}_enc", f"{r.column_name}_hmac"]
        elif r.method == "tokenize":
            cols.append(f"{r.column_name}_token")
    if any(r.method == "encrypt" for r in rows):
        cols.append("pii_key_version")
    return cols + OUTPUT_LINEAGE


def _verified(table, source):
    verified = (spark.read.table(f"{GOV}.batch_control")
                .where((F.col("table_name") == table) & (F.col("status") == "VERIFIED"))
                .select(F.col("batch_id").alias("_batch_id")))
    return spark.read.table(f"{RAW}.{source}").join(verified, "_batch_id", "left_semi").select(*_allow_list(table))


@dp.materialized_view(name="customers", comment="Pseudonymized customers (latest version per customer). Tokens and ciphertext only.")
@dp.expect_all({
    "signup_not_in_future": "signup_date <= current_date()",
    "known_segment": "segment IN ('retail', 'premium', 'business', 'student')",
    "email_token_present": "email_token IS NOT NULL",
})
def customers():
    latest = Window.partitionBy("customer_id").orderBy(F.col("_ingest_ts").desc(), F.col("_batch_id").desc())
    return (_verified("customers", "customers_pseudo")
            .withColumn("_rn", F.row_number().over(latest)).where("_rn = 1").drop("_rn"))


@dp.materialized_view(name="transactions", comment="Transactions from verified batches. card_number removed (data minimization).")
@dp.expect_all({
    "amount_under_review_limit": "amount < 10000",
    "txn_not_in_future": "txn_ts <= current_timestamp()",
})
def transactions():
    return _verified("transactions", "transactions_pseudo")


@dp.materialized_view(name="customer_spend_by_segment", comment="Example gold aggregate: analytics on pseudonymized data, joined on customer_id.")
def customer_spend_by_segment():
    c = spark.read.table("customers")
    t = spark.read.table("transactions")
    return (t.join(c, "customer_id")
            .groupBy("segment", "currency")
            .agg(F.countDistinct("email_token").alias("distinct_customers"),
                 F.count("*").alias("transactions"),
                 F.sum("amount").alias("total_amount")))
