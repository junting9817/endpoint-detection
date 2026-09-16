-- ep.datasets — provenance for every loaded recording: where it came from, its hashes, and what it contains.
-- ReplacingMergeTree keyed on the dataset id: re-loading a dataset replaces its row rather than duplicating it.
CREATE TABLE IF NOT EXISTS ep.datasets
(
    `dataset`        String,
    `source_url`     String,
    `archive_sha256` String,
    `json_sha256`    String,
    `events`         UInt64,
    `first_ts`       DateTime64(3, 'UTC'),
    `last_ts`        DateTime64(3, 'UTC'),
    `hosts`          Array(String),
    `channels`       Array(String),
    `technique`      String,
    `note`           String,
    `loaded_at`      DateTime('UTC')
)
ENGINE = ReplacingMergeTree(loaded_at)
ORDER BY dataset;
