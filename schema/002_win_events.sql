-- ep.win_events — one row per Windows event from a recorded dataset.
--
-- Datasets mix channels (Sysmon, Security, PowerShell), and each event type carries its own fields. The columns below
-- are the fields worth querying across event types, normalised so a rule can use one name: a process creation from
-- Sysmon 1 and from Security 4688 both land in image/command_line/parent_image. Everything else is kept verbatim in
-- `extra`, so nothing is lost and the raw event can still be reconstructed.
--
-- PARTITION BY dataset: loading a dataset drops and rewrites exactly one partition, which makes reloads idempotent.
-- No TTL: these are reference recordings, not live logs.
CREATE TABLE IF NOT EXISTS ep.win_events
(
    `dataset`              LowCardinality(String),
    `ts`                   DateTime64(3, 'UTC'),
    `record_id`            UInt64,
    `hostname`             LowCardinality(String),
    `channel`              LowCardinality(String),
    `provider`             LowCardinality(String),
    `event_id`             UInt16,
    `task`                 UInt16,
    `user`                 String,

    -- process (Sysmon 1, 5, 10, 11-13; Security 4688)
    `process_guid`         String,
    `process_id`           UInt32,
    `image`                String,
    `original_file_name`   String,
    `command_line`         String CODEC(ZSTD(1)),
    `current_directory`    String,
    `integrity_level`      LowCardinality(String),
    `logon_id`             String,
    `hashes`               String,
    `parent_process_guid`  String,
    `parent_process_id`    UInt32,
    `parent_image`         String,
    `parent_command_line`  String CODEC(ZSTD(1)),

    -- network (Sysmon 3)
    `protocol`             LowCardinality(String),
    `initiated`            LowCardinality(String),
    `source_ip`            String,
    `source_port`          UInt16,
    `destination_ip`       String,
    `destination_hostname` String,
    `destination_port`     UInt16,

    -- file, registry, image load, process access (Sysmon 7, 10, 11, 12-14, 23)
    `target_filename`      String,
    `target_object`        String,
    `details`              String,
    `image_loaded`         String,
    `signature`            String,
    `signature_status`     LowCardinality(String),
    `source_image`         String,
    `target_image`         String,
    `granted_access`       String,
    `call_trace`           String CODEC(ZSTD(1)),

    -- logon and script content (Security 4624/4625/4648, PowerShell 4104)
    `logon_type`           LowCardinality(String),
    `ip_address`           String,
    `script_block`         String CODEC(ZSTD(3)),

    `message`              String CODEC(ZSTD(3)),
    `extra`                Map(String, String) CODEC(ZSTD(3)),

    INDEX idx_process_guid process_guid TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_event_id     event_id     TYPE set(200)           GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY dataset
ORDER BY (dataset, ts, record_id)
SETTINGS index_granularity = 8192;
