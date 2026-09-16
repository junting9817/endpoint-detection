# shellcheck shell=bash
# ClickHouse access for this project. The server is the NSM lab's container; only the `ep` database is written.
# Source this file; do not run it.

GY_CH_CONTAINER=${EP_CH_CONTAINER:-nsm-clickhouse}

# ch <sql>            : run a query, print the result
# ch_insert <table>   : stream stdin into a table as JSONEachRow
ch() {
  docker exec "$GY_CH_CONTAINER" clickhouse-client --database ep --query "$1"
}

ch_file() { # ch_file <file.sql> — run a whole file (multiple statements)
  docker exec -i "$GY_CH_CONTAINER" clickhouse-client --multiquery <"$1"
}

ch_insert() { # ch_insert <table> — stdin is JSONEachRow
  docker exec -i "$GY_CH_CONTAINER" clickhouse-client --database ep \
    --query "INSERT INTO $1 FORMAT JSONEachRow" \
    --input_format_skip_unknown_fields 1 --date_time_input_format best_effort
}

ch_ready() {
  docker exec "$GY_CH_CONTAINER" clickhouse-client --query "SELECT 1" >/dev/null 2>&1
}
