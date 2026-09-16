-- Queries behind report.md. Read-only; run with:
--   docker exec -i nsm-clickhouse clickhouse-client --database ep --query "<one query>"
-- Every claim in the report comes from one of these; the rows they returned are in findings.csv.

-- 1. What was recorded, per channel (report §2)
SELECT channel, count() AS n
FROM ep.win_events WHERE dataset = 'empire_launcher_vbs'
GROUP BY channel ORDER BY n DESC;

-- 2. Every process creation, both providers, with the ids the report cites (§3, §4)
SELECT ts, event_id, record_id, image, command_line, process_id, parent_process_id
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id IN (1, 4688)
ORDER BY ts;

-- 3. The file explorer.exe wrote when the user opened launcher.vbs (§3)
SELECT ts, record_id, image, target_filename
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id = 11
ORDER BY ts;

-- 4. Outbound connections, Sysmon and the filtering platform (§3, §5)
SELECT ts, record_id, hostname, user, image, source_ip, source_port, destination_ip, destination_port, initiated
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id = 3
ORDER BY ts;

SELECT ts, hostname, extra['Application'] AS app, extra['SourceAddress'] AS src,
       extra['DestAddress'] AS dst, extra['DestPort'] AS dport
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id = 5156 AND app ILIKE '%powershell%'
ORDER BY ts;

-- 5. The script block, and the fact that there is only one (§5, §6)
SELECT ts, record_id, hostname, user, length(script_block) AS chars
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id = 4104
ORDER BY ts;

-- 6. What module logging still recorded after it: every cmdlet the agent invoked (§3, §5)
SELECT ts, replaceAll(extract(extra['Payload'], 'CommandInvocation\\(([^)]*)\\)'), '\n', ' ') AS cmd
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id = 4103 AND cmd != ''
ORDER BY ts;

-- 7. The beacon: the gap between one Start-Sleep and the next (§3, §9)
WITH s AS (
  SELECT ts FROM ep.win_events
  WHERE dataset = 'empire_launcher_vbs' AND event_id = 4103
    AND extra['Payload'] ILIKE '%CommandInvocation(Start-Sleep)%'
  ORDER BY ts
)
SELECT ts, round(date_diff('millisecond', lagInFrame(ts) OVER (ORDER BY ts), ts) / 1000, 3) AS gap_s FROM s;

-- 8. Absence of the things a responder asks about first: persistence, LSASS access, log clearing (§5)
SELECT ts, image, target_object, details
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id IN (12, 13, 14)
  AND match(target_object, 'Run|Services|Winlogon|IFEO|TaskCache');

SELECT ts, source_image, target_image, granted_access
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id = 10 AND target_image ILIKE '%lsass.exe';

SELECT count() FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id IN (1102, 104);

-- 9. Timestamp caveat (§2): the collector's time is not the event's time.
--    Compare what the report prints with what Sysmon itself recorded.
SELECT ts AS collected, extra['UtcTime'] AS sysmon_utctime, event_id, image
FROM ep.win_events
WHERE dataset = 'empire_launcher_vbs' AND event_id IN (1, 3)
ORDER BY ts;
