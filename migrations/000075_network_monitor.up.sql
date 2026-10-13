-- Explicit enrollment only. Discovery never changes the expected set.
CREATE TABLE gp09_network_monitors (
 cluster_id text PRIMARY KEY REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
 collector_id text NOT NULL REFERENCES collectors(collector_id) ON DELETE RESTRICT,
 revision text NOT NULL,
 enrollment jsonb NOT NULL,
 enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_received_at timestamptz,
 summary jsonb NOT NULL DEFAULT '{}'
);
-- Bounded four-cycle replay window, not an unbounded raw telemetry archive.
CREATE TABLE gp09_network_cycles (
 cluster_id text NOT NULL REFERENCES gp09_network_monitors(cluster_id) ON DELETE RESTRICT,
 cycle_id bigserial PRIMARY KEY,
 polls jsonb NOT NULL,
 duration_ms integer NOT NULL DEFAULT 0 CHECK(duration_ms BETWEEN 0 AND 65000),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX gp09_network_cycle_latest ON gp09_network_cycles(cluster_id,cycle_id DESC);
CREATE TABLE gp09_network_episodes (
 episode_id text PRIMARY KEY,
 cluster_id text NOT NULL REFERENCES gp09_network_monitors(cluster_id) ON DELETE RESTRICT,
 entity_key text NOT NULL,
 reason text NOT NULL,
 opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 closed_at timestamptz
);
CREATE UNIQUE INDEX gp09_network_episode_open ON gp09_network_episodes(cluster_id,entity_key) WHERE closed_at IS NULL;

-- A passive counter increase is an event, not proof of a current DOWN port.
ALTER TABLE gp09_alert_outbox DROP CONSTRAINT gp09_alert_outbox_transition_check;
ALTER TABLE gp09_alert_outbox ADD CONSTRAINT gp09_alert_outbox_transition_check
 CHECK(transition IN ('TEST','SOURCE_GAP','PORT_DOWN','LINK_EVENT','RECOVERED'));
