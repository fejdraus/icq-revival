-- Auditors' cosignatures over the E2E key log's checkpoints
-- (docs/e2e/KEY-TRANSPARENCY.md, stage 2): the latest one of each auditor.
-- line is the signature line the auditor sent (c2sp.org/tlog-cosignature);
-- size is the checkpoint it signs, time its timestamp in Unix seconds.
CREATE TABLE IF NOT EXISTS e2e_kt_cosignature
(
    auditor TEXT PRIMARY KEY,
    size    INTEGER NOT NULL,
    time    INTEGER NOT NULL,
    line    TEXT    NOT NULL
);
