-- Enforce one canonical private conversation for each verified user pair.
-- When legacy duplicates exist, keep the conversation with the most messages;
-- ties are resolved by oldest creation time, then stable ID. No conversation data is deleted.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS conversation_pairs (
  user_a_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  conversation_id TEXT NOT NULL UNIQUE REFERENCES conversations(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_a_id, user_b_id),
  CHECK (user_a_id < user_b_id)
);

WITH participants AS (
  SELECT
    c.id,
    c.created_at,
    MIN(cm.user_id) AS user_a_id,
    MAX(cm.user_id) AS user_b_id,
    COUNT(*) AS member_count
  FROM conversations c
  JOIN conversation_members cm ON cm.conversation_id = c.id
  GROUP BY c.id
  HAVING COUNT(*) = 2
),
ranked AS (
  SELECT
    p.*,
    ROW_NUMBER() OVER (
      PARTITION BY p.user_a_id, p.user_b_id
      ORDER BY
        (SELECT COUNT(*) FROM encrypted_messages em WHERE em.conversation_id = p.id) DESC,
        p.created_at ASC,
        p.id ASC
    ) AS pair_rank
  FROM participants p
)
INSERT OR IGNORE INTO conversation_pairs (user_a_id, user_b_id, conversation_id, created_at)
SELECT user_a_id, user_b_id, id, created_at
FROM ranked
WHERE pair_rank = 1;
