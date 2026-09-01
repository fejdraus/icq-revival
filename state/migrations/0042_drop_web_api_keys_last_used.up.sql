-- The last_used timestamp is not read anywhere, so the column is unused.
ALTER TABLE web_api_keys DROP COLUMN last_used;
