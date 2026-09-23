-- The table from 0044 held addresses the recovery service had confirmed by
-- letter. Confirmation is no longer what makes an address usable for signing
-- in: an address can only be attached to an account by someone who already
-- knows its password, so it opens nothing that was not already open. What the
-- address must be is unique, and that is checked wherever one is written.
--
-- Renamed accordingly. The addresses in the ICQ profile (icq_basicInfo_
-- emailAddress) and in the AIM account (emailAddress) work for signing in too;
-- this table only adds the one the recovery service keeps in its own database.

ALTER TABLE verifiedEmail RENAME TO loginEmail;
ALTER TABLE loginEmail RENAME COLUMN verifiedAt TO boundAt;

DROP INDEX IF EXISTS idx_verifiedEmail_email;
CREATE INDEX IF NOT EXISTS idx_loginEmail_email ON loginEmail(email);
