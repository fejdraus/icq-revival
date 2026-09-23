DROP INDEX IF EXISTS idx_loginEmail_email;

ALTER TABLE loginEmail RENAME COLUMN boundAt TO verifiedAt;
ALTER TABLE loginEmail RENAME TO verifiedEmail;

CREATE INDEX IF NOT EXISTS idx_verifiedEmail_email ON verifiedEmail(email);
