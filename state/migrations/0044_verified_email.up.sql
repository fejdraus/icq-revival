-- Addresses confirmed by the password-recovery service. Old clients label the
-- login field "ICQ#/Email" because the real server accepted a validated email
-- address in place of the number; this table is what makes an address
-- validated here. It is written by the registration service when the owner
-- follows the link in the confirmation letter, and is only read at login.
--
-- The address is deliberately not unique: two people may confirm the same
-- mailbox, and an ambiguous address must fail to sign in rather than pick one.

CREATE TABLE IF NOT EXISTS verifiedEmail (
    identScreenName TEXT PRIMARY KEY,
    email           TEXT NOT NULL,
    verifiedAt      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verifiedEmail_email ON verifiedEmail(email);
