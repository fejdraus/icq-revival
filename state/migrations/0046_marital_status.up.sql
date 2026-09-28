-- Marital status from the ICQ profile.
--
-- In the directory dialect this is tag 0x012C, and clients fill it in: QIP 2012
-- sends it as two bytes, Miranda as a word (icqosc_svcs.cpp, ppackTLVWord 0x12C).
-- The profile had no place for it, so the value was silently dropped.
--
-- The codes come from the client's reference list (10 - single, 11 - in a
-- relationship, 12 - engaged, 20 - married, 30 - divorced, 31 - separated,
-- 40 - widowed). Zero means "not specified".

ALTER TABLE users
    ADD COLUMN icq_moreInfo_maritalStatus INTEGER NOT NULL DEFAULT 0;
