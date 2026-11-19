-- Native node subscription visibility is independent of inbound enablement.
-- Existing and new nodes retain the previous default subscription behavior.
ALTER TABLE nodes ADD COLUMN include_in_sub INTEGER NOT NULL DEFAULT 1 CHECK(include_in_sub IN (0,1));
ALTER TABLE xray_nodes ADD COLUMN include_in_sub INTEGER NOT NULL DEFAULT 1 CHECK(include_in_sub IN (0,1));
