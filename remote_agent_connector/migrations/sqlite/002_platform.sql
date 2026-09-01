ALTER TABLE remote_agent_devices
ADD COLUMN platform TEXT NOT NULL DEFAULT 'unknown';
