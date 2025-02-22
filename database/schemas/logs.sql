-- Logs Schema Definition
CREATE TABLE logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    details JSONB,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_action CHECK (action ~ '^[A-Z_]+$')
);

-- Indexes
CREATE INDEX idx_logs_user_id ON logs(user_id);
CREATE INDEX idx_logs_action ON logs(action);
CREATE INDEX idx_logs_created_at ON logs(created_at);
CREATE INDEX idx_logs_resource ON logs(resource_type, resource_id);
CREATE INDEX idx_logs_details ON logs USING GIN (details);

-- Partitioning by time
CREATE OR REPLACE FUNCTION create_logs_partition()
RETURNS TRIGGER AS $$
DECLARE
    partition_date TEXT;
    partition_name TEXT;
BEGIN
    partition_date := TO_CHAR(NEW.created_at, 'YYYY_MM');
    partition_name := 'logs_' || partition_date;
    
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = partition_name) THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF logs FOR VALUES FROM (%L) TO (%L)',
            partition_name,
            date_trunc('month', NEW.created_at),
            date_trunc('month', NEW.created_at) + interval '1 month'
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER create_logs_partition_trigger
    BEFORE INSERT ON logs
    FOR EACH ROW
    EXECUTE FUNCTION create_logs_partition();

-- Automatic cleanup of old logs
CREATE OR REPLACE FUNCTION cleanup_old_logs()
RETURNS void AS $$
BEGIN
    DELETE FROM logs
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '6 months';
END;
$$ LANGUAGE plpgsql;

-- Permissions
GRANT SELECT, INSERT ON logs TO app_user;
GRANT USAGE ON SEQUENCE logs_id_seq TO app_user;
