BEGIN;

-- Insert test admin
INSERT INTO users (username, email, password_hash, first_name, last_name, role)
VALUES (
    'test_admin',
    'test_admin@example.com',
    '$2b$10$EuMZ8JqNz8gxrXgFxE.YlOMrVGRvPIL9ZFKdw3T8N2T4jGglyFp8y', -- password: test123
    'Test',
    'Admin',
    'admin'
);

-- Insert test user
INSERT INTO users (username, email, password_hash, first_name, last_name, role)
VALUES (
    'test_user',
    'test_user@example.com',
    '$2b$10$EuMZ8JqNz8gxrXgFxE.YlOMrVGRvPIL9ZFKdw3T8N2T4jGglyFp8y',
    'Test',
    'User',
    'user'
);

-- Insert test session
INSERT INTO sessions (user_id, token, ip_address, expires_at)
VALUES (
    1,
    'test_token_123',
    '127.0.0.1',
    CURRENT_TIMESTAMP + INTERVAL '1 day'
);

-- Insert test logs
INSERT INTO logs (user_id, action, resource_type, details, ip_address)
VALUES
    (1, 'TEST_ACTION', 'test', '{"test": true}', '127.0.0.1');

COMMIT;
