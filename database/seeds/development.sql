BEGIN;

-- Insert admin user
INSERT INTO users (username, email, password_hash, first_name, last_name, role)
VALUES (
    'admin',
    'admin@example.com',
    '$2b$10$EuMZ8JqNz8gxrXgFxE.YlOMrVGRvPIL9ZFKdw3T8N2T4jGglyFp8y', -- password: admin123
    'Admin',
    'User',
    'admin'
);

-- Insert test users
INSERT INTO users (username, email, password_hash, first_name, last_name, role)
VALUES
    ('user1', 'user1@example.com', '$2b$10$EuMZ8JqNz8gxrXgFxE.YlOMrVGRvPIL9ZFKdw3T8N2T4jGglyFp8y', 'Test', 'User1', 'user'),
    ('user2', 'user2@example.com', '$2b$10$EuMZ8JqNz8gxrXgFxE.YlOMrVGRvPIL9ZFKdw3T8N2T4jGglyFp8y', 'Test', 'User2', 'user'),
    ('moderator', 'mod@example.com', '$2b$10$EuMZ8JqNz8gxrXgFxE.YlOMrVGRvPIL9ZFKdw3T8N2T4jGglyFp8y', 'Mod', 'User', 'moderator');

-- Insert test logs
INSERT INTO logs (user_id, action, resource_type, resource_id, details, ip_address)
VALUES
    (1, 'LOGIN', 'user', 1, '{"browser": "Chrome", "platform": "Windows"}', '127.0.0.1'),
    (1, 'CREATE_USER', 'user', 2, '{"username": "user1"}', '127.0.0.1'),
    (1, 'UPDATE_SETTINGS', 'settings', null, '{"changed": ["email_notifications"]}', '127.0.0.1');

COMMIT;
