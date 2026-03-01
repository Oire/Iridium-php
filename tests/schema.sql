CREATE TABLE IF NOT EXISTS iridium_tokens (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    token_type INT,
    selector VARCHAR(255) NOT NULL UNIQUE,
    verifier VARCHAR(255) NOT NULL UNIQUE,
    additional_info TEXT,
    expiration_time BIGINT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
