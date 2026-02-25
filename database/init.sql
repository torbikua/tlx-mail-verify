-- Mail Verifier Database Schema

CREATE TABLE IF NOT EXISTS email_checks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    -- Email Info
    message_id VARCHAR(512),
    subject TEXT,
    from_address VARCHAR(512),
    from_name VARCHAR(512),
    to_address VARCHAR(512),
    received_date TIMESTAMP,

    -- Status
    status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',

    -- Results
    overall_score INT DEFAULT 0 COMMENT 'Score 0-100',
    risk_level ENUM('green', 'yellow', 'red') DEFAULT NULL,

    -- Raw Data
    raw_email_path VARCHAR(1024),
    report_pdf_path VARCHAR(1024),

    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    INDEX idx_from_address (from_address),
    INDEX idx_risk_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS check_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    check_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- DKIM/SPF/DMARC
    dkim_valid BOOLEAN,
    dkim_details JSON,
    spf_valid BOOLEAN,
    spf_details JSON,
    dmarc_valid BOOLEAN,
    dmarc_details JSON,

    -- Domain Analysis
    domain_whois JSON,
    domain_age_days INT,
    domain_registrar VARCHAR(512),
    mx_records JSON,
    dns_records JSON,

    -- IP Analysis
    sender_ip VARCHAR(45),
    ip_location JSON,
    ip_blacklisted BOOLEAN,
    ip_blacklist_details JSON,

    -- Website Analysis
    website_exists BOOLEAN,
    website_ssl_valid BOOLEAN,
    website_ssl_details JSON,
    website_content_summary TEXT,

    -- OSINT
    email_in_breaches BOOLEAN,
    breach_details JSON,
    online_mentions JSON,

    -- AI Analysis
    claude_analysis TEXT,
    claude_verdict TEXT,

    FOREIGN KEY (check_id) REFERENCES email_checks(id) ON DELETE CASCADE,
    INDEX idx_check_id (check_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    level ENUM('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'),
    component VARCHAR(128),
    message TEXT,
    details JSON,

    INDEX idx_created_at (created_at),
    INDEX idx_level (level),
    INDEX idx_component (component)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(128) UNIQUE NOT NULL,
    password_hash VARCHAR(512) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,

    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default admin user (password: changeme)
INSERT INTO admin_users (username, password_hash)
VALUES ('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqVr8H.UQW')
ON DUPLICATE KEY UPDATE username=username;
