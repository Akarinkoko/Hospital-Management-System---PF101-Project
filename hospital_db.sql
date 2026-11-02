CREATE DATABASE IF NOT EXISTS hospital_db;
USE hospital_db;

-- 1. Users table for staff login (same security style as your prof's sample)
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_salt VARCHAR(64) NOT NULL,
    password_hash VARCHAR(64) NOT NULL
);

-- Default admin login: admin / admin123
-- (Salt: '9f86d081884c7d659a2feaa0c55ad015', Hash for 'admin123' with this salt)
INSERT INTO users (username, password_salt, password_hash) 
VALUES ('admin', '9f86d081884c7d659a2feaa0c55ad015', 'c51722881bfa6e54f0a711cc64c8d57551061975e533e5fbcf538d6df022a944')
ON DUPLICATE KEY UPDATE username=username;

-- 2. Patients table for Emergency and Ward Management
CREATE TABLE IF NOT EXISTS patients (
    patient_id INT AUTO_INCREMENT PRIMARY KEY,
    patient_no VARCHAR(30) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    age INT NOT NULL,
    gender VARCHAR(20) NOT NULL,
    room_no VARCHAR(30) NOT NULL,
    condition_type VARCHAR(100) NOT NULL,
    triage_status VARCHAR(50) NOT NULL,
    admission_date VARCHAR(50) NOT NULL,
    status VARCHAR(30) NOT NULL
);
