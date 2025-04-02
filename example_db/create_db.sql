INSTALL SONAME 'auth_ed25519';

-- Vytvoření uživatelů (nebo rolí)
CREATE USER 'public_user'@'%' IDENTIFIED WITH ed25519 USING PASSWORD('password');
CREATE USER 'test_user'@'%' IDENTIFIED WITH mysql_native_password USING PASSWORD('');
CREATE USER 'private_user'@'%' IDENTIFIED WITH mysql_old_password USING PASSWORD('password') REQUIRE SSL;
CREATE USER 'admin_user'@'localhost' IDENTIFIED WITH mysql_native_password USING PASSWORD('password') REQUIRE SSL;

-- Omezení připojení
ALTER USER 'public_user'@'%' WITH MAX_USER_CONNECTIONS 10;
ALTER USER 'private_user'@'%' WITH MAX_USER_CONNECTIONS 10;
ALTER USER 'admin_user'@'localhost' WITH MAX_USER_CONNECTIONS 20;

-- Vytvoření schématu
CREATE DATABASE IF NOT EXISTS my_schema;

-- Přepnutí do schématu
USE my_schema;

-- Vytvoření tabulek
CREATE TABLE IF NOT EXISTS public_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    info TEXT
);

CREATE TABLE IF NOT EXISTS private_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    info TEXT
);

CREATE TABLE IF NOT EXISTS secret_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    info TEXT
);

-- Nastavení oprávnění
GRANT SELECT ON my_schema.public_info TO 'public_user'@'%';
GRANT SELECT ON my_schema.public_info TO 'test_user'@'%';
GRANT SELECT ON my_schema.public_info TO 'private_user'@'%';
GRANT SELECT ON my_schema.private_info TO 'private_user'@'%';

GRANT ALL PRIVILEGES ON my_schema.public_info TO 'admin_user'@'localhost';
GRANT ALL PRIVILEGES ON my_schema.private_info TO 'admin_user'@'localhost';
GRANT ALL PRIVILEGES ON my_schema.secret_info TO 'admin_user'@'localhost';
GRANT SUPER ON *.* TO 'admin_user'@'localhost';
GRANT FILE ON *.* TO 'admin_user'@'localhost';

-- Nastavení podrobosti hlášení chyb
SET GLOBAL log_error_verbosity = 3;
