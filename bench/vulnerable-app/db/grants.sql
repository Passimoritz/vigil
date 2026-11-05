-- Datenbank-Nutzer fuer den Shop
CREATE USER 'shop'@'%' IDENTIFIED BY 'changeme';
GRANT ALL PRIVILEGES ON *.* TO 'shop'@'%';
