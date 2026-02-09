-- Insert sample turret users
INSERT INTO turret_users (id, name, password, use_ext, is_active) VALUES
(1, 'john_trader', 'password123', '6001', 1),
(2, 'sarah_fx', 'password123', '6002', 1),
(3, 'mike_bond', 'password123', '6003', 1),
(4, 'emily_crypto', 'password123', '6004', 1),
(5, 'david_metal', 'password123', '6005', 1);

-- Insert sample phonebook entries for each user
INSERT INTO turret_user_phonebooks (turret_user_id, name, phone, company, email, is_favourite) VALUES
(1, 'Mom', '0812-1111-1111', NULL, NULL, 1),
(1, 'Client BCA', '021-5001-001', 'BCA', 'client@bca.co.id', 1),
(1, 'Broker SGX', '+65-6222-3333', 'SGX', 'broker@sgx.com', 0),
(1, 'Support IT', '7000', 'Internal', NULL, 0),
(1, 'Boss', '6000', 'Internal', NULL, 1),
(2, 'Partner DBS', '+65-6888-8888', 'DBS Bank', 'partner@dbs.com', 1),
(2, 'Sister', '0813-2222-2222', NULL, NULL, 1),
(2, 'Client Mandiri', '021-5002-002', 'Mandiri', 'fx@mandiri.co.id', 0),
(2, 'Dealer Tokyo', '+81-3-1234-5678', 'Tokyo Branch', 'dealer@tokyo.jp', 0),
(2, 'Emergency', '110', NULL, NULL, 0),
(3, 'Wife', '0814-3333-3333', NULL, NULL, 1),
(3, 'Bloomberg Desk', '+1-212-555-0100', 'Bloomberg', 'desk@bloomberg.com', 1),
(3, 'Reuters Contact', '+44-20-7777-8888', 'Reuters', NULL, 0),
(3, 'Treasury Head', '6010', 'Internal', NULL, 1),
(3, 'Risk Manager', '6020', 'Internal', NULL, 0),
(4, 'Dad', '0815-4444-4444', NULL, NULL, 1),
(4, 'Binance Support', '+65-9999-0000', 'Binance', 'support@binance.com', 0),
(4, 'Coinbase Rep', '+1-415-555-1234', 'Coinbase', 'rep@coinbase.com', 0),
(4, 'Crypto Analyst', '6030', 'Internal', NULL, 1),
(4, 'Settlement Team', '6040', 'Internal', NULL, 0),
(5, 'Brother', '0816-5555-5555', NULL, NULL, 1),
(5, 'Gold Dealer London', '+44-20-1234-5678', 'LBMA', 'gold@lbma.com', 1),
(5, 'Silver Broker', '+1-312-555-9999', 'COMEX', 'silver@comex.com', 0),
(5, 'Commodity Head', '6050', 'Internal', NULL, 1),
(5, 'Compliance', '6060', 'Internal', NULL, 0);
