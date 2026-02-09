INSERT INTO customers (id, name, code, is_active) VALUES (2, 'PT KAI', 'KAI IND', 1);
INSERT INTO head_offices (id, customer_id, name, type, is_active) VALUES (2, 2, 'HO KAI Indonesia', 'ha', 1);
INSERT INTO branches (id, customer_id, head_office_id, call_server_id, name, country, province, city, district, address, is_active) VALUES (1, 2, 2, 1, 'KAI Cimahi', 'Indonesia', 'Jawa Barat', 'Cimahi', 'Cimahi Tengah', 'Cimahi Jawa Barat', 1);
INSERT INTO sub_branches (id, customer_id, branch_id, call_server_id, name, code, city, is_active) VALUES (1, 2, 1, 1, 'KAI Juanda Cimahi', 'KAI CMH 011', 'Cimahi', 1);
