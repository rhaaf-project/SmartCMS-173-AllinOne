-- Extensions Sample Data
INSERT IGNORE INTO extensions (call_server_id, extension, name, password, is_active) VALUES 
(3, '7001', 'Ext 7001 - SIP', '1234', 1),
(3, '7002', 'Ext 7002 - SIP', '1234', 1),
(3, '8001', 'Ext 8001 - Line', '1234', 1),
(3, '8002', 'Ext 8002 - Line', '1234', 1),
(3, '8101', 'Ext 8101 - Extension', '1234', 1),
(3, '8102', 'Ext 8102 - Extension', '1234', 1),
(3, '8201', 'Ext 8201 - VPW', '1234', 1),
(3, '8202', 'Ext 8202 - VPW', '1234', 1),
(3, '8301', 'Ext 8301 - CAS', '1234', 1),
(3, '8302', 'Ext 8302 - CAS', '1234', 1);

-- Lines Sample Data
INSERT IGNORE INTO `lines` (call_server_id, name, line_number, type, channel_count, is_active) VALUES 
(3, 'Line Jakarta-01', '021-5001', 'sip', 4, 1),
(3, 'Line Jakarta-02', '021-5002', 'sip', 4, 1),
(3, 'Line Bandung-01', '022-6001', 'sip', 2, 1),
(3, 'Line Surabaya-01', '031-7001', 'sip', 2, 1),
(3, 'Line Medan-01', '061-8001', 'sip', 2, 1);

-- VPW Sample Data (Using INSERT IGNORE to prevent duplicates)
INSERT IGNORE INTO private_wires (call_server_id, name, number, destination, is_active) VALUES 
(3, 'VPW HQ-Branch1', '9001', 'Branch Cimahi', 1),
(3, 'VPW HQ-Branch2', '9002', 'Branch Bandung', 1),
(3, 'VPW HQ-Branch3', '9003', 'Branch Surabaya', 1),
(3, 'VPW Regional-01', '9004', 'Regional West', 1),
(3, 'VPW Regional-02', '9005', 'Regional East', 1);

-- CAS Sample Data
INSERT IGNORE INTO cas (call_server_id, name, cas_number, channel_number, signaling_type, span, timeslot, is_active) VALUES 
(3, 'CAS E1 Port 1', 'CAS-001', 30, 'E1', 1, 1, 1),
(3, 'CAS E1 Port 2', 'CAS-002', 30, 'E1', 1, 2, 1),
(3, 'CAS E1 Port 3', 'CAS-003', 30, 'E1', 2, 1, 1),
(3, 'CAS PRI Link 1', 'CAS-004', 23, 'PRI', 1, 1, 1),
(3, 'CAS PRI Link 2', 'CAS-005', 23, 'PRI', 2, 1, 1);

-- SIP 3rd Party Devices Sample Data
INSERT IGNORE INTO device_3rd_parties (name, mac_address, ip_address, device_type, manufacturer, model, is_active) VALUES 
('Cisco IP Phone 7821', '00:1B:54:AA:BB:01', '192.168.100.101', 'ip_phone', 'Cisco', '7821', 1),
('Yealink T46S', '80:5E:C0:CC:DD:02', '192.168.100.102', 'ip_phone', 'Yealink', 'T46S', 1),
('Grandstream GXP2170', '00:0B:82:EE:FF:03', '192.168.100.103', 'ip_phone', 'Grandstream', 'GXP2170', 1),
('Polycom VVX 450', '64:16:7F:11:22:04', '192.168.100.104', 'ip_phone', 'Polycom', 'VVX 450', 1),
('Fanvil X6U', 'AC:D1:B8:33:44:05', '192.168.100.105', 'ip_phone', 'Fanvil', 'X6U', 1);
