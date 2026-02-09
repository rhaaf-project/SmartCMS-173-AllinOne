-- SBC Connection Status Table
-- Session Border Controller (SBC) monitors SIP trunk/peer connections
-- Tracks: ITSP trunks, IP Groups, Trunk Groups, and peer registration status

CREATE TABLE IF NOT EXISTS sbc_connection_status (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sbc_id INT NOT NULL,
    peer_name VARCHAR(100) NOT NULL COMMENT 'SIP Trunk/IP Group/Trunk Group name',
    peer_type ENUM('ITSP', 'IP_GROUP', 'TRUNK_GROUP', 'SIP_PEER', 'GATEWAY') DEFAULT 'SIP_PEER' COMMENT 'Type of SBC peer connection',
    remote_address VARCHAR(100) NOT NULL COMMENT 'Remote SIP endpoint address (IP:Port or FQDN)',
    local_user VARCHAR(50) DEFAULT NULL COMMENT 'Local SIP username/AOR for registration',
    registration_status ENUM('REGISTERED', 'NOT_REGISTERED', 'REGISTERING', 'FAILED') DEFAULT 'NOT_REGISTERED' COMMENT 'SIP REGISTER status',
    connection_status ENUM('OK', 'LAGGED', 'UNREACHABLE', 'UNKNOWN') DEFAULT 'UNKNOWN' COMMENT 'SIP OPTIONS qualify status',
    latency_ms INT DEFAULT NULL COMMENT 'Round-trip time from SIP OPTIONS ping (ms)',
    active_calls INT DEFAULT 0 COMMENT 'Current active calls on this peer',
    max_calls INT DEFAULT NULL COMMENT 'Maximum concurrent calls allowed',
    last_activity DATETIME DEFAULT NULL COMMENT 'Last successful SIP transaction timestamp',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (sbc_id) REFERENCES call_servers(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sample Data for SBC Connection Status
-- SBC ID 8 = Telkom (192.168.0.10) from call_servers table
-- Realistic SBC peer scenarios based on typical enterprise deployments

INSERT INTO sbc_connection_status (sbc_id, peer_name, peer_type, remote_address, local_user, registration_status, connection_status, latency_ms, active_calls, max_calls, last_activity) VALUES
-- ITSP (Internet Telephony Service Provider) SIP Trunks - connects to carriers for PSTN
(8, 'Telkom-ITSP-Primary', 'ITSP', 'sip.telkom.net.id:5060', 'telkom_trunk_01', 'REGISTERED', 'OK', 18, 5, 30, NOW() - INTERVAL 2 SECOND),
(8, 'Indosat-DID-Trunk', 'ITSP', 'trunk.indosat.net:5060', 'indosat_did_main', 'REGISTERED', 'LAGGED', 165, 2, 20, NOW() - INTERVAL 35 SECOND),
-- IP Groups - internal PBX/Call Server connections
(8, 'IPG-CallServer-HQ', 'IP_GROUP', '10.10.1.50:5060', NULL, 'NOT_REGISTERED', 'OK', 5, 12, 100, NOW() - INTERVAL 1 SECOND),
(8, 'IPG-Branch-Bandung', 'IP_GROUP', '10.10.2.50:5060', NULL, 'NOT_REGISTERED', 'UNREACHABLE', NULL, 0, 50, NOW() - INTERVAL 8 MINUTE),
-- Trunk Groups - grouped SIP trunks for load balancing
(8, 'TG-PSTN-Outbound', 'TRUNK_GROUP', '10.10.1.100:5060', NULL, 'NOT_REGISTERED', 'OK', 12, 8, 60, NOW() - INTERVAL 5 SECOND);
