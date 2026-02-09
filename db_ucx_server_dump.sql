/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19-11.8.3-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: db_ucx
-- ------------------------------------------------------
-- Server version	11.8.3-MariaDB-0+deb13u1 from Debian

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Table structure for table `activity_logs`
--

DROP TABLE IF EXISTS `activity_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `activity_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(100) NOT NULL,
  `entity_type` varchar(100) DEFAULT NULL,
  `entity_id` int(11) DEFAULT NULL,
  `old_values` text DEFAULT NULL,
  `new_values` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `activity_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `cms_users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `activity_logs`
--

LOCK TABLES `activity_logs` WRITE;
/*!40000 ALTER TABLE `activity_logs` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `activity_logs` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `branches`
--

DROP TABLE IF EXISTS `branches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `branches` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer_id` int(11) DEFAULT NULL,
  `head_office_id` int(11) DEFAULT NULL,
  `call_server_id` int(11) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `code` varchar(50) DEFAULT NULL,
  `country` varchar(100) DEFAULT NULL,
  `province` varchar(100) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `district` varchar(100) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `contact_name` varchar(255) DEFAULT NULL,
  `contact_phone` varchar(50) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `customer_id` (`customer_id`),
  KEY `head_office_id` (`head_office_id`),
  CONSTRAINT `branches_ibfk_1` FOREIGN KEY (`customer_id`) REFERENCES `customers` (`id`) ON DELETE SET NULL,
  CONSTRAINT `branches_ibfk_2` FOREIGN KEY (`head_office_id`) REFERENCES `head_offices` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `branches`
--

LOCK TABLES `branches` WRITE;
/*!40000 ALTER TABLE `branches` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `branches` VALUES
(1,2,2,3,'KAI Cimahi','KAI CMH 01','Indonesia','Jawa Barat','Cimahi','Cimahi Tengah','CImahi Jawa Barat','','','',1,'2026-01-30 09:56:59','2026-01-30 18:01:49');
/*!40000 ALTER TABLE `branches` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `cache`
--

DROP TABLE IF EXISTS `cache`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cache` (
  `key` varchar(191) NOT NULL,
  `value` mediumtext NOT NULL,
  `expiration` int(11) NOT NULL,
  PRIMARY KEY (`key`),
  KEY `cache_expiration_index` (`expiration`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cache`
--

LOCK TABLES `cache` WRITE;
/*!40000 ALTER TABLE `cache` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `cache` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `cache_locks`
--

DROP TABLE IF EXISTS `cache_locks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cache_locks` (
  `key` varchar(191) NOT NULL,
  `owner` varchar(191) NOT NULL,
  `expiration` int(11) NOT NULL,
  PRIMARY KEY (`key`),
  KEY `cache_locks_expiration_index` (`expiration`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cache_locks`
--

LOCK TABLES `cache_locks` WRITE;
/*!40000 ALTER TABLE `cache_locks` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `cache_locks` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `call_servers`
--

DROP TABLE IF EXISTS `call_servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `call_servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `head_office_id` int(11) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `host` varchar(255) NOT NULL,
  `port` int(11) DEFAULT 5060,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `head_office_id` (`head_office_id`),
  CONSTRAINT `call_servers_ibfk_1` FOREIGN KEY (`head_office_id`) REFERENCES `head_offices` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `call_servers`
--

LOCK TABLES `call_servers` WRITE;
/*!40000 ALTER TABLE `call_servers` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `call_servers` VALUES
(1,1,'SmartUCX-1-HO','103.154.80.172',5060,NULL,1,'2026-01-29 17:28:18','2026-01-29 17:28:18'),
(2,2,'SmartUCX-1-KAI','103.154.81.101',5060,NULL,1,'2026-01-30 17:52:41','2026-01-30 17:59:32'),
(3,2,'SmartUCX-2-KAI','103.154.81.102',5060,NULL,1,'2026-01-30 17:53:31','2026-01-30 17:59:39'),
(4,2,'SmartUCX-3-KAI','103.154.81.103',5060,NULL,1,'2026-01-30 17:53:43','2026-01-30 17:59:48'),
(5,2,'SmartUCX-4-KAI','103.154.81.104',5060,NULL,1,'2026-01-30 17:54:01','2026-01-30 17:59:56'),
(6,2,'SmartUCX-5-KAI','103.154.81.105',5060,NULL,1,'2026-01-30 17:54:12','2026-01-30 18:00:16'),
(7,3,'SmartGAR-1-HO','103.154.80.125',5060,NULL,1,'2026-01-31 14:05:24','2026-01-31 14:05:24');
/*!40000 ALTER TABLE `call_servers` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `cas`
--

DROP TABLE IF EXISTS `cas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cas` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `cas_number` varchar(50) DEFAULT NULL,
  `channel_number` int(11) DEFAULT NULL,
  `signaling_type` varchar(50) DEFAULT NULL,
  `trunk_id` bigint(20) unsigned DEFAULT NULL,
  `span` int(11) DEFAULT NULL,
  `timeslot` int(11) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `destination` varchar(100) DEFAULT NULL,
  `destination_local` tinyint(1) DEFAULT 0,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cas`
--

LOCK TABLES `cas` WRITE;
/*!40000 ALTER TABLE `cas` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `cas` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `cdrs`
--

DROP TABLE IF EXISTS `cdrs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cdrs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `calldate` datetime NOT NULL,
  `clid` varchar(80) NOT NULL DEFAULT '',
  `src` varchar(80) NOT NULL DEFAULT '',
  `dst` varchar(80) NOT NULL DEFAULT '',
  `dcontext` varchar(80) NOT NULL DEFAULT '',
  `channel` varchar(80) NOT NULL DEFAULT '',
  `dstchannel` varchar(80) NOT NULL DEFAULT '',
  `lastapp` varchar(80) NOT NULL DEFAULT '',
  `lastdata` varchar(80) NOT NULL DEFAULT '',
  `duration` int(11) NOT NULL DEFAULT 0,
  `billsec` int(11) NOT NULL DEFAULT 0,
  `disposition` varchar(45) NOT NULL DEFAULT '',
  `amaflags` int(11) NOT NULL DEFAULT 0,
  `accountcode` varchar(20) NOT NULL DEFAULT '',
  `uniqueid` varchar(32) NOT NULL,
  `userfield` varchar(255) NOT NULL DEFAULT '',
  `did` varchar(50) NOT NULL DEFAULT '',
  `recordingfile` varchar(255) NOT NULL DEFAULT '',
  `cnum` varchar(80) NOT NULL DEFAULT '',
  `cnam` varchar(80) NOT NULL DEFAULT '',
  `outbound_cnum` varchar(80) NOT NULL DEFAULT '',
  `outbound_cnam` varchar(80) NOT NULL DEFAULT '',
  `dst_cnam` varchar(80) NOT NULL DEFAULT '',
  `linkedid` varchar(32) NOT NULL DEFAULT '',
  `peeraccount` varchar(80) NOT NULL DEFAULT '',
  `sequence` int(11) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `cdrs_uniqueid_unique` (`uniqueid`),
  KEY `cdrs_calldate_index` (`calldate`),
  KEY `cdrs_src_index` (`src`),
  KEY `cdrs_dst_index` (`dst`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cdrs`
--

LOCK TABLES `cdrs` WRITE;
/*!40000 ALTER TABLE `cdrs` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `cdrs` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `cms_groups`
--

DROP TABLE IF EXISTS `cms_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cms_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `permissions` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cms_groups`
--

LOCK TABLES `cms_groups` WRITE;
/*!40000 ALTER TABLE `cms_groups` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `cms_groups` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `cms_users`
--

DROP TABLE IF EXISTS `cms_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cms_users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','operator','viewer') DEFAULT 'viewer',
  `is_active` tinyint(1) DEFAULT 1,
  `last_login` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cms_users`
--

LOCK TABLES `cms_users` WRITE;
/*!40000 ALTER TABLE `cms_users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `cms_users` VALUES
(1,'Administrator','admin@smartcms.local','$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi','admin',1,NULL,'2026-01-29 17:28:18','2026-01-29 17:28:18');
/*!40000 ALTER TABLE `cms_users` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `conferences`
--

DROP TABLE IF EXISTS `conferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conferences` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `call_server_id` int(11) DEFAULT NULL,
  `conf_num` varchar(20) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `pin` varchar(20) DEFAULT NULL,
  `admin_pin` varchar(20) DEFAULT NULL,
  `options` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `call_server_id` (`call_server_id`),
  CONSTRAINT `conferences_ibfk_1` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `conferences`
--

LOCK TABLES `conferences` WRITE;
/*!40000 ALTER TABLE `conferences` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `conferences` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `customers`
--

DROP TABLE IF EXISTS `customers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `customers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `code` varchar(50) DEFAULT NULL,
  `contact_person` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `phone` varchar(50) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `customers`
--

LOCK TABLES `customers` WRITE;
/*!40000 ALTER TABLE `customers` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `customers` VALUES
(1,'PT Smart Infinite Prosperity','SIP','Joni Me Ow','joni@smart.com','02150877432','Jakarta, Indonesia',1,'2026-01-29 17:28:18','2026-01-29 17:28:18'),
(2,'PT KAI','KAI IND','Kaimanu','kaimanu@kai,id','123456','Gambir Jakarta',1,'2026-01-29 18:00:14','2026-01-29 18:00:14'),
(3,'PT Garuda','GARUDA IND','Garuda','garuda@garuda.id','123456','Monas Jakarta',1,'2026-01-31 14:03:41','2026-01-31 14:03:41');
/*!40000 ALTER TABLE `customers` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `dahdi_channels`
--

DROP TABLE IF EXISTS `dahdi_channels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dahdi_channels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `call_server_id` int(11) DEFAULT NULL,
  `channel_type` enum('fxo','fxs','e1','e1_cas') NOT NULL,
  `span` int(11) DEFAULT NULL,
  `channel` int(11) DEFAULT NULL,
  `signalling` varchar(50) DEFAULT NULL,
  `context` varchar(100) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `call_server_id` (`call_server_id`),
  CONSTRAINT `dahdi_channels_ibfk_1` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dahdi_channels`
--

LOCK TABLES `dahdi_channels` WRITE;
/*!40000 ALTER TABLE `dahdi_channels` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `dahdi_channels` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `device_3rd_parties`
--

DROP TABLE IF EXISTS `device_3rd_parties`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_3rd_parties` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `mac_address` varchar(17) DEFAULT NULL,
  `ip_address` varchar(15) DEFAULT NULL,
  `device_type` varchar(50) DEFAULT 'ip_phone',
  `manufacturer` varchar(100) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_3rd_parties`
--

LOCK TABLES `device_3rd_parties` WRITE;
/*!40000 ALTER TABLE `device_3rd_parties` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `device_3rd_parties` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `extensions`
--

DROP TABLE IF EXISTS `extensions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `extensions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `call_server_id` int(11) DEFAULT NULL,
  `extension` varchar(20) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `password` varchar(100) DEFAULT NULL,
  `voicemail` varchar(50) DEFAULT NULL,
  `outbound_cid` varchar(50) DEFAULT NULL,
  `ring_timer` int(11) DEFAULT 30,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `call_server_id` (`call_server_id`),
  CONSTRAINT `extensions_ibfk_1` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `extensions`
--

LOCK TABLES `extensions` WRITE;
/*!40000 ALTER TABLE `extensions` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `extensions` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `failed_jobs`
--

DROP TABLE IF EXISTS `failed_jobs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `failed_jobs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(191) NOT NULL,
  `connection` text NOT NULL,
  `queue` text NOT NULL,
  `payload` longtext NOT NULL,
  `exception` longtext NOT NULL,
  `failed_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `failed_jobs_uuid_unique` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `failed_jobs`
--

LOCK TABLES `failed_jobs` WRITE;
/*!40000 ALTER TABLE `failed_jobs` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `failed_jobs` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `firewalls`
--

DROP TABLE IF EXISTS `firewalls`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `firewalls` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `port` varchar(191) NOT NULL,
  `source` varchar(191) NOT NULL DEFAULT 'any',
  `destination` varchar(191) NOT NULL DEFAULT 'any',
  `protocol` varchar(191) NOT NULL,
  `interface` varchar(191) NOT NULL,
  `direction` varchar(191) NOT NULL,
  `action` varchar(191) NOT NULL,
  `comment` varchar(191) DEFAULT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `firewalls_call_server_id_foreign` (`call_server_id`),
  CONSTRAINT `firewalls_call_server_id_foreign` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `firewalls`
--

LOCK TABLES `firewalls` WRITE;
/*!40000 ALTER TABLE `firewalls` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `firewalls` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `head_offices`
--

DROP TABLE IF EXISTS `head_offices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `head_offices` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer_id` int(11) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `code` varchar(50) DEFAULT NULL,
  `type` enum('basic','ha','fo') DEFAULT 'basic',
  `country` varchar(100) DEFAULT NULL,
  `province` varchar(100) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `district` varchar(100) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `contact_name` varchar(255) DEFAULT NULL,
  `contact_phone` varchar(50) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `bcp_drc_server_id` int(11) DEFAULT NULL,
  `bcp_drc_enabled` tinyint(1) DEFAULT 0,
  `call_servers_json` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `customer_id` (`customer_id`),
  CONSTRAINT `head_offices_ibfk_1` FOREIGN KEY (`customer_id`) REFERENCES `customers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `head_offices`
--

LOCK TABLES `head_offices` WRITE;
/*!40000 ALTER TABLE `head_offices` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `head_offices` VALUES
(1,1,'HO Jakarta','HO-JKT','ha',NULL,NULL,'Jakarta',NULL,NULL,NULL,NULL,NULL,1,'2026-01-29 17:28:18','2026-01-29 17:28:18',NULL,0,NULL),
(2,2,'HO KAI Indonesia','KAI IND 01','ha','Indonesia','DKI','Jakarta','Jakarta Pusat','Gambir','','','',1,'2026-01-29 18:04:43','2026-01-30 18:00:46',6,0,'[{\"call_server_id\":2,\"is_enabled\":true},{\"call_server_id\":3,\"is_enabled\":true},{\"call_server_id\":4,\"is_enabled\":true}]'),
(3,3,'HO Garuda Indonesia','GAR IND 01','basic','Indonesia','DKI','Jakarta','Jakarta Pusat','Monas','','','',1,'2026-01-31 14:04:48','2026-01-31 14:04:48',1,0,'[{\"call_server_id\":6,\"is_enabled\":true}]');
/*!40000 ALTER TABLE `head_offices` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `inbound_routes`
--

DROP TABLE IF EXISTS `inbound_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `inbound_routes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `did_number` varchar(191) NOT NULL,
  `description` varchar(191) DEFAULT NULL,
  `trunk_id` bigint(20) unsigned DEFAULT NULL,
  `destination_type` varchar(191) NOT NULL DEFAULT 'extension',
  `destination_id` bigint(20) unsigned DEFAULT NULL,
  `cid_filter` varchar(191) DEFAULT NULL,
  `priority` int(11) NOT NULL DEFAULT 0,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `inbound_routes_trunk_id_foreign` (`trunk_id`),
  KEY `inbound_routes_did_number_priority_index` (`did_number`,`priority`),
  KEY `inbound_routes_call_server_id_foreign` (`call_server_id`),
  CONSTRAINT `inbound_routes_call_server_id_foreign` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL,
  CONSTRAINT `inbound_routes_trunk_id_foreign` FOREIGN KEY (`trunk_id`) REFERENCES `trunks` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `inbound_routes`
--

LOCK TABLES `inbound_routes` WRITE;
/*!40000 ALTER TABLE `inbound_routes` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `inbound_routes` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `inbound_routings`
--

DROP TABLE IF EXISTS `inbound_routings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `inbound_routings` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `did_number` varchar(50) DEFAULT NULL,
  `destination` varchar(100) DEFAULT NULL,
  `destination_type` varchar(50) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `inbound_routings`
--

LOCK TABLES `inbound_routings` WRITE;
/*!40000 ALTER TABLE `inbound_routings` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `inbound_routings` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `intercoms`
--

DROP TABLE IF EXISTS `intercoms`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `intercoms` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `branch_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(191) NOT NULL,
  `extension` varchar(20) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `intercoms_call_server_id_index` (`call_server_id`),
  KEY `intercoms_branch_id_index` (`branch_id`),
  CONSTRAINT `intercoms_branch_id_foreign` FOREIGN KEY (`branch_id`) REFERENCES `branches` (`id`) ON DELETE SET NULL,
  CONSTRAINT `intercoms_call_server_id_foreign` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `intercoms`
--

LOCK TABLES `intercoms` WRITE;
/*!40000 ALTER TABLE `intercoms` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `intercoms` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `ivr`
--

DROP TABLE IF EXISTS `ivr`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `ivr` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `call_server_id` int(11) DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `announcement` int(11) DEFAULT NULL,
  `direct_dial` varchar(50) DEFAULT NULL,
  `timeout_time` int(11) DEFAULT 10,
  `invalid_loops` int(11) DEFAULT 3,
  `timeout_destination` varchar(255) DEFAULT NULL,
  `invalid_destination` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `call_server_id` (`call_server_id`),
  CONSTRAINT `ivr_ibfk_1` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ivr`
--

LOCK TABLES `ivr` WRITE;
/*!40000 ALTER TABLE `ivr` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `ivr` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `job_batches`
--

DROP TABLE IF EXISTS `job_batches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `job_batches` (
  `id` varchar(191) NOT NULL,
  `name` varchar(191) NOT NULL,
  `total_jobs` int(11) NOT NULL,
  `pending_jobs` int(11) NOT NULL,
  `failed_jobs` int(11) NOT NULL,
  `failed_job_ids` longtext NOT NULL,
  `options` mediumtext DEFAULT NULL,
  `cancelled_at` int(11) DEFAULT NULL,
  `created_at` int(11) NOT NULL,
  `finished_at` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `job_batches`
--

LOCK TABLES `job_batches` WRITE;
/*!40000 ALTER TABLE `job_batches` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `job_batches` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `jobs`
--

DROP TABLE IF EXISTS `jobs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `jobs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `queue` varchar(191) NOT NULL,
  `payload` longtext NOT NULL,
  `attempts` tinyint(3) unsigned NOT NULL,
  `reserved_at` int(10) unsigned DEFAULT NULL,
  `available_at` int(10) unsigned NOT NULL,
  `created_at` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `jobs_queue_index` (`queue`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `jobs`
--

LOCK TABLES `jobs` WRITE;
/*!40000 ALTER TABLE `jobs` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `jobs` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `lines`
--

DROP TABLE IF EXISTS `lines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `lines` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `line_number` varchar(255) NOT NULL,
  `type` varchar(50) DEFAULT 'sip',
  `channel_count` int(11) DEFAULT 1,
  `trunk_id` bigint(20) unsigned DEFAULT NULL,
  `description` text DEFAULT NULL,
  `secret` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `lines`
--

LOCK TABLES `lines` WRITE;
/*!40000 ALTER TABLE `lines` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `lines` VALUES
(1,2,'kaimanu','110011','sip',1,NULL,NULL,'1234',1,NULL,NULL),
(2,3,'kaimanu','110012','sip',1,NULL,NULL,'1234',1,NULL,NULL),
(3,4,'kaimanu','110013','sip',1,NULL,NULL,'1234',1,NULL,NULL),
(4,2,'kaimanu','110021','sip',1,NULL,NULL,'1234',1,NULL,NULL),
(5,3,'kaimanu','110022','sip',1,NULL,NULL,'1234',1,NULL,NULL),
(6,4,'kaimanu','110023','sip',1,NULL,NULL,'1234',1,NULL,NULL),
(7,1,'Smartono','100011','sip',1,NULL,NULL,'1234',1,NULL,NULL);
/*!40000 ALTER TABLE `lines` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `migrations`
--

DROP TABLE IF EXISTS `migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `migrations` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `migration` varchar(191) NOT NULL,
  `batch` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migrations`
--

LOCK TABLES `migrations` WRITE;
/*!40000 ALTER TABLE `migrations` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `migrations` VALUES
(1,'0001_01_01_000000_create_users_table',1),
(2,'0001_01_01_000001_create_cache_table',1),
(3,'0001_01_01_000002_create_jobs_table',1),
(4,'2026_01_14_000000_create_extensions_table',1),
(5,'2026_01_14_000001_create_trunks_table',1),
(6,'2026_01_14_000002_create_call_servers_table',1),
(7,'2026_01_14_000003_add_call_server_to_trunks',1),
(8,'2026_01_14_000004_create_outbound_routes_table',1),
(9,'2026_01_14_000005_create_inbound_routes_table',1),
(10,'2026_01_14_000006_add_call_server_to_extensions',1),
(11,'2026_01_14_000007_create_lines_table',1),
(12,'2026_01_14_000008_create_vpws_table',1),
(13,'2026_01_14_000009_create_cas_table',1),
(14,'2026_01_14_000010_add_call_server_to_routes',1),
(15,'2026_01_14_000011_create_customers_table',1),
(16,'2026_01_14_000012_create_head_offices_table',1),
(17,'2026_01_14_000013_create_branches_table',1),
(18,'2026_01_14_000014_add_branch_id_to_extensions_lines',1),
(19,'2026_01_14_000015_add_head_office_to_call_servers',1),
(20,'2026_01_14_000016_remove_call_server_from_head_offices',1),
(21,'2026_01_14_000017_create_intercoms_table',1),
(22,'2026_01_20_000001_create_sbcs_and_private_wires_tables',1),
(23,'2026_01_22_create_firewalls_table',1),
(24,'2026_01_22_create_recording_servers_table',1),
(25,'2026_01_22_create_static_routes_table',1),
(26,'2026_01_23_create_sbc_routes_table',1),
(27,'2026_01_28_012547_create_personal_access_tokens_table',1),
(28,'2026_01_28_165200_create_sub_branches_table',1),
(29,'2026_01_28_170000_create_cdrs_table',1);
/*!40000 ALTER TABLE `migrations` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `outbound_routes`
--

DROP TABLE IF EXISTS `outbound_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `outbound_routes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(191) NOT NULL,
  `trunk_id` bigint(20) unsigned NOT NULL,
  `dial_pattern` varchar(191) NOT NULL DEFAULT '.',
  `match_cid` varchar(191) DEFAULT NULL,
  `prepend_digits` varchar(191) DEFAULT NULL,
  `outcid` varchar(191) DEFAULT NULL,
  `priority` int(11) NOT NULL DEFAULT 0,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `description` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `outbound_routes_trunk_id_foreign` (`trunk_id`),
  KEY `outbound_routes_priority_index` (`priority`),
  KEY `outbound_routes_call_server_id_foreign` (`call_server_id`),
  CONSTRAINT `outbound_routes_call_server_id_foreign` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL,
  CONSTRAINT `outbound_routes_trunk_id_foreign` FOREIGN KEY (`trunk_id`) REFERENCES `trunks` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `outbound_routes`
--

LOCK TABLES `outbound_routes` WRITE;
/*!40000 ALTER TABLE `outbound_routes` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `outbound_routes` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `outbound_routings`
--

DROP TABLE IF EXISTS `outbound_routings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `outbound_routings` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `dial_pattern` varchar(100) DEFAULT NULL,
  `trunk_id` bigint(20) unsigned DEFAULT NULL,
  `priority` int(11) DEFAULT 0,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `outbound_routings`
--

LOCK TABLES `outbound_routings` WRITE;
/*!40000 ALTER TABLE `outbound_routings` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `outbound_routings` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `password_reset_tokens`
--

DROP TABLE IF EXISTS `password_reset_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_reset_tokens` (
  `email` varchar(191) NOT NULL,
  `token` varchar(191) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `password_reset_tokens`
--

LOCK TABLES `password_reset_tokens` WRITE;
/*!40000 ALTER TABLE `password_reset_tokens` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `password_reset_tokens` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `personal_access_tokens`
--

DROP TABLE IF EXISTS `personal_access_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `personal_access_tokens` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `tokenable_type` varchar(191) NOT NULL,
  `tokenable_id` bigint(20) unsigned NOT NULL,
  `name` text NOT NULL,
  `token` varchar(64) NOT NULL,
  `abilities` text DEFAULT NULL,
  `last_used_at` timestamp NULL DEFAULT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `personal_access_tokens_token_unique` (`token`),
  KEY `personal_access_tokens_tokenable_type_tokenable_id_index` (`tokenable_type`,`tokenable_id`),
  KEY `personal_access_tokens_expires_at_index` (`expires_at`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `personal_access_tokens`
--

LOCK TABLES `personal_access_tokens` WRITE;
/*!40000 ALTER TABLE `personal_access_tokens` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `personal_access_tokens` VALUES
(1,'App\\Models\\User',2,'api-token','7d407e845c046db541d65dac829e9c35ac79db002f91908c61e9f5a3b6534189','[\"*\"]',NULL,NULL,'2026-01-29 06:25:27','2026-01-29 06:25:27'),
(2,'App\\Models\\User',2,'api-token','901c1a676b71acbf1d8f22b9e10da87afd56e458e8901d9c04204cda3835a2b2','[\"*\"]',NULL,NULL,'2026-01-29 06:29:29','2026-01-29 06:29:29'),
(3,'App\\Models\\User',1,'api-token','82337c16d87f3ac1bf4e0cee10b87f04cf1e31e8dcbd30f77b0e5ac420e833fb','[\"*\"]',NULL,NULL,'2026-01-29 06:33:02','2026-01-29 06:33:02'),
(4,'App\\Models\\User',1,'api-token','7a7711eb764910a7904c596252e698ffbb9e79370da52337b8dca511d0746a6c','[\"*\"]',NULL,NULL,'2026-01-29 10:53:58','2026-01-29 10:53:58'),
(5,'App\\Models\\User',1,'api-token','ccb04207d9ce0c310e6e6dcfb11471415c676ebefd7748e977c1f2eb4bdad5db','[\"*\"]',NULL,NULL,'2026-01-29 14:48:33','2026-01-29 14:48:33'),
(6,'App\\Models\\User',1,'api-token','530e735aa3170a62fe242edf3feec203981c62c44f02c2cc9ff0d2ce844748d8','[\"*\"]',NULL,NULL,'2026-01-30 15:40:33','2026-01-30 15:40:33');
/*!40000 ALTER TABLE `personal_access_tokens` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `private_wires`
--

DROP TABLE IF EXISTS `private_wires`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `private_wires` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `number` varchar(50) DEFAULT NULL,
  `destination` varchar(100) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `private_wires`
--

LOCK TABLES `private_wires` WRITE;
/*!40000 ALTER TABLE `private_wires` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `private_wires` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `recording_servers`
--

DROP TABLE IF EXISTS `recording_servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `recording_servers` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `ip_address` varchar(191) NOT NULL,
  `port` varchar(191) DEFAULT NULL,
  `pbx_system_type` varchar(191) NOT NULL DEFAULT 'None',
  `pbx_system_1` varchar(191) DEFAULT NULL,
  `pbx_system_2` varchar(191) DEFAULT NULL,
  `pbx_system_3` varchar(191) DEFAULT NULL,
  `pbx_system_4` varchar(191) DEFAULT NULL,
  `description` varchar(191) DEFAULT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `recording_servers_call_server_id_foreign` (`call_server_id`),
  CONSTRAINT `recording_servers_call_server_id_foreign` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `recording_servers`
--

LOCK TABLES `recording_servers` WRITE;
/*!40000 ALTER TABLE `recording_servers` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `recording_servers` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `ring_groups`
--

DROP TABLE IF EXISTS `ring_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `ring_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `call_server_id` int(11) DEFAULT NULL,
  `grp_num` varchar(20) NOT NULL,
  `description` varchar(100) DEFAULT NULL,
  `strategy` varchar(50) DEFAULT 'ringall',
  `grp_time` int(11) DEFAULT 20,
  `grp_list` text DEFAULT NULL,
  `destination` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `call_server_id` (`call_server_id`),
  CONSTRAINT `ring_groups_ibfk_1` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ring_groups`
--

LOCK TABLES `ring_groups` WRITE;
/*!40000 ALTER TABLE `ring_groups` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `ring_groups` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `sbc_routes`
--

DROP TABLE IF EXISTS `sbc_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sbc_routes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `src_call_server_id` bigint(20) unsigned DEFAULT NULL,
  `src_description` varchar(255) DEFAULT NULL,
  `src_pattern` varchar(100) NOT NULL,
  `src_cid_filter` varchar(100) DEFAULT NULL,
  `src_priority` int(11) DEFAULT 0,
  `src_is_active` tinyint(1) DEFAULT 1,
  `src_from_sbc_id` bigint(20) unsigned DEFAULT NULL,
  `src_destination_id` bigint(20) unsigned DEFAULT NULL,
  `dest_call_server_id` bigint(20) unsigned DEFAULT NULL,
  `dest_description` varchar(255) DEFAULT NULL,
  `dest_pattern` varchar(100) DEFAULT NULL,
  `dest_cid_filter` varchar(100) DEFAULT NULL,
  `dest_priority` int(11) DEFAULT 0,
  `dest_is_active` tinyint(1) DEFAULT 1,
  `dest_from_sbc_id` bigint(20) unsigned DEFAULT NULL,
  `dest_destination_id` bigint(20) unsigned DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sbc_routes`
--

LOCK TABLES `sbc_routes` WRITE;
/*!40000 ALTER TABLE `sbc_routes` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `sbc_routes` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `sbcs`
--

DROP TABLE IF EXISTS `sbcs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sbcs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `sip_server` varchar(255) NOT NULL,
  `sip_server_port` int(11) DEFAULT 5060,
  `outcid` varchar(255) DEFAULT NULL,
  `maxchans` int(11) DEFAULT 2,
  `transport` varchar(20) DEFAULT 'udp',
  `context` varchar(100) DEFAULT 'from-pstn',
  `codecs` varchar(100) DEFAULT 'ulaw,alaw',
  `dtmfmode` varchar(20) DEFAULT 'auto',
  `registration` varchar(20) DEFAULT 'none',
  `auth_username` varchar(100) DEFAULT NULL,
  `secret` varchar(100) DEFAULT NULL,
  `qualify` tinyint(1) DEFAULT 1,
  `qualify_frequency` int(11) DEFAULT 60,
  `disabled` tinyint(1) DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sbcs`
--

LOCK TABLES `sbcs` WRITE;
/*!40000 ALTER TABLE `sbcs` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `sbcs` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `sessions`
--

DROP TABLE IF EXISTS `sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sessions` (
  `id` varchar(191) NOT NULL,
  `user_id` bigint(20) unsigned DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `payload` longtext NOT NULL,
  `last_activity` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sessions_user_id_index` (`user_id`),
  KEY `sessions_last_activity_index` (`last_activity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sessions`
--

LOCK TABLES `sessions` WRITE;
/*!40000 ALTER TABLE `sessions` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `sessions` VALUES
('FhSrGS4Dv4AZvEaIbWrWJobdPnkbn1mOr6MzhMyH',NULL,'127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','YTo0OntzOjY6Il90b2tlbiI7czo0MDoiZkFjVHBScGt6V1ozWThvTUpGbkx3YmFXcHAwejV5SkxRMlpJeWZWbiI7czo5OiJfcHJldmlvdXMiO2E6Mjp7czozOiJ1cmwiO3M6Mjc6Imh0dHA6Ly8xMDMuMTU0LjgwLjE3MS9hZG1pbiI7czo1OiJyb3V0ZSI7czozMDoiZmlsYW1lbnQuYWRtaW4ucGFnZXMuZGFzaGJvYXJkIjt9czo2OiJfZmxhc2giO2E6Mjp7czozOiJvbGQiO2E6MDp7fXM6MzoibmV3IjthOjA6e319czozOiJ1cmwiO2E6MTp7czo4OiJpbnRlbmRlZCI7czoyNzoiaHR0cDovLzEwMy4xNTQuODAuMTcxL2FkbWluIjt9fQ==',1769649373),
('Kpb5f27VGQmXSFcSL6xQEtlOSl0KQ12IUQrCLIBz',NULL,'104.28.245.127','curl/8.13.0','YTozOntzOjY6Il90b2tlbiI7czo0MDoickVVR2V3UkFQZ1dvbmlJMXA5bVdxa01rZmd4S1BnZ0VYSXZFenNWZSI7czo5OiJfcHJldmlvdXMiO2E6Mjp7czozOiJ1cmwiO3M6NDA6Imh0dHA6Ly8xMDMuMTU0LjgwLjE3MS9TbWFydENNUy9pbmRleC5waHAiO3M6NToicm91dGUiO047fXM6NjoiX2ZsYXNoIjthOjI6e3M6Mzoib2xkIjthOjA6e31zOjM6Im5ldyI7YTowOnt9fX0=',1769646971),
('ycWU2N7hkj6NDaAESDLPLETINPkX4NlEpd3wu8bn',NULL,'127.0.0.1','curl/8.13.0','YTozOntzOjY6Il90b2tlbiI7czo0MDoiSGg5dlBDMUtrbVJpRVo2Zm5wdTdKZmVXQU13dVFuakV0UDRkVzlXYSI7czo5OiJfcHJldmlvdXMiO2E6Mjp7czozOiJ1cmwiO3M6MjE6Imh0dHA6Ly8xMDMuMTU0LjgwLjE3MSI7czo1OiJyb3V0ZSI7Tjt9czo2OiJfZmxhc2giO2E6Mjp7czozOiJvbGQiO2E6MDp7fXM6MzoibmV3IjthOjA6e319fQ==',1769649242);
/*!40000 ALTER TABLE `sessions` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `static_routes`
--

DROP TABLE IF EXISTS `static_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `static_routes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `network` varchar(191) NOT NULL,
  `subnet` varchar(191) NOT NULL,
  `gateway` varchar(191) NOT NULL,
  `device` varchar(191) NOT NULL,
  `description` varchar(191) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `static_routes_call_server_id_foreign` (`call_server_id`),
  CONSTRAINT `static_routes_call_server_id_foreign` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `static_routes`
--

LOCK TABLES `static_routes` WRITE;
/*!40000 ALTER TABLE `static_routes` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `static_routes` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `sub_branches`
--

DROP TABLE IF EXISTS `sub_branches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sub_branches` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customer_id` int(11) DEFAULT NULL,
  `branch_id` int(11) DEFAULT NULL,
  `call_server_id` int(11) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `code` varchar(50) DEFAULT NULL,
  `country` varchar(100) DEFAULT NULL,
  `province` varchar(100) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `district` varchar(100) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `contact_name` varchar(255) DEFAULT NULL,
  `contact_phone` varchar(50) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `customer_id` (`customer_id`),
  KEY `branch_id` (`branch_id`),
  CONSTRAINT `sub_branches_ibfk_1` FOREIGN KEY (`customer_id`) REFERENCES `customers` (`id`) ON DELETE SET NULL,
  CONSTRAINT `sub_branches_ibfk_2` FOREIGN KEY (`branch_id`) REFERENCES `branches` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sub_branches`
--

LOCK TABLES `sub_branches` WRITE;
/*!40000 ALTER TABLE `sub_branches` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `sub_branches` VALUES
(1,2,1,4,'KAI Juanda Cimahi','KAI CMH 011','Indonesia','Jawa Barat','Cimahi','Cimahi Tengah','Jl. Juanda Cimahi','','','',1,'2026-01-30 10:05:14','2026-01-30 18:01:35');
/*!40000 ALTER TABLE `sub_branches` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `system_logs`
--

DROP TABLE IF EXISTS `system_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `level` enum('debug','info','warning','error','critical') DEFAULT 'info',
  `message` text NOT NULL,
  `context` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `system_logs`
--

LOCK TABLES `system_logs` WRITE;
/*!40000 ALTER TABLE `system_logs` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `system_logs` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `time_conditions`
--

DROP TABLE IF EXISTS `time_conditions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `time_conditions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `call_server_id` int(11) DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `time_group_id` int(11) DEFAULT NULL,
  `match_destination` varchar(255) DEFAULT NULL,
  `nomatch_destination` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `call_server_id` (`call_server_id`),
  CONSTRAINT `time_conditions_ibfk_1` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `time_conditions`
--

LOCK TABLES `time_conditions` WRITE;
/*!40000 ALTER TABLE `time_conditions` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `time_conditions` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `trunks`
--

DROP TABLE IF EXISTS `trunks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `trunks` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `sip_server` varchar(255) NOT NULL,
  `sip_server_port` int(11) DEFAULT 5060,
  `outcid` varchar(255) DEFAULT NULL,
  `maxchans` int(11) DEFAULT 2,
  `transport` varchar(20) DEFAULT 'udp',
  `context` varchar(100) DEFAULT 'from-pstn',
  `codecs` varchar(100) DEFAULT 'ulaw,alaw',
  `dtmfmode` varchar(20) DEFAULT 'auto',
  `registration` varchar(20) DEFAULT 'none',
  `auth_username` varchar(100) DEFAULT NULL,
  `secret` varchar(100) DEFAULT NULL,
  `qualify` tinyint(1) DEFAULT 1,
  `qualify_frequency` int(11) DEFAULT 60,
  `disabled` tinyint(1) DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `trunks`
--

LOCK TABLES `trunks` WRITE;
/*!40000 ALTER TABLE `trunks` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `trunks` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(191) NOT NULL,
  `email` varchar(191) NOT NULL,
  `email_verified_at` timestamp NULL DEFAULT NULL,
  `password` varchar(191) NOT NULL,
  `remember_token` varchar(100) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `users_email_unique` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES
(1,'Root Admin','root@smartcms.local',NULL,'$2y$12$0C8/MhlXdOgV.lrumF4.BeLJRcHxxYW.9AWUTytDv0S2nUQw.eKUC',NULL,'2026-01-28 17:41:24','2026-01-29 06:32:32'),
(2,'Admin','admin@smartx.local',NULL,'$2y$12$64LubVJh6eme1OWPQcdtSu1wkDuktulZ44epINbkJ0tFYNy5jfi.W',NULL,'2026-01-28 17:41:24','2026-01-29 06:32:33'),
(3,'CMS Admin','cmsadmin@smartx.local',NULL,'$2y$12$foK1p/ToMBX7GeS3Gg2ZJusx8y2MZESWvVkqHdQkPYtTzKJYPmmWa',NULL,'2026-01-28 17:41:24','2026-01-29 06:32:33');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;

--
-- Table structure for table `vpws`
--

DROP TABLE IF EXISTS `vpws`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpws` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint(20) unsigned DEFAULT NULL,
  `trunk_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `vpw_number` varchar(50) NOT NULL,
  `type` varchar(50) DEFAULT 'point_to_point',
  `source_extension` varchar(50) DEFAULT NULL,
  `destination` varchar(100) DEFAULT NULL,
  `destination_local` tinyint(1) DEFAULT 0,
  `priority` int(11) DEFAULT 0,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vpws`
--

LOCK TABLES `vpws` WRITE;
/*!40000 ALTER TABLE `vpws` DISABLE KEYS */;
set autocommit=0;
/*!40000 ALTER TABLE `vpws` ENABLE KEYS */;
UNLOCK TABLES;
commit;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2026-02-01  3:43:09
