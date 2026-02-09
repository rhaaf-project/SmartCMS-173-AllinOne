-- MySQL dump 10.13  Distrib 8.4.7, for Win64 (x86_64)
--
-- Host: localhost    Database: db_ucx
-- ------------------------------------------------------
-- Server version	8.4.7

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `activity_logs`
--

DROP TABLE IF EXISTS `activity_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `activity_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `action` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `entity_type` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `entity_id` int DEFAULT NULL,
  `old_values` text COLLATE utf8mb4_unicode_ci,
  `new_values` text COLLATE utf8mb4_unicode_ci,
  `ip_address` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `user_agent` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `activity_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `cms_users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `activity_logs`
--

LOCK TABLES `activity_logs` WRITE;
/*!40000 ALTER TABLE `activity_logs` DISABLE KEYS */;
INSERT INTO `activity_logs` VALUES (1,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.6133','2026-02-01 14:01:47'),(2,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:12:00'),(3,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:12:11'),(4,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:12:27'),(5,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:12:52'),(6,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:13:51'),(7,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:14:31'),(8,NULL,'logout','auth',NULL,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:14:59'),(9,NULL,'logout','auth',NULL,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:16:42');
/*!40000 ALTER TABLE `activity_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `alarm_notifications`
--

DROP TABLE IF EXISTS `alarm_notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `alarm_notifications` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `type` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'notification',
  `severity` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'low',
  `title` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `message` text COLLATE utf8mb4_unicode_ci,
  `is_read` tinyint(1) DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `alarm_notifications`
--

LOCK TABLES `alarm_notifications` WRITE;
/*!40000 ALTER TABLE `alarm_notifications` DISABLE KEYS */;
/*!40000 ALTER TABLE `alarm_notifications` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `branches`
--

DROP TABLE IF EXISTS `branches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `branches` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` int DEFAULT NULL,
  `head_office_id` int DEFAULT NULL,
  `call_server_id` int DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `code` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `country` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `province` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `city` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `district` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `address` text COLLATE utf8mb4_unicode_ci,
  `contact_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `contact_phone` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
INSERT INTO `branches` VALUES (1,2,2,3,'KAI Cimahi','KAI CMH 01','Indonesia','Jawa Barat','Cimahi','Cimahi Tengah','CImahi Jawa Barat','','','',1,'2026-01-30 09:56:59','2026-01-30 18:01:49');
/*!40000 ALTER TABLE `branches` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `call_logs`
--

DROP TABLE IF EXISTS `call_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `call_logs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `caller` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `callee` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `duration` int NOT NULL DEFAULT '0',
  `status` enum('answered','missed','busy','failed') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'missed',
  `started_at` timestamp NULL DEFAULT NULL,
  `ended_at` timestamp NULL DEFAULT NULL,
  `channel_id` bigint unsigned DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `call_logs_channel_id_index` (`channel_id`),
  KEY `call_logs_created_at_index` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `call_logs`
--

LOCK TABLES `call_logs` WRITE;
/*!40000 ALTER TABLE `call_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `call_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `call_servers`
--

DROP TABLE IF EXISTS `call_servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `call_servers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `head_office_id` int DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `host` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `port` int DEFAULT '5060',
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
INSERT INTO `call_servers` VALUES (1,1,'SmartUCX-1-HO','103.154.80.172',5060,NULL,1,'2026-01-29 17:28:18','2026-01-29 17:28:18'),(2,2,'SmartUCX-1-KAI','103.154.81.101',5060,NULL,1,'2026-01-30 17:52:41','2026-01-30 17:59:32'),(3,2,'SmartUCX-2-KAI','103.154.81.102',5060,NULL,1,'2026-01-30 17:53:31','2026-01-30 17:59:39'),(4,2,'SmartUCX-3-KAI','103.154.81.103',5060,NULL,1,'2026-01-30 17:53:43','2026-01-30 17:59:48'),(5,2,'SmartUCX-4-KAI','103.154.81.104',5060,NULL,1,'2026-01-30 17:54:01','2026-01-30 17:59:56'),(6,2,'SmartUCX-5-KAI','103.154.81.105',5060,NULL,1,'2026-01-30 17:54:12','2026-01-30 18:00:16'),(7,3,'SmartGAR-1-HO','103.154.80.125',5060,NULL,1,'2026-01-31 14:05:24','2026-01-31 14:05:24');
/*!40000 ALTER TABLE `call_servers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cas`
--

DROP TABLE IF EXISTS `cas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cas` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cas_number` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `channel_number` int DEFAULT NULL,
  `signaling_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `trunk_id` bigint unsigned DEFAULT NULL,
  `span` int DEFAULT NULL,
  `timeslot` int DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `destination` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `destination_local` tinyint(1) DEFAULT '0',
  `is_active` tinyint(1) DEFAULT '1',
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
/*!40000 ALTER TABLE `cas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cms_groups`
--

DROP TABLE IF EXISTS `cms_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cms_groups` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `permissions` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cms_groups`
--

LOCK TABLES `cms_groups` WRITE;
/*!40000 ALTER TABLE `cms_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `cms_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cms_users`
--

DROP TABLE IF EXISTS `cms_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cms_users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `role` enum('admin','operator','viewer') COLLATE utf8mb4_unicode_ci DEFAULT 'viewer',
  `is_active` tinyint(1) DEFAULT '1',
  `last_login` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cms_users`
--

LOCK TABLES `cms_users` WRITE;
/*!40000 ALTER TABLE `cms_users` DISABLE KEYS */;
INSERT INTO `cms_users` VALUES (1,'Administrator','admin@smartcms.local','$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi','admin',1,NULL,'2026-01-29 17:28:18','2026-01-29 17:28:18');
/*!40000 ALTER TABLE `cms_users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `conferences`
--

DROP TABLE IF EXISTS `conferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `conferences` (
  `id` int NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `conf_num` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pin` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `admin_pin` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `options` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
/*!40000 ALTER TABLE `conferences` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `customers`
--

DROP TABLE IF EXISTS `customers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `customers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `code` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `contact_person` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `phone` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `address` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `customers`
--

LOCK TABLES `customers` WRITE;
/*!40000 ALTER TABLE `customers` DISABLE KEYS */;
INSERT INTO `customers` VALUES (1,'PT Smart Infinite Prosperity','SIP','Joni Me Ow','joni@smart.com','02150877432','Jakarta, Indonesia',1,'2026-01-29 17:28:18','2026-01-29 17:28:18'),(2,'PT KAI','KAI IND','Kaimanu','kaimanu@kai,id','123456','Gambir Jakarta',1,'2026-01-29 18:00:14','2026-01-29 18:00:14'),(3,'PT Garuda','GARUDA IND','Garuda','garuda@garuda.id','123456','Monas Jakarta',1,'2026-01-31 14:03:41','2026-01-31 14:03:41');
/*!40000 ALTER TABLE `customers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dahdi_channels`
--

DROP TABLE IF EXISTS `dahdi_channels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dahdi_channels` (
  `id` int NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `channel_type` enum('fxo','fxs','e1','e1_cas') COLLATE utf8mb4_unicode_ci NOT NULL,
  `span` int DEFAULT NULL,
  `channel` int DEFAULT NULL,
  `signalling` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `context` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
/*!40000 ALTER TABLE `dahdi_channels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_3rd_parties`
--

DROP TABLE IF EXISTS `device_3rd_parties`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_3rd_parties` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `mac_address` varchar(17) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ip_address` varchar(15) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `device_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT 'ip_phone',
  `manufacturer` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `model` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
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
/*!40000 ALTER TABLE `device_3rd_parties` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `extensions`
--

DROP TABLE IF EXISTS `extensions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `extensions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `extension` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `voicemail` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `outbound_cid` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ring_timer` int DEFAULT '30',
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
/*!40000 ALTER TABLE `extensions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `head_offices`
--

DROP TABLE IF EXISTS `head_offices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `head_offices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` int DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `code` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `type` enum('basic','ha','fo') COLLATE utf8mb4_unicode_ci DEFAULT 'basic',
  `country` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `province` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `city` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `district` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `address` text COLLATE utf8mb4_unicode_ci,
  `contact_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `contact_phone` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `bcp_drc_server_id` int DEFAULT NULL,
  `bcp_drc_enabled` tinyint(1) DEFAULT '0',
  `call_servers_json` text COLLATE utf8mb4_unicode_ci,
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
INSERT INTO `head_offices` VALUES (1,1,'HO Jakarta','HO-JKT','ha',NULL,NULL,'Jakarta',NULL,NULL,NULL,NULL,NULL,1,'2026-01-29 17:28:18','2026-01-29 17:28:18',NULL,0,NULL),(2,2,'HO KAI Indonesia','KAI IND 01','ha','Indonesia','DKI','Jakarta','Jakarta Pusat','Gambir','','','',1,'2026-01-29 18:04:43','2026-01-30 18:00:46',6,0,'[{\"call_server_id\":2,\"is_enabled\":true},{\"call_server_id\":3,\"is_enabled\":true},{\"call_server_id\":4,\"is_enabled\":true}]'),(3,3,'HO Garuda Indonesia','GAR IND 01','basic','Indonesia','DKI','Jakarta','Jakarta Pusat','Monas','','','',1,'2026-01-31 14:04:48','2026-01-31 14:04:48',1,0,'[{\"call_server_id\":6,\"is_enabled\":true}]');
/*!40000 ALTER TABLE `head_offices` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `inbound_routings`
--

DROP TABLE IF EXISTS `inbound_routings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `inbound_routings` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `did_number` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `destination` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `destination_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
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
/*!40000 ALTER TABLE `inbound_routings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `intercoms`
--

DROP TABLE IF EXISTS `intercoms`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `intercoms` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `branch_id` bigint unsigned DEFAULT NULL,
  `name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `extension` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `intercoms_call_server_id_index` (`call_server_id`),
  KEY `intercoms_branch_id_index` (`branch_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `intercoms`
--

LOCK TABLES `intercoms` WRITE;
/*!40000 ALTER TABLE `intercoms` DISABLE KEYS */;
INSERT INTO `intercoms` VALUES (1,4,1,'kaimanu','6001',NULL,1,NULL,NULL);
/*!40000 ALTER TABLE `intercoms` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ivr`
--

DROP TABLE IF EXISTS `ivr`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ivr` (
  `id` int NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `announcement` int DEFAULT NULL,
  `direct_dial` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `timeout_time` int DEFAULT '10',
  `invalid_loops` int DEFAULT '3',
  `timeout_destination` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `invalid_destination` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
/*!40000 ALTER TABLE `ivr` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `lines`
--

DROP TABLE IF EXISTS `lines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lines` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `line_number` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT 'sip',
  `channel_count` int DEFAULT '1',
  `trunk_id` bigint unsigned DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `secret` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
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
INSERT INTO `lines` VALUES (1,2,'kaimanu','110011','sip',1,NULL,NULL,'1234',1,NULL,NULL),(2,3,'kaimanu','110012','sip',1,NULL,NULL,'1234',1,NULL,NULL),(3,4,'kaimanu','110013','sip',1,NULL,NULL,'1234',1,NULL,NULL),(4,2,'kaimanu','110021','sip',1,NULL,NULL,'1234',1,NULL,NULL),(5,3,'kaimanu','110022','sip',1,NULL,NULL,'1234',1,NULL,NULL),(6,4,'kaimanu','110023','sip',1,NULL,NULL,'1234',1,NULL,NULL),(7,1,'Smartono','100011','sip',1,NULL,NULL,'1234',1,NULL,NULL);
/*!40000 ALTER TABLE `lines` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `outbound_routings`
--

DROP TABLE IF EXISTS `outbound_routings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `outbound_routings` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `dial_pattern` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `trunk_id` bigint unsigned DEFAULT NULL,
  `priority` int DEFAULT '0',
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
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
/*!40000 ALTER TABLE `outbound_routings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `private_wires`
--

DROP TABLE IF EXISTS `private_wires`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `private_wires` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `number` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `destination` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
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
/*!40000 ALTER TABLE `private_wires` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ring_groups`
--

DROP TABLE IF EXISTS `ring_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ring_groups` (
  `id` int NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `grp_num` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `strategy` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT 'ringall',
  `grp_time` int DEFAULT '20',
  `grp_list` text COLLATE utf8mb4_unicode_ci,
  `destination` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
/*!40000 ALTER TABLE `ring_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sbc_routes`
--

DROP TABLE IF EXISTS `sbc_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sbc_routes` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `src_call_server_id` bigint unsigned DEFAULT NULL,
  `src_description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `src_pattern` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `src_cid_filter` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `src_priority` int DEFAULT '0',
  `src_is_active` tinyint(1) DEFAULT '1',
  `src_from_sbc_id` bigint unsigned DEFAULT NULL,
  `src_destination_id` bigint unsigned DEFAULT NULL,
  `dest_call_server_id` bigint unsigned DEFAULT NULL,
  `dest_description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `dest_pattern` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `dest_cid_filter` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `dest_priority` int DEFAULT '0',
  `dest_is_active` tinyint(1) DEFAULT '1',
  `dest_from_sbc_id` bigint unsigned DEFAULT NULL,
  `dest_destination_id` bigint unsigned DEFAULT NULL,
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
/*!40000 ALTER TABLE `sbc_routes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sbcs`
--

DROP TABLE IF EXISTS `sbcs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sbcs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `sip_server` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `sip_server_port` int DEFAULT '5060',
  `outcid` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `maxchans` int DEFAULT '2',
  `transport` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'udp',
  `context` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT 'from-pstn',
  `codecs` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT 'ulaw,alaw',
  `dtmfmode` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'auto',
  `registration` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'none',
  `auth_username` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `secret` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `qualify` tinyint(1) DEFAULT '1',
  `qualify_frequency` int DEFAULT '60',
  `disabled` tinyint(1) DEFAULT '0',
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
/*!40000 ALTER TABLE `sbcs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sub_branches`
--

DROP TABLE IF EXISTS `sub_branches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sub_branches` (
  `id` int NOT NULL AUTO_INCREMENT,
  `customer_id` int DEFAULT NULL,
  `branch_id` int DEFAULT NULL,
  `call_server_id` int DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `code` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `country` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `province` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `city` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `district` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `address` text COLLATE utf8mb4_unicode_ci,
  `contact_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `contact_phone` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
INSERT INTO `sub_branches` VALUES (1,2,1,4,'KAI Juanda Cimahi','KAI CMH 011','Indonesia','Jawa Barat','Cimahi','Cimahi Tengah','Jl. Juanda Cimahi','','','',1,'2026-01-30 10:05:14','2026-01-30 18:01:35');
/*!40000 ALTER TABLE `sub_branches` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `system_logs`
--

DROP TABLE IF EXISTS `system_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `level` enum('debug','info','warning','error','critical') COLLATE utf8mb4_unicode_ci DEFAULT 'info',
  `message` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `context` text COLLATE utf8mb4_unicode_ci,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `system_logs`
--

LOCK TABLES `system_logs` WRITE;
/*!40000 ALTER TABLE `system_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `system_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `time_conditions`
--

DROP TABLE IF EXISTS `time_conditions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `time_conditions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `time_group_id` int DEFAULT NULL,
  `match_destination` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `nomatch_destination` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
/*!40000 ALTER TABLE `time_conditions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `trunks`
--

DROP TABLE IF EXISTS `trunks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trunks` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `sip_server` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `sip_server_port` int DEFAULT '5060',
  `outcid` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `maxchans` int DEFAULT '2',
  `transport` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'udp',
  `context` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT 'from-pstn',
  `codecs` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT 'ulaw,alaw',
  `dtmfmode` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'auto',
  `registration` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'none',
  `auth_username` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `secret` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `qualify` tinyint(1) DEFAULT '1',
  `qualify_frequency` int DEFAULT '60',
  `disabled` tinyint(1) DEFAULT '0',
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `trunks`
--

LOCK TABLES `trunks` WRITE;
/*!40000 ALTER TABLE `trunks` DISABLE KEYS */;
INSERT INTO `trunks` VALUES (1,7,'Garuda','',5060,NULL,2,'udp','from-pstn','ulaw,alaw','auto','none',NULL,NULL,1,60,0,NULL,NULL);
/*!40000 ALTER TABLE `trunks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vpws`
--

DROP TABLE IF EXISTS `vpws`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpws` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` bigint unsigned DEFAULT NULL,
  `trunk_id` bigint unsigned DEFAULT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `vpw_number` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT 'point_to_point',
  `source_extension` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `destination` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `destination_local` tinyint(1) DEFAULT '0',
  `priority` int DEFAULT '0',
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
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
/*!40000 ALTER TABLE `vpws` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-02-01 21:26:55
