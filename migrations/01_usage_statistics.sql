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
-- Table structure for table `usage_statistics`
--

DROP TABLE IF EXISTS `usage_statistics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usage_statistics` (
  `id` int NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `branch_id` int DEFAULT NULL,
  `call_server_id` int DEFAULT NULL,
  `extension_number` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  `line_inbound` int DEFAULT '0',
  `line_outbound` int DEFAULT '0',
  `ext_inbound` int DEFAULT '0',
  `ext_outbound` int DEFAULT '0',
  `vpw_inbound` int DEFAULT '0',
  `vpw_outbound` int DEFAULT '0',
  `cas_inbound` int DEFAULT '0',
  `cas_outbound` int DEFAULT '0',
  `sip_inbound` int DEFAULT '0',
  `sip_outbound` int DEFAULT '0',
  `total_time_inbound` int DEFAULT '0',
  `total_time_outbound` int DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_daily_ext` (`date`,`call_server_id`,`extension_number`),
  KEY `idx_date` (`date`),
  KEY `idx_branch` (`branch_id`),
  KEY `idx_call_server` (`call_server_id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usage_statistics`
--

LOCK TABLES `usage_statistics` WRITE;
/*!40000 ALTER TABLE `usage_statistics` DISABLE KEYS */;
INSERT INTO `usage_statistics` VALUES (1,'2026-02-04',1,3,'8001',4,5,0,0,0,0,0,0,0,0,1932,43960,'2026-02-04 07:32:37'),(2,'2026-02-04',1,3,'8002',1,4,0,0,0,0,0,0,0,0,1933,43961,'2026-02-04 07:32:37'),(3,'2026-02-04',1,3,'8101',0,0,3,10,0,0,0,0,0,0,794,43962,'2026-02-04 07:32:37'),(4,'2026-02-04',1,3,'8102',0,0,0,2,0,0,0,0,0,0,1935,43963,'2026-02-04 07:32:37'),(5,'2026-02-04',1,3,'8201',0,0,0,0,7,2,0,0,0,0,1936,43964,'2026-02-04 07:32:37'),(6,'2026-02-04',1,3,'8202',0,0,0,0,1,0,0,0,0,0,1937,43965,'2026-02-04 07:32:37'),(7,'2026-02-04',1,3,'8301',0,0,0,0,0,0,3,7,0,0,1938,43966,'2026-02-04 07:32:37'),(8,'2026-02-04',1,3,'8302',0,0,0,0,0,0,3,5,0,0,1939,43967,'2026-02-04 07:32:37'),(9,'2026-02-04',1,3,'7001',0,0,0,0,0,0,0,0,32,45,1940,43968,'2026-02-04 07:32:37'),(10,'2026-02-04',1,3,'7002',0,0,0,0,0,0,0,0,12,6,1941,43969,'2026-02-04 07:32:37');
/*!40000 ALTER TABLE `usage_statistics` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-02-04 18:38:26
