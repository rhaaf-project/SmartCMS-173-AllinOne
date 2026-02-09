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
) ENGINE=InnoDB AUTO_INCREMENT=70 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `activity_logs`
--

LOCK TABLES `activity_logs` WRITE;
/*!40000 ALTER TABLE `activity_logs` DISABLE KEYS */;
INSERT INTO `activity_logs` VALUES (1,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.6133','2026-02-01 14:01:47');
INSERT INTO `activity_logs` VALUES (2,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:12:00');
INSERT INTO `activity_logs` VALUES (3,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:12:11');
INSERT INTO `activity_logs` VALUES (4,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:12:27');
INSERT INTO `activity_logs` VALUES (5,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:12:52');
INSERT INTO `activity_logs` VALUES (6,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:13:51');
INSERT INTO `activity_logs` VALUES (7,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:14:31');
INSERT INTO `activity_logs` VALUES (8,NULL,'logout','auth',NULL,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:14:59');
INSERT INTO `activity_logs` VALUES (9,NULL,'logout','auth',NULL,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 14:16:42');
INSERT INTO `activity_logs` VALUES (10,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 15:21:41');
INSERT INTO `activity_logs` VALUES (11,NULL,'login','auth',NULL,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"CMS Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 15:21:46');
INSERT INTO `activity_logs` VALUES (12,NULL,'logout','auth',NULL,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"CMS Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 15:21:51');
INSERT INTO `activity_logs` VALUES (13,NULL,'login','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 15:21:55');
INSERT INTO `activity_logs` VALUES (14,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 15:45:21');
INSERT INTO `activity_logs` VALUES (15,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 15:56:12');
INSERT INTO `activity_logs` VALUES (16,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 15:57:54');
INSERT INTO `activity_logs` VALUES (17,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 15:58:24');
INSERT INTO `activity_logs` VALUES (18,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.6133','2026-02-01 18:15:57');
INSERT INTO `activity_logs` VALUES (19,NULL,'logout','auth',NULL,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 18:19:29');
INSERT INTO `activity_logs` VALUES (20,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 18:19:33');
INSERT INTO `activity_logs` VALUES (21,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 18:22:10');
INSERT INTO `activity_logs` VALUES (27,NULL,'login','auth',2,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"CMS Admin\"}','::1','Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.6133','2026-02-01 18:24:31');
INSERT INTO `activity_logs` VALUES (28,NULL,'login','auth',2,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"CMS Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 18:25:18');
INSERT INTO `activity_logs` VALUES (29,NULL,'logout','auth',NULL,NULL,'{\"email\":\"cmsadmin@smartx.local\",\"name\":\"CMS Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 18:25:38');
INSERT INTO `activity_logs` VALUES (30,NULL,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-01 18:25:43');
INSERT INTO `activity_logs` VALUES (31,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 00:12:32');
INSERT INTO `activity_logs` VALUES (32,NULL,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 00:12:35');
INSERT INTO `activity_logs` VALUES (33,NULL,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 00:24:13');
INSERT INTO `activity_logs` VALUES (34,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 00:29:50');
INSERT INTO `activity_logs` VALUES (35,NULL,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 00:29:52');
INSERT INTO `activity_logs` VALUES (36,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 00:45:54');
INSERT INTO `activity_logs` VALUES (37,NULL,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 00:45:56');
INSERT INTO `activity_logs` VALUES (38,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:09:17');
INSERT INTO `activity_logs` VALUES (39,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:12:53');
INSERT INTO `activity_logs` VALUES (40,1,'update','users',1,NULL,'{\"id\":1,\"name\":\"Root Admin\",\"email\":\"root@smartcms.local\",\"profile_image\":\"user_1769994791_697ffa274a0e1.jpg\",\"password\":\"$2y$10$stMS2vV9t8gJjbe3VAhrdukbK0Ti1KrSOLGTy.UZjKgqjTOb2aPJu\",\"role\":\"admin\",\"is_active\":1,\"last_login\":\"2026-02-02 08:12:53\",\"created_at\":\"2026-02-01 22:37:47\",\"updated_at\":\"2026-02-02 08:12:53\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:13:11');
INSERT INTO `activity_logs` VALUES (41,1,'update','users',1,NULL,'{\"id\":1,\"name\":\"Root Admin\",\"email\":\"root@smartcms.local\",\"profile_image\":\"user_1769994814_697ffa3ed0eb4.jpg\",\"password\":\"$2y$10$UuOc9fL5aomA67RvMsAQieibU.Q\\/.YVNk2ZwZ052pLTyDAUJRcwB2\",\"role\":\"admin\",\"is_active\":1,\"last_login\":\"2026-02-02 08:12:53\",\"created_at\":\"2026-02-01 22:37:47\",\"updated_at\":\"2026-02-02 08:12:53\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:13:34');
INSERT INTO `activity_logs` VALUES (42,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:15:19');
INSERT INTO `activity_logs` VALUES (43,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:15:21');
INSERT INTO `activity_logs` VALUES (44,1,'update','users',1,NULL,'{\"id\":1,\"name\":\"Root Admin\",\"email\":\"root@smartcms.local\",\"profile_image\":\"user_1769994935_697ffab75a7fa.jpg\",\"password\":\"$2y$10$CyCcGQOCJ3J6Yr3MLyMq.u7NAUu7C6FBqF6hZlm5AV\\/xVaBiNHmQ2\",\"role\":\"admin\",\"is_active\":1,\"last_login\":\"2026-02-02 08:15:21\",\"created_at\":\"2026-02-01 22:37:47\",\"updated_at\":\"2026-02-02 08:15:21\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:15:35');
INSERT INTO `activity_logs` VALUES (45,1,'update','users',1,NULL,'{\"id\":1,\"name\":\"Root Admin\",\"email\":\"root@smartcms.local\",\"profile_image\":\"user_1769994935_697ffab75a7fa.jpg\",\"password\":\"$2y$10$uROCwJdnuQEvAHp0fJyyF.v2jTavZccBeu9GDKd4mIvQDVf1E5yde\",\"role\":\"admin\",\"is_active\":1,\"last_login\":\"2026-02-02 08:15:21\",\"created_at\":\"2026-02-01 22:37:47\",\"updated_at\":\"2026-02-02 08:15:21\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:15:46');
INSERT INTO `activity_logs` VALUES (46,1,'update','users',1,NULL,'{\"id\":1,\"name\":\"Root Admin\",\"email\":\"root@smartcms.local\",\"profile_image\":\"user_1769995225_697ffbd9e4078.jpg\",\"password\":\"$2y$10$ps5kXM6Y.A9JW3mvRkHRTOU9hrZg4\\/LmcQNGICp6XTEHteg4x85lq\",\"role\":\"admin\",\"is_active\":1,\"last_login\":\"2026-02-02 08:15:21\",\"created_at\":\"2026-02-01 22:37:47\",\"updated_at\":\"2026-02-02 08:15:21\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:20:25');
INSERT INTO `activity_logs` VALUES (47,1,'update','users',1,NULL,'{\"id\":1,\"name\":\"Root Admin\",\"email\":\"root@smartcms.local\",\"profile_image\":\"user_1769995349_697ffc551c1b3.jpg\",\"password\":\"$2y$10$RhxdhOeRRYvGP8hL3mSRPe88nWqN26Xf9Ef1ZPmcmnedaZFdrv6zK\",\"role\":\"admin\",\"is_active\":1,\"last_login\":\"2026-02-02 08:15:21\",\"created_at\":\"2026-02-01 22:37:47\",\"updated_at\":\"2026-02-02 08:15:21\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 01:22:29');
INSERT INTO `activity_logs` VALUES (48,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-02 11:14:59');
INSERT INTO `activity_logs` VALUES (50,NULL,'login_failed','auth',NULL,NULL,'{\"email\":\"root@smartx.local\"}','127.0.0.1','Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36','2026-02-02 23:13:59');
INSERT INTO `activity_logs` VALUES (53,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 00:06:00');
INSERT INTO `activity_logs` VALUES (54,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 06:09:28');
INSERT INTO `activity_logs` VALUES (55,NULL,'login_failed','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 07:52:11');
INSERT INTO `activity_logs` VALUES (56,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 07:53:19');
INSERT INTO `activity_logs` VALUES (57,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 08:16:25');
INSERT INTO `activity_logs` VALUES (58,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 19:34:24');
INSERT INTO `activity_logs` VALUES (59,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 19:45:02');
INSERT INTO `activity_logs` VALUES (60,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 19:48:45');
INSERT INTO `activity_logs` VALUES (61,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 19:53:14');
INSERT INTO `activity_logs` VALUES (62,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 20:01:45');
INSERT INTO `activity_logs` VALUES (63,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-03 20:02:15');
INSERT INTO `activity_logs` VALUES (65,NULL,'logout','auth',NULL,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-04 11:26:27');
INSERT INTO `activity_logs` VALUES (67,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-04 16:05:37');
INSERT INTO `activity_logs` VALUES (68,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-04 16:48:31');
INSERT INTO `activity_logs` VALUES (69,1,'login','auth',1,NULL,'{\"email\":\"root@smartcms.local\",\"name\":\"Root Admin\"}','::1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','2026-02-05 05:49:41');
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
-- Table structure for table `announcements`
--

DROP TABLE IF EXISTS `announcements`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `announcements` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `filename` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `announcements`
--

LOCK TABLES `announcements` WRITE;
/*!40000 ALTER TABLE `announcements` DISABLE KEYS */;
/*!40000 ALTER TABLE `announcements` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `black_lists`
--

DROP TABLE IF EXISTS `black_lists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `black_lists` (
  `id` int NOT NULL AUTO_INCREMENT,
  `number` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `black_lists`
--

LOCK TABLES `black_lists` WRITE;
/*!40000 ALTER TABLE `black_lists` DISABLE KEYS */;
/*!40000 ALTER TABLE `black_lists` ENABLE KEYS */;
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
  `sbc_id` int DEFAULT NULL,
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
INSERT INTO `branches` VALUES (1,2,2,3,8,'KAI Cimahi','KAI CMH 01','Indonesia','Jawa Barat','Cimahi','Cimahi Tengah','CImahi Jawa Barat','','','',1,'2026-01-30 09:56:59','2026-02-04 16:17:39');
/*!40000 ALTER TABLE `branches` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cache`
--

DROP TABLE IF EXISTS `cache`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cache` (
  `key` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `value` mediumtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `expiration` int NOT NULL,
  PRIMARY KEY (`key`),
  KEY `cache_expiration_index` (`expiration`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cache`
--

LOCK TABLES `cache` WRITE;
/*!40000 ALTER TABLE `cache` DISABLE KEYS */;
/*!40000 ALTER TABLE `cache` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cache_locks`
--

DROP TABLE IF EXISTS `cache_locks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cache_locks` (
  `key` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `owner` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `expiration` int NOT NULL,
  PRIMARY KEY (`key`),
  KEY `cache_locks_expiration_index` (`expiration`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cache_locks`
--

LOCK TABLES `cache_locks` WRITE;
/*!40000 ALTER TABLE `cache_locks` DISABLE KEYS */;
/*!40000 ALTER TABLE `cache_locks` ENABLE KEYS */;
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
  `type` text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY (`id`),
  KEY `head_office_id` (`head_office_id`),
  CONSTRAINT `call_servers_ibfk_1` FOREIGN KEY (`head_office_id`) REFERENCES `head_offices` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `call_servers`
--

LOCK TABLES `call_servers` WRITE;
/*!40000 ALTER TABLE `call_servers` DISABLE KEYS */;
INSERT INTO `call_servers` VALUES (3,2,'SmartUCX-2-KAI','103.154.81.102',5060,NULL,1,'2026-01-30 17:53:31','2026-01-30 17:59:39',NULL);
INSERT INTO `call_servers` VALUES (4,2,'SmartUCX-3-KAI','103.154.81.103',5060,NULL,1,'2026-01-30 17:53:43','2026-01-30 17:59:48',NULL);
INSERT INTO `call_servers` VALUES (8,3,'Telkom','192.168.0.10',5060,NULL,1,'2026-02-02 11:16:29','2026-02-04 01:01:03','sbc');
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
  `call_server_id` int DEFAULT NULL,
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
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cas`
--

LOCK TABLES `cas` WRITE;
/*!40000 ALTER TABLE `cas` DISABLE KEYS */;
INSERT INTO `cas` VALUES (1,3,'CAS E1 Port 1','CAS-001',30,'E1',NULL,1,1,NULL,NULL,0,1,NULL,NULL);
INSERT INTO `cas` VALUES (2,3,'CAS E1 Port 2','CAS-002',30,'E1',NULL,1,2,NULL,NULL,0,1,NULL,NULL);
INSERT INTO `cas` VALUES (3,3,'CAS E1 Port 3','CAS-003',30,'E1',NULL,2,1,NULL,NULL,0,1,NULL,NULL);
INSERT INTO `cas` VALUES (4,3,'CAS PRI Link 1','CAS-004',23,'PRI',NULL,1,1,NULL,NULL,0,1,NULL,NULL);
INSERT INTO `cas` VALUES (5,3,'CAS PRI Link 2','CAS-005',23,'PRI',NULL,2,1,NULL,NULL,0,1,NULL,NULL);
/*!40000 ALTER TABLE `cas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cdrs`
--

DROP TABLE IF EXISTS `cdrs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cdrs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `calldate` datetime NOT NULL,
  `clid` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `src` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `dst` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `dcontext` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `channel` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `dstchannel` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `lastapp` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `lastdata` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `duration` int NOT NULL DEFAULT '0',
  `billsec` int NOT NULL DEFAULT '0',
  `disposition` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `amaflags` int NOT NULL DEFAULT '0',
  `accountcode` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `uniqueid` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `userfield` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `did` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `recordingfile` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `cnum` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `cnam` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `outbound_cnum` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `outbound_cnam` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `dst_cnam` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `linkedid` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `peeraccount` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `sequence` int NOT NULL DEFAULT '0',
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
/*!40000 ALTER TABLE `cdrs` ENABLE KEYS */;
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
-- Table structure for table `custom_destinations`
--

DROP TABLE IF EXISTS `custom_destinations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `custom_destinations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `target` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `notes` text COLLATE utf8mb4_unicode_ci,
  `return_call` tinyint(1) DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `custom_destinations`
--

LOCK TABLES `custom_destinations` WRITE;
/*!40000 ALTER TABLE `custom_destinations` DISABLE KEYS */;
/*!40000 ALTER TABLE `custom_destinations` ENABLE KEYS */;
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
INSERT INTO `customers` VALUES (1,'PT Smart Infinite Prosperity','SIP','Joni Me Ow','joni@smart.com','02150877432','Jakarta, Indonesia',1,'2026-01-29 17:28:18','2026-01-29 17:28:18');
INSERT INTO `customers` VALUES (2,'PT KAI','KAI IND','Kaimanu','kaimanu@kai,id','123456','Gambir Jakarta',1,'2026-01-29 18:00:14','2026-01-29 18:00:14');
INSERT INTO `customers` VALUES (3,'PT Garuda','GARUDA IND','Garuda','garuda@garuda.id','123456','Monas Jakarta',1,'2026-01-31 14:03:41','2026-01-31 14:03:41');
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
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_3rd_parties`
--

LOCK TABLES `device_3rd_parties` WRITE;
/*!40000 ALTER TABLE `device_3rd_parties` DISABLE KEYS */;
INSERT INTO `device_3rd_parties` VALUES (1,'Cisco IP Phone 7821','00:1B:54:AA:BB:01','192.168.100.101','ip_phone','Cisco','7821',NULL,1,NULL,NULL);
INSERT INTO `device_3rd_parties` VALUES (2,'Yealink T46S','80:5E:C0:CC:DD:02','192.168.100.102','ip_phone','Yealink','T46S',NULL,1,NULL,NULL);
INSERT INTO `device_3rd_parties` VALUES (3,'Grandstream GXP2170','00:0B:82:EE:FF:03','192.168.100.103','ip_phone','Grandstream','GXP2170',NULL,1,NULL,NULL);
INSERT INTO `device_3rd_parties` VALUES (4,'Polycom VVX 450','64:16:7F:11:22:04','192.168.100.104','ip_phone','Polycom','VVX 450',NULL,1,NULL,NULL);
INSERT INTO `device_3rd_parties` VALUES (5,'Fanvil X6U','AC:D1:B8:33:44:05','192.168.100.105','ip_phone','Fanvil','X6U',NULL,1,NULL,NULL);
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
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `extensions`
--

LOCK TABLES `extensions` WRITE;
/*!40000 ALTER TABLE `extensions` DISABLE KEYS */;
INSERT INTO `extensions` VALUES (1,3,'7001','Ext 7001 - SIP','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (2,3,'7002','Ext 7002 - SIP','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (3,3,'8001','Ext 8001 - Line','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (4,3,'8002','Ext 8002 - Line','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (5,3,'8101','Ext 8101 - Extension','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (6,3,'8102','Ext 8102 - Extension','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (7,3,'8201','Ext 8201 - VPW','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (8,3,'8202','Ext 8202 - VPW','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (9,3,'8301','Ext 8301 - CAS','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
INSERT INTO `extensions` VALUES (10,3,'8302','Ext 8302 - CAS','1234',NULL,NULL,30,1,'2026-02-04 11:38:39','2026-02-04 11:38:39');
/*!40000 ALTER TABLE `extensions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `failed_jobs`
--

DROP TABLE IF EXISTS `failed_jobs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `failed_jobs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `connection` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `queue` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `payload` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `exception` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `failed_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `failed_jobs_uuid_unique` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `failed_jobs`
--

LOCK TABLES `failed_jobs` WRITE;
/*!40000 ALTER TABLE `failed_jobs` DISABLE KEYS */;
/*!40000 ALTER TABLE `failed_jobs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `firewall_rules`
--

DROP TABLE IF EXISTS `firewall_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `firewall_rules` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `protocol` enum('TCP','UDP','ICMP','ALL') DEFAULT 'TCP',
  `port` varchar(50) NOT NULL COMMENT 'Port or range e.g. 5060 or 10000-20000',
  `source` varchar(50) DEFAULT 'Any',
  `action` enum('ACCEPT','DROP','REJECT') DEFAULT 'ACCEPT',
  `priority` int DEFAULT '100',
  `device_type` enum('call_server','sbc','recording') NOT NULL,
  `device_id` bigint unsigned NOT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `firewall_rules`
--

LOCK TABLES `firewall_rules` WRITE;
/*!40000 ALTER TABLE `firewall_rules` DISABLE KEYS */;
/*!40000 ALTER TABLE `firewall_rules` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `firewalls`
--

DROP TABLE IF EXISTS `firewalls`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `firewalls` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `port` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `source` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'any',
  `destination` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'any',
  `protocol` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `interface` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `direction` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `action` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `comment` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT '1',
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
/*!40000 ALTER TABLE `firewalls` ENABLE KEYS */;
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
INSERT INTO `head_offices` VALUES (1,1,'HO Jakarta','HO-JKT','ha',NULL,NULL,'Jakarta',NULL,NULL,NULL,NULL,NULL,1,'2026-01-29 17:28:18','2026-01-29 17:28:18',NULL,0,NULL);
INSERT INTO `head_offices` VALUES (2,2,'HO KAI Indonesia','KAI IND 01','ha','Indonesia','DKI','Jakarta','Jakarta Pusat','Gambir','','','',1,'2026-01-29 18:04:43','2026-01-30 18:00:46',6,0,'[{\"call_server_id\":2,\"is_enabled\":true},{\"call_server_id\":3,\"is_enabled\":true},{\"call_server_id\":4,\"is_enabled\":true}]');
INSERT INTO `head_offices` VALUES (3,3,'HO Garuda Indonesia','GAR IND 01','basic','Indonesia','DKI','Jakarta','Jakarta Pusat','Monas','','','',1,'2026-01-31 14:04:48','2026-01-31 14:04:48',1,0,'[{\"call_server_id\":6,\"is_enabled\":true}]');
/*!40000 ALTER TABLE `head_offices` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `inbound_routes`
--

DROP TABLE IF EXISTS `inbound_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `inbound_routes` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `did_number` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `trunk_id` bigint unsigned DEFAULT NULL,
  `destination_type` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'extension',
  `destination_id` bigint unsigned DEFAULT NULL,
  `cid_filter` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `priority` int NOT NULL DEFAULT '0',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
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
/*!40000 ALTER TABLE `inbound_routes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `inbound_routings`
--

DROP TABLE IF EXISTS `inbound_routings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `inbound_routings` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
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
  `call_server_id` int DEFAULT NULL,
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
-- Table structure for table `ivr_entries`
--

DROP TABLE IF EXISTS `ivr_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ivr_entries` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ivr_id` int DEFAULT NULL,
  `digits` varchar(10) COLLATE utf8mb4_unicode_ci NOT NULL,
  `destination` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `return_to_ivr` tinyint(1) DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ivr_id` (`ivr_id`),
  CONSTRAINT `ivr_entries_ibfk_1` FOREIGN KEY (`ivr_id`) REFERENCES `ivr` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ivr_entries`
--

LOCK TABLES `ivr_entries` WRITE;
/*!40000 ALTER TABLE `ivr_entries` DISABLE KEYS */;
/*!40000 ALTER TABLE `ivr_entries` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `job_batches`
--

DROP TABLE IF EXISTS `job_batches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `job_batches` (
  `id` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `total_jobs` int NOT NULL,
  `pending_jobs` int NOT NULL,
  `failed_jobs` int NOT NULL,
  `failed_job_ids` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `options` mediumtext COLLATE utf8mb4_unicode_ci,
  `cancelled_at` int DEFAULT NULL,
  `created_at` int NOT NULL,
  `finished_at` int DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `job_batches`
--

LOCK TABLES `job_batches` WRITE;
/*!40000 ALTER TABLE `job_batches` DISABLE KEYS */;
/*!40000 ALTER TABLE `job_batches` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `jobs`
--

DROP TABLE IF EXISTS `jobs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `jobs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `queue` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `payload` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `attempts` tinyint unsigned NOT NULL,
  `reserved_at` int unsigned DEFAULT NULL,
  `available_at` int unsigned NOT NULL,
  `created_at` int unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `jobs_queue_index` (`queue`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `jobs`
--

LOCK TABLES `jobs` WRITE;
/*!40000 ALTER TABLE `jobs` DISABLE KEYS */;
/*!40000 ALTER TABLE `jobs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `lines`
--

DROP TABLE IF EXISTS `lines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lines` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
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
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `lines`
--

LOCK TABLES `lines` WRITE;
/*!40000 ALTER TABLE `lines` DISABLE KEYS */;
INSERT INTO `lines` VALUES (1,8,'kaimanu','110011','sip',1,NULL,NULL,'1234',1,NULL,NULL);
INSERT INTO `lines` VALUES (2,3,'kaimanu','110012','sip',1,NULL,NULL,'1234',1,NULL,NULL);
INSERT INTO `lines` VALUES (3,4,'kaimanu','110013','sip',1,NULL,NULL,'1234',1,NULL,NULL);
INSERT INTO `lines` VALUES (4,3,'kaimanu','110021','sip',1,NULL,NULL,'1234',1,NULL,NULL);
INSERT INTO `lines` VALUES (5,3,'kaimanu','110022','sip',1,NULL,NULL,'1234',1,NULL,NULL);
INSERT INTO `lines` VALUES (6,4,'kaimanu','110023','sip',1,NULL,NULL,'1234',1,NULL,NULL);
INSERT INTO `lines` VALUES (7,8,'Smartono','100011','sip',1,NULL,NULL,'1234',1,NULL,NULL);
INSERT INTO `lines` VALUES (8,3,'Line Jakarta-01','021-5001','sip',4,NULL,NULL,NULL,1,NULL,NULL);
INSERT INTO `lines` VALUES (9,3,'Line Jakarta-02','021-5002','sip',4,NULL,NULL,NULL,1,NULL,NULL);
INSERT INTO `lines` VALUES (10,3,'Line Bandung-01','022-6001','sip',2,NULL,NULL,NULL,1,NULL,NULL);
INSERT INTO `lines` VALUES (11,3,'Line Surabaya-01','031-7001','sip',2,NULL,NULL,NULL,1,NULL,NULL);
INSERT INTO `lines` VALUES (12,4,'Line Medan-01','061-8001','sip',2,NULL,NULL,NULL,1,NULL,NULL);
/*!40000 ALTER TABLE `lines` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `migrations`
--

DROP TABLE IF EXISTS `migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `migrations` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `migration` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `batch` int NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `migrations`
--

LOCK TABLES `migrations` WRITE;
/*!40000 ALTER TABLE `migrations` DISABLE KEYS */;
INSERT INTO `migrations` VALUES (1,'0001_01_01_000000_create_users_table',1);
INSERT INTO `migrations` VALUES (2,'0001_01_01_000001_create_cache_table',1);
INSERT INTO `migrations` VALUES (3,'0001_01_01_000002_create_jobs_table',1);
INSERT INTO `migrations` VALUES (4,'2026_01_14_000000_create_extensions_table',1);
INSERT INTO `migrations` VALUES (5,'2026_01_14_000001_create_trunks_table',1);
INSERT INTO `migrations` VALUES (6,'2026_01_14_000002_create_call_servers_table',1);
INSERT INTO `migrations` VALUES (7,'2026_01_14_000003_add_call_server_to_trunks',1);
INSERT INTO `migrations` VALUES (8,'2026_01_14_000004_create_outbound_routes_table',1);
INSERT INTO `migrations` VALUES (9,'2026_01_14_000005_create_inbound_routes_table',1);
INSERT INTO `migrations` VALUES (10,'2026_01_14_000006_add_call_server_to_extensions',1);
INSERT INTO `migrations` VALUES (11,'2026_01_14_000007_create_lines_table',1);
INSERT INTO `migrations` VALUES (12,'2026_01_14_000008_create_vpws_table',1);
INSERT INTO `migrations` VALUES (13,'2026_01_14_000009_create_cas_table',1);
INSERT INTO `migrations` VALUES (14,'2026_01_14_000010_add_call_server_to_routes',1);
INSERT INTO `migrations` VALUES (15,'2026_01_14_000011_create_customers_table',1);
INSERT INTO `migrations` VALUES (16,'2026_01_14_000012_create_head_offices_table',1);
INSERT INTO `migrations` VALUES (17,'2026_01_14_000013_create_branches_table',1);
INSERT INTO `migrations` VALUES (18,'2026_01_14_000014_add_branch_id_to_extensions_lines',1);
INSERT INTO `migrations` VALUES (19,'2026_01_14_000015_add_head_office_to_call_servers',1);
INSERT INTO `migrations` VALUES (20,'2026_01_14_000016_remove_call_server_from_head_offices',1);
INSERT INTO `migrations` VALUES (21,'2026_01_14_000017_create_intercoms_table',1);
INSERT INTO `migrations` VALUES (22,'2026_01_20_000001_create_sbcs_and_private_wires_tables',1);
INSERT INTO `migrations` VALUES (23,'2026_01_22_create_firewalls_table',1);
INSERT INTO `migrations` VALUES (24,'2026_01_22_create_recording_servers_table',1);
INSERT INTO `migrations` VALUES (25,'2026_01_22_create_static_routes_table',1);
INSERT INTO `migrations` VALUES (26,'2026_01_23_create_sbc_routes_table',1);
INSERT INTO `migrations` VALUES (27,'2026_01_28_012547_create_personal_access_tokens_table',1);
INSERT INTO `migrations` VALUES (28,'2026_01_28_165200_create_sub_branches_table',1);
INSERT INTO `migrations` VALUES (29,'2026_01_28_170000_create_cdrs_table',1);
/*!40000 ALTER TABLE `migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `misc_destinations`
--

DROP TABLE IF EXISTS `misc_destinations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `misc_destinations` (
  `id` int NOT NULL AUTO_INCREMENT,
  `description` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `dial` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `misc_destinations`
--

LOCK TABLES `misc_destinations` WRITE;
/*!40000 ALTER TABLE `misc_destinations` DISABLE KEYS */;
/*!40000 ALTER TABLE `misc_destinations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `outbound_dial_patterns`
--

DROP TABLE IF EXISTS `outbound_dial_patterns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `outbound_dial_patterns` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `outbound_routing_id` bigint unsigned NOT NULL,
  `prepend` varchar(50) DEFAULT NULL COMMENT 'Digits to prepend before dialing',
  `prefix` varchar(50) DEFAULT NULL COMMENT 'Prefix to strip from dialed number',
  `match_pattern` varchar(100) DEFAULT NULL COMMENT 'Pattern to match (e.g., 9XXXXXXX)',
  `caller_id` varchar(50) DEFAULT NULL COMMENT 'CallerID to use for this pattern',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `outbound_routing_id` (`outbound_routing_id`),
  CONSTRAINT `outbound_dial_patterns_ibfk_1` FOREIGN KEY (`outbound_routing_id`) REFERENCES `outbound_routings` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `outbound_dial_patterns`
--

LOCK TABLES `outbound_dial_patterns` WRITE;
/*!40000 ALTER TABLE `outbound_dial_patterns` DISABLE KEYS */;
/*!40000 ALTER TABLE `outbound_dial_patterns` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `outbound_routes`
--

DROP TABLE IF EXISTS `outbound_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `outbound_routes` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `trunk_id` bigint unsigned NOT NULL,
  `dial_pattern` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '.',
  `match_cid` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `prepend_digits` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `outcid` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `priority` int NOT NULL DEFAULT '0',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `description` text COLLATE utf8mb4_unicode_ci,
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
/*!40000 ALTER TABLE `outbound_routes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `outbound_routings`
--

DROP TABLE IF EXISTS `outbound_routings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `outbound_routings` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
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
-- Table structure for table `password_reset_tokens`
--

DROP TABLE IF EXISTS `password_reset_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_reset_tokens` (
  `email` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `token` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `password_reset_tokens`
--

LOCK TABLES `password_reset_tokens` WRITE;
/*!40000 ALTER TABLE `password_reset_tokens` DISABLE KEYS */;
/*!40000 ALTER TABLE `password_reset_tokens` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `personal_access_tokens`
--

DROP TABLE IF EXISTS `personal_access_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `personal_access_tokens` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `tokenable_type` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `tokenable_id` bigint unsigned NOT NULL,
  `name` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `token` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `abilities` text COLLATE utf8mb4_unicode_ci,
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
INSERT INTO `personal_access_tokens` VALUES (1,'App\\Models\\User',2,'api-token','7d407e845c046db541d65dac829e9c35ac79db002f91908c61e9f5a3b6534189','[\"*\"]',NULL,NULL,'2026-01-29 06:25:27','2026-01-29 06:25:27');
INSERT INTO `personal_access_tokens` VALUES (2,'App\\Models\\User',2,'api-token','901c1a676b71acbf1d8f22b9e10da87afd56e458e8901d9c04204cda3835a2b2','[\"*\"]',NULL,NULL,'2026-01-29 06:29:29','2026-01-29 06:29:29');
INSERT INTO `personal_access_tokens` VALUES (3,'App\\Models\\User',1,'api-token','82337c16d87f3ac1bf4e0cee10b87f04cf1e31e8dcbd30f77b0e5ac420e833fb','[\"*\"]',NULL,NULL,'2026-01-29 06:33:02','2026-01-29 06:33:02');
INSERT INTO `personal_access_tokens` VALUES (4,'App\\Models\\User',1,'api-token','7a7711eb764910a7904c596252e698ffbb9e79370da52337b8dca511d0746a6c','[\"*\"]',NULL,NULL,'2026-01-29 10:53:58','2026-01-29 10:53:58');
INSERT INTO `personal_access_tokens` VALUES (5,'App\\Models\\User',1,'api-token','ccb04207d9ce0c310e6e6dcfb11471415c676ebefd7748e977c1f2eb4bdad5db','[\"*\"]',NULL,NULL,'2026-01-29 14:48:33','2026-01-29 14:48:33');
INSERT INTO `personal_access_tokens` VALUES (6,'App\\Models\\User',1,'api-token','530e735aa3170a62fe242edf3feec203981c62c44f02c2cc9ff0d2ce844748d8','[\"*\"]',NULL,NULL,'2026-01-30 15:40:33','2026-01-30 15:40:33');
/*!40000 ALTER TABLE `personal_access_tokens` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `phone_directories`
--

DROP TABLE IF EXISTS `phone_directories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `phone_directories` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `company` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `phones` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `notes` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `phone_directories_chk_1` CHECK (json_valid(`phones`))
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `phone_directories`
--

LOCK TABLES `phone_directories` WRITE;
/*!40000 ALTER TABLE `phone_directories` DISABLE KEYS */;
INSERT INTO `phone_directories` VALUES (1,'John Doe','Acme Corp','[\"021-1234567\", \"0812-1234567\"]','john@acme.com',NULL,1,'2026-02-03 19:33:29','2026-02-03 19:33:29');
INSERT INTO `phone_directories` VALUES (2,'Jane Smith','XYZ Bank','[\"021-7654321\"]','jane@xyz.com',NULL,1,'2026-02-03 19:33:29','2026-02-03 19:33:29');
/*!40000 ALTER TABLE `phone_directories` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `private_wires`
--

DROP TABLE IF EXISTS `private_wires`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `private_wires` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `number` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `destination` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `private_wires`
--

LOCK TABLES `private_wires` WRITE;
/*!40000 ALTER TABLE `private_wires` DISABLE KEYS */;
INSERT INTO `private_wires` VALUES (1,3,'VPW HQ-Branch1','9001','Branch Cimahi',NULL,1,NULL,NULL);
INSERT INTO `private_wires` VALUES (2,3,'VPW HQ-Branch2','9002','Branch Bandung',NULL,1,NULL,NULL);
INSERT INTO `private_wires` VALUES (3,3,'VPW HQ-Branch3','9003','Branch Surabaya',NULL,1,NULL,NULL);
INSERT INTO `private_wires` VALUES (4,3,'VPW Regional-01','9004','Regional West',NULL,1,NULL,NULL);
INSERT INTO `private_wires` VALUES (5,3,'VPW Regional-02','9005','Regional East',NULL,1,NULL,NULL);
/*!40000 ALTER TABLE `private_wires` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `recording_servers`
--

DROP TABLE IF EXISTS `recording_servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `recording_servers` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `ip_address` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `port` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pbx_system_type` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'None',
  `pbx_system_1` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pbx_system_2` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pbx_system_3` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pbx_system_4` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_enabled` tinyint(1) NOT NULL DEFAULT '1',
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
/*!40000 ALTER TABLE `recording_servers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `recordings`
--

DROP TABLE IF EXISTS `recordings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `recordings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `filename` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `recordings`
--

LOCK TABLES `recordings` WRITE;
/*!40000 ALTER TABLE `recordings` DISABLE KEYS */;
/*!40000 ALTER TABLE `recordings` ENABLE KEYS */;
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
-- Table structure for table `sbc_connection_status`
--

DROP TABLE IF EXISTS `sbc_connection_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sbc_connection_status` (
  `id` int NOT NULL AUTO_INCREMENT,
  `sbc_id` int NOT NULL,
  `peer_name` varchar(100) NOT NULL COMMENT 'SIP Trunk/IP Group/Trunk Group name',
  `peer_type` enum('ITSP','IP_GROUP','TRUNK_GROUP','SIP_PEER','GATEWAY') DEFAULT 'SIP_PEER' COMMENT 'Type of SBC peer connection',
  `remote_address` varchar(100) NOT NULL COMMENT 'Remote SIP endpoint address (IP:Port or FQDN)',
  `local_user` varchar(50) DEFAULT NULL COMMENT 'Local SIP username/AOR for registration',
  `registration_status` enum('REGISTERED','NOT_REGISTERED','REGISTERING','FAILED') DEFAULT 'NOT_REGISTERED' COMMENT 'SIP REGISTER status',
  `connection_status` enum('OK','LAGGED','UNREACHABLE','UNKNOWN') DEFAULT 'UNKNOWN' COMMENT 'SIP OPTIONS qualify status',
  `latency_ms` int DEFAULT NULL COMMENT 'Round-trip time from SIP OPTIONS ping (ms)',
  `active_calls` int DEFAULT '0' COMMENT 'Current active calls on this peer',
  `max_calls` int DEFAULT NULL COMMENT 'Maximum concurrent calls allowed',
  `last_activity` datetime DEFAULT NULL COMMENT 'Last successful SIP transaction timestamp',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `sbc_id` (`sbc_id`),
  CONSTRAINT `sbc_connection_status_ibfk_1` FOREIGN KEY (`sbc_id`) REFERENCES `call_servers` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sbc_connection_status`
--

LOCK TABLES `sbc_connection_status` WRITE;
/*!40000 ALTER TABLE `sbc_connection_status` DISABLE KEYS */;
INSERT INTO `sbc_connection_status` VALUES (1,8,'Telkom-ITSP-Primary','ITSP','sip.telkom.net.id:5060','telkom_trunk_01','REGISTERED','OK',18,5,30,'2026-02-04 20:49:00','2026-02-04 13:49:02','2026-02-04 13:49:02');
INSERT INTO `sbc_connection_status` VALUES (2,8,'Indosat-DID-Trunk','ITSP','trunk.indosat.net:5060','indosat_did_main','REGISTERED','LAGGED',165,2,20,'2026-02-04 20:48:27','2026-02-04 13:49:02','2026-02-04 13:49:02');
INSERT INTO `sbc_connection_status` VALUES (3,8,'IPG-CallServer-HQ','IP_GROUP','10.10.1.50:5060',NULL,'NOT_REGISTERED','OK',5,12,100,'2026-02-04 20:49:01','2026-02-04 13:49:02','2026-02-04 13:49:02');
INSERT INTO `sbc_connection_status` VALUES (4,8,'IPG-Branch-Bandung','IP_GROUP','10.10.2.50:5060',NULL,'NOT_REGISTERED','UNREACHABLE',NULL,0,50,'2026-02-04 20:41:02','2026-02-04 13:49:02','2026-02-04 13:49:02');
INSERT INTO `sbc_connection_status` VALUES (5,8,'TG-PSTN-Outbound','TRUNK_GROUP','10.10.1.100:5060',NULL,'NOT_REGISTERED','OK',12,8,60,'2026-02-04 20:48:57','2026-02-04 13:49:02','2026-02-04 13:49:02');
/*!40000 ALTER TABLE `sbc_connection_status` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sbc_routes`
--

LOCK TABLES `sbc_routes` WRITE;
/*!40000 ALTER TABLE `sbc_routes` DISABLE KEYS */;
INSERT INTO `sbc_routes` VALUES (2,8,'S-test','0212222',NULL,0,1,5,NULL,8,'D-test','','700',0,1,4,NULL,NULL,NULL);
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
  `call_server_id` int DEFAULT NULL,
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
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sbcs`
--

LOCK TABLES `sbcs` WRITE;
/*!40000 ALTER TABLE `sbcs` DISABLE KEYS */;
INSERT INTO `sbcs` VALUES (4,8,'ConnectionTelkom','13.44.13.4',5060,'02150877477',2,'udp','from-pstn','ulaw,alaw','auto','none',NULL,NULL,1,60,0,NULL,NULL);
INSERT INTO `sbcs` VALUES (5,8,'ConnectionPBX','13.44.13.26',5060,'02150877477',2,'udp','from-pstn','ulaw,alaw','auto','none',NULL,NULL,1,60,0,NULL,NULL);
/*!40000 ALTER TABLE `sbcs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sessions`
--

DROP TABLE IF EXISTS `sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sessions` (
  `id` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_id` bigint unsigned DEFAULT NULL,
  `ip_address` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `user_agent` text COLLATE utf8mb4_unicode_ci,
  `payload` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `last_activity` int NOT NULL,
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
INSERT INTO `sessions` VALUES ('FhSrGS4Dv4AZvEaIbWrWJobdPnkbn1mOr6MzhMyH',NULL,'127.0.0.1','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36','YTo0OntzOjY6Il90b2tlbiI7czo0MDoiZkFjVHBScGt6V1ozWThvTUpGbkx3YmFXcHAwejV5SkxRMlpJeWZWbiI7czo5OiJfcHJldmlvdXMiO2E6Mjp7czozOiJ1cmwiO3M6Mjc6Imh0dHA6Ly8xMDMuMTU0LjgwLjE3MS9hZG1pbiI7czo1OiJyb3V0ZSI7czozMDoiZmlsYW1lbnQuYWRtaW4ucGFnZXMuZGFzaGJvYXJkIjt9czo2OiJfZmxhc2giO2E6Mjp7czozOiJvbGQiO2E6MDp7fXM6MzoibmV3IjthOjA6e319czozOiJ1cmwiO2E6MTp7czo4OiJpbnRlbmRlZCI7czoyNzoiaHR0cDovLzEwMy4xNTQuODAuMTcxL2FkbWluIjt9fQ==',1769649373);
INSERT INTO `sessions` VALUES ('Kpb5f27VGQmXSFcSL6xQEtlOSl0KQ12IUQrCLIBz',NULL,'104.28.245.127','curl/8.13.0','YTozOntzOjY6Il90b2tlbiI7czo0MDoickVVR2V3UkFQZ1dvbmlJMXA5bVdxa01rZmd4S1BnZ0VYSXZFenNWZSI7czo5OiJfcHJldmlvdXMiO2E6Mjp7czozOiJ1cmwiO3M6NDA6Imh0dHA6Ly8xMDMuMTU0LjgwLjE3MS9TbWFydENNUy9pbmRleC5waHAiO3M6NToicm91dGUiO047fXM6NjoiX2ZsYXNoIjthOjI6e3M6Mzoib2xkIjthOjA6e31zOjM6Im5ldyI7YTowOnt9fX0=',1769646971);
INSERT INTO `sessions` VALUES ('ycWU2N7hkj6NDaAESDLPLETINPkX4NlEpd3wu8bn',NULL,'127.0.0.1','curl/8.13.0','YTozOntzOjY6Il90b2tlbiI7czo0MDoiSGg5dlBDMUtrbVJpRVo2Zm5wdTdKZmVXQU13dVFuakV0UDRkVzlXYSI7czo5OiJfcHJldmlvdXMiO2E6Mjp7czozOiJ1cmwiO3M6MjE6Imh0dHA6Ly8xMDMuMTU0LjgwLjE3MSI7czo1OiJyb3V0ZSI7Tjt9czo2OiJfZmxhc2giO2E6Mjp7czozOiJvbGQiO2E6MDp7fXM6MzoibmV3IjthOjA6e319fQ==',1769649242);
/*!40000 ALTER TABLE `sessions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `static_routes`
--

DROP TABLE IF EXISTS `static_routes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `static_routes` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
  `network` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `subnet` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `gateway` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `device` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `destination` text COLLATE utf8mb4_unicode_ci,
  `interface_name` text COLLATE utf8mb4_unicode_ci,
  `metric` text COLLATE utf8mb4_unicode_ci,
  `device_type` text COLLATE utf8mb4_unicode_ci,
  `device_id` int DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `static_routes_call_server_id_foreign` (`call_server_id`),
  CONSTRAINT `static_routes_call_server_id_foreign` FOREIGN KEY (`call_server_id`) REFERENCES `call_servers` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `static_routes`
--

LOCK TABLES `static_routes` WRITE;
/*!40000 ALTER TABLE `static_routes` DISABLE KEYS */;
INSERT INTO `static_routes` VALUES (1,NULL,'','','192.168.100.1','',NULL,NULL,NULL,'111','eth0','100','call_server',4,1);
INSERT INTO `static_routes` VALUES (2,NULL,'','','192.168.100.1','',NULL,NULL,NULL,'222','eth0','100','sbc',8,1);
/*!40000 ALTER TABLE `static_routes` ENABLE KEYS */;
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
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sub_branches`
--

LOCK TABLES `sub_branches` WRITE;
/*!40000 ALTER TABLE `sub_branches` DISABLE KEYS */;
INSERT INTO `sub_branches` VALUES (1,2,1,4,'KAI Juanda Cimahi','KAI CMH 011','Indonesia','Jawa Barat','Cimahi','Cimahi Tengah','Jl. Juanda Cimahi','','','',1,'2026-01-30 10:05:14','2026-01-30 18:01:35');
INSERT INTO `sub_branches` VALUES (2,2,1,8,'KAI Juanda Cimahi 2','KAI CMH 0112','Indonesia','Jawa Barat','Cimahi','Cimahi Tengah','Jl. Juanda Cimahi','','','',1,'2026-02-04 16:21:23','2026-02-04 16:21:39');
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
  `call_server_id` int DEFAULT NULL,
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
INSERT INTO `trunks` VALUES (1,8,'Garuda','',5060,NULL,2,'udp','from-pstn','ulaw,alaw','auto','none',NULL,NULL,1,60,0,NULL,NULL);
/*!40000 ALTER TABLE `trunks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `turret_group_members`
--

DROP TABLE IF EXISTS `turret_group_members`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `turret_group_members` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `group_id` bigint unsigned NOT NULL,
  `extension` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `group_id` (`group_id`),
  CONSTRAINT `turret_group_members_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `turret_groups` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `turret_group_members`
--

LOCK TABLES `turret_group_members` WRITE;
/*!40000 ALTER TABLE `turret_group_members` DISABLE KEYS */;
/*!40000 ALTER TABLE `turret_group_members` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `turret_groups`
--

DROP TABLE IF EXISTS `turret_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `turret_groups` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `turret_groups`
--

LOCK TABLES `turret_groups` WRITE;
/*!40000 ALTER TABLE `turret_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `turret_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `turret_policies`
--

DROP TABLE IF EXISTS `turret_policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `turret_policies` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `max_channels` int DEFAULT '4',
  `allow_recording` tinyint(1) DEFAULT '1',
  `allow_intercom` tinyint(1) DEFAULT '1',
  `allow_group_talk` tinyint(1) DEFAULT '1',
  `allow_external` tinyint(1) DEFAULT '1',
  `description` text COLLATE utf8mb4_unicode_ci,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `turret_policies`
--

LOCK TABLES `turret_policies` WRITE;
/*!40000 ALTER TABLE `turret_policies` DISABLE KEYS */;
INSERT INTO `turret_policies` VALUES (1,'Standard Trader',4,1,1,1,1,'Default policy for traders',1,'2026-02-03 19:33:29','2026-02-03 19:33:29');
INSERT INTO `turret_policies` VALUES (2,'Senior Trader',8,1,1,1,1,'Extended channels for senior traders',1,'2026-02-03 19:33:29','2026-02-03 19:33:29');
/*!40000 ALTER TABLE `turret_policies` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `turret_templates`
--

DROP TABLE IF EXISTS `turret_templates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `turret_templates` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` text COLLATE utf8mb4_unicode_ci,
  `layout_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `turret_templates_chk_1` CHECK (json_valid(`layout_json`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `turret_templates`
--

LOCK TABLES `turret_templates` WRITE;
/*!40000 ALTER TABLE `turret_templates` DISABLE KEYS */;
/*!40000 ALTER TABLE `turret_templates` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `turret_users`
--

DROP TABLE IF EXISTS `turret_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `turret_users` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Username for turret login',
  `password` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `use_ext` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'Assigned extension number',
  `is_active` tinyint(1) DEFAULT '1',
  `last_login` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `turret_users`
--

LOCK TABLES `turret_users` WRITE;
/*!40000 ALTER TABLE `turret_users` DISABLE KEYS */;
/*!40000 ALTER TABLE `turret_users` ENABLE KEYS */;
UNLOCK TABLES;

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
INSERT INTO `usage_statistics` VALUES (1,'2026-02-04',1,3,'8001',4,5,0,0,0,0,0,0,0,0,1932,43960,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (2,'2026-02-04',1,3,'8002',1,4,0,0,0,0,0,0,0,0,1933,43961,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (3,'2026-02-04',1,3,'8101',0,0,3,10,0,0,0,0,0,0,794,43962,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (4,'2026-02-04',1,3,'8102',0,0,0,2,0,0,0,0,0,0,1935,43963,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (5,'2026-02-04',1,3,'8201',0,0,0,0,7,2,0,0,0,0,1936,43964,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (6,'2026-02-04',1,3,'8202',0,0,0,0,1,0,0,0,0,0,1937,43965,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (7,'2026-02-04',1,3,'8301',0,0,0,0,0,0,3,7,0,0,1938,43966,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (8,'2026-02-04',1,3,'8302',0,0,0,0,0,0,3,5,0,0,1939,43967,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (9,'2026-02-04',1,3,'7001',0,0,0,0,0,0,0,0,32,45,1940,43968,'2026-02-04 07:32:37');
INSERT INTO `usage_statistics` VALUES (10,'2026-02-04',1,3,'7002',0,0,0,0,0,0,0,0,12,6,1941,43969,'2026-02-04 07:32:37');
/*!40000 ALTER TABLE `usage_statistics` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `profile_image` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `role` enum('admin','operator','viewer') COLLATE utf8mb4_unicode_ci DEFAULT 'viewer',
  `is_active` tinyint(1) DEFAULT '1',
  `last_login` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=MyISAM AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'Root Admin','root@smartcms.local','user_1769995349_697ffc551c1b3.jpg','$2y$10$RhxdhOeRRYvGP8hL3mSRPe88nWqN26Xf9Ef1ZPmcmnedaZFdrv6zK','admin',1,'2026-02-05 05:49:41','2026-02-01 15:37:47','2026-02-05 05:49:41');
INSERT INTO `users` VALUES (2,'CMS Admin','cmsadmin@smartx.local',NULL,'$2y$12$cLO6WBNDC4merbNAH2eMWOIwcE5pY4HbyZnTbJhFS0SlRpO9QEj.e','admin',1,'2026-02-01 18:25:18','2026-02-01 15:37:47','2026-02-01 18:25:18');
INSERT INTO `users` VALUES (3,'Operator User','operator@smartx.local',NULL,'\\.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi','operator',1,NULL,'2026-02-01 15:37:47','2026-02-01 15:37:47');
INSERT INTO `users` VALUES (4,'Admin User','admin@smartx.local','user_1770074198_6981305604095.jpg','$2y$12$FFwec5m/ZQ6yo/To8fouXeKYvAlua/JVsJDjPgfuSfT/UfgTyOSgG','admin',1,'2026-02-04 11:26:32','2026-02-01 18:12:14','2026-02-04 11:26:32');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vpws`
--

DROP TABLE IF EXISTS `vpws`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vpws` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `call_server_id` int DEFAULT NULL,
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

-- Dump completed on 2026-02-05 14:36:15
