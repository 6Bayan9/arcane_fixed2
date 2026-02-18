-- ============================================================
-- ARCANE Database - arcane_db
-- Updated: Full schema with analysis_type
-- ============================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================
-- TABLE: sectors
-- ============================================================
DROP TABLE IF EXISTS `sectors`;
CREATE TABLE `sectors` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `sectors` VALUES
(1,'Construction'),
(2,'Manufacturing'),
(3,'Oil & Gas'),
(4,'Healthcare'),
(5,'Commerce'),
(6,'Education'),
(7,'Government');

-- ============================================================
-- TABLE: users
-- ============================================================
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `full_name` varchar(100) NOT NULL DEFAULT '',
  `name` varchar(100) NOT NULL DEFAULT '',
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(64) NOT NULL,
  `salt` varchar(64) NOT NULL DEFAULT '',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE: projects
-- ============================================================
DROP TABLE IF EXISTS `projects`;
CREATE TABLE `projects` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `sector_id` int DEFAULT NULL,
  `sector` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `description` text,
  `analysis_type` varchar(50) DEFAULT NULL,
  `dataset_path` varchar(255) DEFAULT NULL,
  `status` varchar(30) DEFAULT 'pending',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `fk_projects_user` (`user_id`),
  KEY `fk_projects_sector` (`sector_id`),
  CONSTRAINT `fk_projects_sector` FOREIGN KEY (`sector_id`) REFERENCES `sectors` (`id`),
  CONSTRAINT `fk_projects_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE: pipeline_results
-- ============================================================
DROP TABLE IF EXISTS `pipeline_results`;
CREATE TABLE `pipeline_results` (
  `id` int NOT NULL AUTO_INCREMENT,
  `project_id` int NOT NULL,
  `rows_count` int DEFAULT 0,
  `cols_count` int DEFAULT 0,
  `missing_before` int DEFAULT 0,
  `missing_after` int DEFAULT 0,
  `duplicates_removed` int DEFAULT 0,
  `model_accuracy` float DEFAULT NULL,
  `model_precision` float DEFAULT NULL,
  `model_recall` float DEFAULT NULL,
  `model_f1` float DEFAULT NULL,
  `model_r2` float DEFAULT NULL,
  `model_mse` float DEFAULT NULL,
  `model_mae` float DEFAULT NULL,
  `chart_labels` text,
  `chart_data` text,
  `chart_column` varchar(100) DEFAULT NULL,
  `target_column` varchar(100) DEFAULT NULL,
  `feature_importance` text,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `fk_results_project` (`project_id`),
  CONSTRAINT `fk_results_project` FOREIGN KEY (`project_id`) REFERENCES `projects` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
