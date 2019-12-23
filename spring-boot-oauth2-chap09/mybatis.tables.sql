CREATE TABLE `user` (
  `username` varchar(256) NOT NULL,
  `name` varchar(256) NOT NULL,
  `icon` varchar(1024) DEFAULT NULL,
  `access_token` varchar(4096) DEFAULT NULL,
  `refresh_token` varchar(4096) DEFAULT NULL,
  PRIMARY KEY (`username`)
);
