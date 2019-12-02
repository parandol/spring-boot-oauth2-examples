CREATE TABLE `oauth_refresh_token` (
  `token_id` varchar(256) DEFAULT NULL,
  `token` varchar(4096) DEFAULT NULL,
  `authentication` varchar(4096) DEFAULT NULL,
  `username` varchar(256) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL
);
