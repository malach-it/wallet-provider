# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic # [0.1.22] - 2023-09-21

# [1.0.10] - 2024-01-12
### changed
- modification ecran mobile partage refusé
- 
# [1.0.9] - 2023-12-18
### changed
- nouveaux ecrans 

# [1.0.8] - 2023-12-13
### changed
- corrections,

# [1.0.7] - 2023-12-11
### changed
- corrections,

# [1.0.6] - 2023-12-08
### changed
- FAQ,
- CGU
- texte website 

# [1.0.5] - 2023-11-13
### Added
- state sur code 

# [1.0.4] - 2023-11-09
### Added
- DID sur code 
- 
# [1.0.3] - 2023-11-07
### Added
- log sur code 
- 
# [1.0.2] - 2023-10-24
### Changed
- modif code button

# [1.0.1] - 2023-10-09
### Changed
- inclus iPadOS

# [1.0.0] - 2023-09-28
### Changed
- WEBLINK pour preprod
# [0.1.23] - 2023-09-26
### Changed
- Qrcode pour preprod
- bug fix
# [0.1.22] - 2023-09-21
### Changed
- issuer list
- email message pour 500
- store apple et google

# [0.1.21] - 2023-09-18
### Changed
- mise a jour fichiers Apple/Android
- mise en place app.jeprouvemonage.fr

# [0.1.20] - 2023-09-15
### Changed
- update ecrans
# [0.1.19] - 2023-09-12
### Changed
- update ecrans
- QR code life a 5 minutes
- mise a jour readme.md avec les 2 domaines a creer

# [0.1.18] - 2023-09-8
### Changed
- NGINX proxy_read_timeout = 1200 -> revenir a 300
- si le user refuses de presenter son VC un message lui iest envoyé (page en cours de design)
- si le QRcode est expiré -> message, page en cours de design


# [0.1.17] - 2023-08-18
### Added
- API pour recevoir les avis du wallet

# [0.1.16] - 2023-08-9
### Changed
- Mise à jour des Mentions
- update pieds de page poru ecrans wallet

# [0.1.15] - 2023-08-9
### Changed
- Mise à jour des FAQ, CGU, Mentions


# [0.1.14] - 2023-08-8
### Changed
- Mise à jour des FAQ (Besoin d'aide)
- Mise a jours CGU, Mentions legales et Cookies


# [0.1.13] - 2023-08-6
### Changed
- Nouveau weblink sur https://jeprouvemonage.talao.co/jpma


## [0.1.12] - 2023-07-31
### Added
- liens vers store

### Changed
- Nouveau lien comme weblink à la place de deeplink


## [0.1.11] - 2023-07-26
### Added
- page "Besoin d'aide' partielle

## [0.1.10] - 2023-07-24
### Changed
- Mise à jour de la homepage


## [0.1.9] - 2023-07-19
### Changed
- Mise à jour de la homepage


## [0.1.8] - 2023-07-18
### Added
- links sur la homepage du site preprod.jeprouvemonage.fr  


## [0.1.7] - 2023-07-17
### Added
- page du site jeprouvemonage.fr  
- device detector poue QRcode  
- device detector dans requitements.txt
- landing page du site  


### Changed
- custom schema jpma:// remplace https://jeprouvemonage.fr


## [0.1.6] - 2023-07-12
### Added
- gevent dans gunicornconf.py  


## [0.1.5] - 2023-07-11
### Changed
- Path de  l'issuer OPENID "/api/v1.0" remplace "/sandbox/op"   

### Added
- CHANGELOG.md
- QRcode lisible avec appareil photo   
- Environnement docaposte_preprod et docaposte_prod dans le fichier gunicornconf.py
- error handler sur code 500 avec email healthcheck@jeprouvemonage.fr

### Removed
- Le fichier gunicornconf.py du repo