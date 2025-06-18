# Gestionnaire de Mots de Passe Sécurisé

## Description

Ce projet est une application Java sécurisée permettant de gérer des mots de passe personnels via une architecture client-serveur basée sur RPC (Remote Procedure Call).  
Les données sensibles sont protégées grâce à un chiffrement **AES-256**, une authentification avec hachage **SHA-256 salé**, et une communication sécurisée via **TLS 1.3**.  
Le projet est conteneurisé avec Docker pour simplifier le déploiement et garantir l'isolation des composants.

---

## Fonctionnalités principales

- Authentification sécurisée des utilisateurs  
- Stockage chiffré des mots de passe (AES-256)  
- Communication client-serveur sécurisée via TLS 1.3  
- Interface graphique simple (JavaFX / Swing)  
- Conteneurisation Docker avec orchestration Docker Compose

---

## Prérequis

- Java JDK 17 ou supérieur  
- Docker & Docker Compose installés  
- OpenSSL (pour générer le keystore SSL)  
- Connexion internet pour télécharger les dépendances

---

## Installation, Déploiement et Structure du projet

### 1. Télécharger les bibliothèques Java

Exécute les commandes suivantes et place les fichiers JAR dans les dossiers `client/` et `server/` :

```bash
curl -O https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar  
curl -O https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.42.0.0/sqlite-jdbc-3.42.0.0.jar
```

### 2. Générer le keystore SSL (PKCS12)

Utilise OpenSSL pour créer le certificat et le keystore. Exécute les commandes suivantes et place le fichier `keystore.p12` dans le dossier `server/` :

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/C=MA/ST=Taroudant/L=Kchachda/O=CyberSecurity/OU=LocalDev/CN=172.16.101.128"

openssl pkcs12 -export -inkey server.key -in server.crt \
  -out keystore.p12 -name server
```

### 3. Construire les images Docker

Depuis la racine du projet, lance la construction des images Docker :

```bash
docker-compose build
```

### 4. Démarrer les services

Pour lancer le serveur et le client, exécute :

```bash
docker-compose up
```

### 5. Arrêter les services

Pour arrêter proprement tous les conteneurs, utilise :

```bash
docker-compose down
```

---

## Structure du projet

```plaintext
password-manager/
├── client/
│   ├── PasswordManagerClient.java
│   ├── Dockerfile.client
│   ├── gson-2.10.1.jar
│   └── sqlite-jdbc-3.42.0.0.jar
├── server/
│   ├── PasswordManagerServer.java
│   ├── Dockerfile.server
│   ├── keystore.p12
│   ├── gson-2.10.1.jar
│   └── sqlite-jdbc-3.42.0.0.jar
├── data/
├── docker-compose.yml
└── README.md
```

---

## Sécurité

- Les mots de passe utilisateurs sont hachés avec SHA-256 et salés avant stockage.  
- Les mots de passe stockés sont chiffrés avec AES-256.  
- Toutes les communications client-serveur sont chiffrées via TLS 1.3.  
- La gestion des sessions est sécurisée et temporaire.

---

## Auteurs

- Nana Diawara
- Hasna Daoui  


