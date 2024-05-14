# Projet d'études - Valentin GAGET

Le projet vise à développer une toolbox automatisée pour les tests d'intrusion, simplifiant le processus de réalisation des tests tout en utilisant des techniques avancées d'analyse de vulnérabilités. Cette solution répond à la demande croissante en tests d'intrusion de qualité dans des délais serrés.

## Fonctionnalité

### Découverte de ports, services et vulnérabilités

Scan de ports avec Nmap: Permet de découvrir les ports ouverts sur un hôte ainsi que les services qui y sont associés.
Découverte des services en cours d'exécution avec Nmap: Identifie les services qui tournent sur les ports ouverts.
Recherche de répertoires/fichiers cachés sur un serveur web avec dirb: Explore les répertoires et fichiers cachés sur un serveur web.
Scan de vulnérabilités sur un serveur web avec Nikto: Détecte les vulnérabilités sur un serveur web.

### Analyse de la sécurité des mots de passe et test d'authentification

Analyse de la sécurité des mots de passe avec Hydra: Évalue la robustesse des mots de passe en effectuant des attaques par force brute ou par dictionnaire.
Test d'authentification avec Hydra: Effectue des tests d'authentification en utilisant des combinaisons d'identifiants et de mots de passe.
Tester si votre mots de passe à été compromis en utilisant une api

### Recherche de vulnérabilités

Recherche de vulnérabilités - CVE: Identifie les vulnérabilités connues répertoriées dans la base de données CVE (Common Vulnerabilities and Exposures).

### Exploitation de vulnérabilités

Attaque DDoS: Cette fonctionnalité permet de lancer des attaques de type Déni de Service Distribué (DDoS) contre une cible spécifiée, mettant ainsi ses services hors ligne en saturant ses ressources réseau.
Connexion au backdoor - Reverse Shell: Cette fonctionnalité permet d'exploiter une vulnérabilité pour établir une connexion avec un backdoor sur la cible, donnant ainsi à l'utilisateur un accès distant au système compromis.
(à noter que le programme "remote_shell_serveur.py" devrat être exécuté sur la cible).

### Génération de rapports

Génération de rapports des tests effectués: Génère un rapport détaillé des résultats des tests effectués, y compris les vulnérabilités détectées et les actions prises.

## Installation

Pour télécharger le script :
```bash
git clone https://github.com/Valentin-G44/Projet-Master-1
cd Projet-Master-1
```
Installation des dépendances
```bash
chmod +x setup.sh
./setup.sh
```
Utilisation
```bash
python3 ToolBox_VG.py
```

## Ressources utilisées

- [XXX]()
