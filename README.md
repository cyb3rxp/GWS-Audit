# Présentation

<img width="580" height="414" alt="image" src="https://github.com/user-attachments/assets/7d62dba6-d716-44d7-a56d-9d81ec41b8eb" />


GWS Audit est un outil écrit en Python pour l'audit de la configuration de sécurité d’un environnement Google Workspace.
Il n'a pas de caractère offensif, et ne contient pas de requête destructrice pour les données ou la configuration : il ne fait que lire et chercher.

**Important** : il est néanmoins impératif d'avoir un accord écrit préalable de la part de l'entité qui possède le GWS.


## Fonctionnalités

### Analyse des paramètres de sécurité
- configuration SPF/DKIM/DMARC ;
- administrateurs sans MFA ;
- utilisateurs sans MFA ;
- périphériques dont le disque n'est pas chiffré :
   - NB : l'efficacité de détection dépend du type de périphérique et de son intégration avec GWS.

### Vérification des bonnes pratiques :
- comptes sans numéro de téléphone de récupération ;
- comptes ayant une adresse email externe de récupération ;
- transferts automatiques vers d'autres BAL ;
- transferts automatiques avec suppression de l'email ensuite (filtres Gmail) ;
- comptes inactifs ;
- périphériques inactifs ;
- détection de groupes dans lesquels n'importe qui peut poster ;
- détection de fichiers sensibles par mots-clefs (NB : recherche dans leur nom/chemin uniquement, pas dans leur contenu) ;
- détection de dossiers/partagés sans ACL ("à tous").


## Configuration des audits

- La section RULES, en début de script, permet de paramétrer (activer/désactiver) chaque audit, en spécifiant le booléen (True/False) ;
   - voici la configuration par défaut (tout activé sauf l'audit GDrive) :
<img width="1671" height="941" alt="image" src="https://github.com/user-attachments/assets/f849eb38-0702-4567-92e0-3b1c6c213cb1" />

   
   - NB : l'audit GDrive peut être très long (pour cause d'énumération des fichiers partagés par utilisateur) !
- Certaines variables peuvent être modifiées, telles que les mots-clef "sensibles" à chercher, ou les mots-clef de détection de comptes partagés.

## Rapport

- L'outil embarque une génération automatique de rapports
  - NB : par défaut, les rapports et fichiers de données générés sont dans le dossier "output" (qui est paramétrable au début du script)
- 3 formats de rapports générés en standard : JSON, MarkDown, et HTML


# Usage

## Prérequis

- [GAM](https://github.com/GAM-team/GAM/wiki/How-to-Install-GAM7) :
  - **Attention** : sans GAM, le script ne fonctionnera pas (sauf pour la partie SPF/DKIM/DMARC)
  - GAM doit être installé et paramétré correctement par rapport au GWS à auditer.
- Python 3.8+ :
  - les prérequis sont spécifiés dans le fichier "requirements.txt" ;
- Un compte sur l'environnement GWS avec rôle administrateur.


## Lancement de l'outil

Dans un terminal (Windows CMD) :
``` python.exe .\gws_audit.py ``` 

NB : ne pas oublier d'enlever la sécurité du script (cf. code source)


# Pour aller plus loin


* Solution complémentaire : [AdminPulse for Workspace](https://github.com/doitintl/DoiT-AdminPulse-for-Workspace?tab=readme-ov-file)
   * NB : attention, c'est tout en anglais... et en clicodrôme sous Excel (_via_ une extension) ! 
