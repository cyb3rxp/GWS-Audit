# GWS-Audit

Outil Python d’audit de la configuration de sécurité d’un environnement Google Workspace.
L'outil n'a pas de caractère offensif, et ne contient pas de requête destructrice pour les données ou la configuration : il ne fait que lire et chercher.

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
- comptes ayant une adresse externe de récupération ;
- transferts automatiques vers d'autres BAL ;
- transferts automatiques avec suppression de l'email ensuite (filtres Gmail) ;
- comptes inactifs ;
- périphériques inactifs ;
- détection de groupes dans lesquels n'importe qui peut poster ;
- détection de fichiers sensibles par mots-clefs ;
- détection de dossiers/partagés sans ACL ("à tous").


## Configuration des audits

- La section RULES, en début de script, permet de paramétrer (activer/désactiver) chaque audit, en spécifiant le booléen (True/False) ;
   - NB : l'audit GDrive peut être très long (pour cause d'énumération des fichiers partagés par utilisateur) !
- Certaines variables peuvent être modifiées, telles que les mots-clef "sensibles" à chercher, ou les mots-clef de détection de comptes partagés.

## Rapport

- Génération automatique de rapports
  - NB : par défaut, les rapports et fichiers de données générés sont dans le dossier "output" (qui est paramétrable au début du script)
- 3 formats de rapports générés en standard : JSON, MarkDown, et HTML

## Prérequis
- [GAM](https://github.com/GAM-team/GAM/wiki/How-to-Install-GAM7)
  - **Attention** : sans GAM, le script ne fonctionnera pas (sauf pour la partie SPF/DKIM/DMARC) 
- Python 3.x :
  - les prérequis sont spécifiés ;
- Un compte sur l'environnement GWS avec rôle administrateur.