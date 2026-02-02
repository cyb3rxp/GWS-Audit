# GWS-Audit

Outil Python d’audit de la configuration de sécurité d’un environnement Google Workspace.

## Fonctionnalités

### Analyse des paramètres de sécurité
- configuration SPF/DKIM/DMARC ;
- administrateurs sans MFA ;
- utilisateurs sans MFA ;
- détection de périphériques dont le disque n'est pas chiffré 
   - NB : l'efficacité de détection dépend du type de périphérique et de son intégration avec GWS.

### Vérification des bonnes pratiques :
- comptes sans numéro de téléphone de récupération ;
- comptes ayant une adresse externe de récupération ;
- transferts automatiques vers d'autres BAL ;
- transferts automatiques avec suppression de l'email ensuite (filtres Gmail) ;
- comptes inactifs ;
- périphériques inactifs ;
- détection de fichiers sensibles par mots-clefs ;
- détection de dossiers/partagés sans ACL ("à tous") ; 
- détection de groupes dans lesquels n'importe qui peut poster ;

## Configuration des audits

- La section RULES permet de paramétrer (activer/désactiver) chaque audit, en spécifiant le booléen (True/False) ;
   - NB : l'audit GDrives peut être très long !
- Certaines variables peuvent être modifiées, telles que les mots-clef à chercher, ou les mots-clef de détection de comptes partagés ;

## Rapport

- Génération automatique de rapports
- 3 formats : JSON, MarkDown, et HTLM

## Prérequis
- [GAM](https://github.com/GAM-team/GAM/wiki/How-to-Install-GAM7)
  - **Attention** : sans GAM, le script ne fonctionnera pas (sauf pour la partie SPF/DKIM/DMARC).
- Python 3.x
- Accès administrateur Google Workspace