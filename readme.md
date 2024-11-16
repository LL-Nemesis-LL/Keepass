# Keepass

Dans le cadre d'un projet scolaire réaliser en C++, il nous est demandé de développer un gestionnaire de mot de passse. On a à notre disposition un code source pour la gestion du chiffrement [AES.cpp](./src/AES.cpp). Sinon pour les tests ou l'ui, c'est à nous de les développés. 

## Besoins

- Une classe qui sera composé de toutes les fonctionnalités d'un gestionnaire de mot de passe
- Une interface utilisateur qui permettra d'intéragir avec le gestionnaire de mot de passe. 
- Une batterie de teste qui s'assurera que notre classe est bien implémentée.

## Fonctionnalités

- Ajout de comptes, noms d'utilisateurs et mots de passes
- Générateur de mots de passes aléatoires
- Suppression de comptes
- Création d'un fichier de sauvegarde
- Chiffrement du fichier de sauvegarde avec AES