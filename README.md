# Dazibao par inondation non-fiable

## Install

Ce projet utilise [makefile](https://www.gnu.org/software/make/manual/make.html).

L'installation se fait avec la 
[commande `make`](https://www.gnu.org/software/make/manual/make.html) :

```sh
$ make
```

## Lancer le programme

Le serveur se lance en utilisant la cammande :

```sh
$ ./main
```

Le programme converse alors avec le server `2001:660:3301:9200::51c2:1b9b` sur le port `1212`.

## Modifier des valeurs

### A l'aide de la commande

Pour voir l'aide :
```sh
$ ./main -h
```
Afficher les infomations utiles pour le debug :
```sh
$ ./main -d
```
Utilisation de l'ipv4 (ipv6 par défaut)
```sh
$ ./main -4
```
Ajouter un message (par défaut : `seqno = 0`)
```sh
$ ./main -m "message" -s 1024
```
Modifier le server permanent (par défaut : `ip_server = 2001:660:3301:9200::51c2:1b9b`, `port_server = 1212`)
```sh
$ ./main -i "2001:660:3301:9200::51c2:1b9b" -P 1212
```
Modifier votre port d'écoute (par défaut : `port = 3001`)
```sh
$ ./main -p 8000
```

### A l'aide des constantes

`PAQUET_SIZE` : taille maximale d'un paquet

`DATA_SIZE` : taille maximale du body d'un tlv

`VOISINS_SIZE` : taille de la table des voisins

`DONNEES_SIZE` : taille de la table des données

`MAX_VOISINS` : une fois cette valeur dépasée, les voisins ne sont plus ajoutés 

`PARCOURS` : Toutes les X secondes, le nœud parcourt sa table de voisins.

`TMEOUT` : élimination d'un voisin

`MAX_SEND_TLV2` : envoie des TLV2 tant que cette valeur n'est pas atteinte
