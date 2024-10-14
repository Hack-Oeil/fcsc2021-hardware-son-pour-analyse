# FCSC 2021 Son Pour Analyse

Un équipement embarqué, une tablette, comporte un système d'échanges sécurisés avec un serveur de données.

Pour authentifier les données envoyées par cette tablette, une signature est apposée sur 
chacun des fichiers envoyés. La signature est calculée de la manière suivante :

```
RSA-CRT(SHA256(fichier))
```

qui par exemple, peut être implémentée en Python de la manière suivante :
```python
import hashlib
f = open('public/ANSSI_ref.png','rb')
raw = bytearray(f.read())
m = hashlib.sha256(raw).digest()
m = int.from_bytes(m, byteorder='big', signed=False)
signature = pow_crt(m, d, p, q)
print(f"{signature.hex()}")
```

Ainsi la signature de l'image ANSSI_ref.png de référence est égale à
```
39eb497f830a302f41818784cf83bff1d245e2a2d5e1dc04996d57443bcc4a5fde3650ad11a70267fd4c34d922c47633d2decb21d30d42215766485acf6399d1f9639419d2104376070045b8401470e56fc3b21cc4b2e5d6443cb1beef4815db6725cf0226d49d8e17199c6075dd78f393e265ad350ac79c5be18fc6c9981de1
```
qui se vérifiera facilement grâce à clé publique RSA:
```
e = 65537
n = 114181065031786564590139505995090932681603488058093695383755920020714540043378009781380110655253006728353171921382633045444731450267353184468441566668432893992049978192406103162591416659000523363797206479008373775089128981682147631692898693610665109453356689955829711356078688003770094519986009441791800904261
```
Un de nos apprentis en canaux auxillaires nous a remonté un phénomène étrange concernant l'implémentation du RSA-CRT sur cette tablette : malgré la mise en place d'une contre-mesure classique pour éviter les attaques par les canaux auxilliares temporels et celui lié à la consommation de courant, il semblerait que des informations sensibles fuitent dans le spectre audible ! La contre-mesure utilisée est la méthode de Montgomery, elle consiste en l'utilisation d'une exponentiation modulaire ne faisant pas apparaitre de différence de calcul entre les différents bits des exposants secrets dp et dq de RSA.

```python
def montgomery(a, e, n):
    exp = map(int, f"{e:b}")
    out = [1, a]
    for i in exp:
        out[1 - i] = (out[0] * out[1]) % n
        out[i] = (out[i] ** 2) % n
    return out[0]
```
Cependant, cet apprenti, qui est aussi oreille d'or, s'est aperçu d'une différence sonore. Pour cela, il a ralenti au minimum la vitesse de calcul de la tablette et enregistré les sons émis par la tablette lors d'une signature cryptographique. Réussirez-vous, comme lui, à retrouver les secrets RSA en utilisant cet enregistrement ?

Prouvez-le en calculant le SHA256 de la signature du fichier audio contenant l'enregistrement que vous venez d'analyser. Le flag pourra être calculé ainsi :

```python
import hashlib
f = open('public/RSA.wav', 'rb')
raw = bytearray(f.read())
m = hashlib.sha256(raw).digest()
m = int.from_bytes(m, byteorder = 'big', signed = False)
sig = pow(m, d, n)
flag = hashlib.sha256(sig.to_bytes(128, byteorder = "big")).digest()
print(f"FCSC{{{flag.hex()}}}")
```

Fichiers :
- [ANSSI_ref.png](ANSSI_ref.png)
- [RSA.wav](RSA.wav)



Auteur : Guena

Origine : [SmeaLog](https://hackropole.fr/fr/challenges/hardware/fcsc2021-hardware-son-pour-analyse/)

-----------

## Installation manuel
Vous n'utilisez pas l'application **les CTFs de Cyrhades** ? C'est dommage !
Mais voici comment installer ce CTF manuellement :

> git clone https://github.com/Hack-Oeil/fcsc2021-hardware-son-pour-analyse.git

> cd fcsc2021-hardware-son-pour-analyse


-----------

## Sur le site officiel hackropole.fr
> https://hackropole.fr/fr/challenges/hardware/fcsc2021-hardware-son-pour-analyse/