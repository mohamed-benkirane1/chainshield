# ChainShield

ChainShield est une plateforme **défensive** d'aide à l'évaluation des risques liés aux arnaques crypto.

> ⚠️ ChainShield fournit des indicateurs de risque destinés à assister une analyse humaine.
> Ses résultats ne constituent **jamais** une preuve de fraude.

## État actuel

Version publiée : **v0.1.0**. ChainShield **v0.2.0 est en cours de
développement** : l'investigation d'adresse et le graphe de relations USDT
sont disponibles sur `main` mais pas encore publiés (le package reste en 0.1.0).

- `GET /health` ;
- `POST /api/v1/transactions/inspect` : lecture seule d'une transaction Ethereum
  ou TRON (statut, valeur native) et de ses transferts USDT officiels, identifiés
  par l'adresse du contrat (registre vérifié), avec des montants exacts.
- `POST /api/v1/transactions/assess` : même inspection, plus des caractéristiques
  factuelles et le rapprochement avec des signalements d'adresses **fournis par
  le client** (50 au maximum par requête).
- `POST /api/v1/addresses/investigate` (v0.2.0, en développement) : synthèse
  factuelle de l'activité observée d'une adresse dans 1 à 3 transactions
  fournies (voir [Investigation d'adresse](#investigation-dadresse-v020-en-développement)).
- `POST /api/v1/relationships/usdt` (v0.2.0, en développement) : graphe orienté
  des événements `Transfer` USDT officiels observés dans 1 à 3 transactions
  fournies (voir [Graphe de relations USDT](#graphe-de-relations-usdt-v020-en-développement)).

Les signalements ne sont ni vérifiés, ni récupérés, ni enrichis :
`source_reference` n'est jamais consulté. Une correspondance recommande
seulement une revue humaine ; elle ne prouve rien contre l'adresse ni contre
les autres participants. Aucun score n'est calculé, `risk_determination` reste
toujours `indeterminate`, et l'absence de correspondance ne signifie jamais
qu'une transaction est sûre.

Le corps de chaque requête est limité à 256 Kio (262 144 octets, comptés à la
réception) : au-delà, la réponse est `413 request_too_large`, avant tout
traitement. C'est une limite opérationnelle, pas un seuil de risque.

Les routes d'analyse `POST /api/v1/...` exigent un token Bearer (voir
[Authentification](#authentification)) et partagent un quota de 30 unités
par 60 secondes (voir [Limitation de débit](#limitation-de-débit)).
`GET /health`, `/docs` et `/openapi.json` restent publiques et non limitées.

Cette API est une interface de développement uniquement : pas encore de
stockage, et une limitation de débit uniquement locale au processus. Elle ne
doit pas être exposée publiquement en l'état.

## Périmètre envisagé (non implémenté)

- NLP FR / AR / EN ;
- modèles de ML ;
- exploration automatique de graphes blockchain ;
- dashboard analyste.

## Prérequis

- Python 3.11+
- Git

## Installation (Windows, PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Lancer l'API en local

Configurer le token d'API et au moins un réseau (jamais de secret dans Git) :

```powershell
$env:CHAINSHIELD_API_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:CHAINSHIELD_ETHEREUM_RPC_URL = "https://..."   # Ethereum mainnet
$env:CHAINSHIELD_TRON_RPC_URL = "https://..."       # TRON mainnet
$env:CHAINSHIELD_TRON_API_KEY = "..."               # optionnel
python -m uvicorn app.main:app --reload
```

Documentation interactive : http://127.0.0.1:8000/docs

## Authentification

Authentification v1 par **secret partagé**, adaptée à cette phase de
développement : un seul token pour tous les clients, sans comptes
utilisateurs, permissions, expiration ni rotation automatique.

- `CHAINSHIELD_API_TOKEN` : token attendu par le serveur. Au moins 32
  caractères ASCII visibles (ni espace, ni caractère de contrôle). Il n'existe
  aucune valeur par défaut. Générer une valeur locale avec
  `python -c "import secrets; print(secrets.token_urlsafe(32))"` (43 caractères),
  et ne jamais l'écrire dans Git, un ticket ou un log.
- Chaque appel aux routes protégées envoie l'en-tête
  `Authorization: Bearer <token>` (un seul en-tête `Authorization`). Le token
  est comparé à l'identique, en temps constant, sans normalisation.

```powershell
$headers = @{ Authorization = "Bearer $env:CHAINSHIELD_API_TOKEN" }
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/transactions/inspect `
  -Headers $headers -ContentType "application/json" `
  -Body '{"network": "ethereum", "tx_hash": "0x..."}'
```

Réponses :

- `401 unauthorized` (en-tête `WWW-Authenticate: Bearer`) : token absent,
  vide, incorrect, autre schéma que Bearer, en-tête malformé ou dupliqué.
  Le code et le message sont identiques dans tous ces cas.
- `503 auth_not_configured` : `CHAINSHIELD_API_TOKEN` absent ou invalide sur
  le serveur. L'API échoue en mode fermé, sans jamais révéler la configuration.

Une requête de plus de 256 Kio reste rejetée en `413` avant toute
authentification. Un JSON syntaxiquement invalide est rejeté en `422` par
FastAPI avant la vérification du token, sans qu'aucun traitement ne s'exécute.

Dans Swagger (`/docs`), cliquer sur **Authorize**, coller le token (sans le
préfixe `Bearer`), puis appeler les routes protégées.

Une exposition hors d'un poste de développement nécessiterait au minimum HTTPS,
une limitation de débit centralisée, une gestion et une rotation des secrets,
de la journalisation et d'autres protections opérationnelles.

## Limitation de débit

Les routes d'analyse partagent un quota de **30 unités par fenêtre glissante de
60 secondes**, pour limiter les abus et la consommation des ressources RPC.
`POST /api/v1/transactions/inspect` et `POST /api/v1/transactions/assess`
consomment 1 unité par requête ; `POST /api/v1/addresses/investigate` et
`POST /api/v1/relationships/usdt` consomment **1 unité par hash fourni**
(1 à 3), en une seule admission atomique : une requête refusée ne consomme
rien.

- **Quota global** : l'authentification repose sur un seul secret partagé, il
  n'y a donc pas d'identité de client. Le quota est commun à tous les clients
  authentifiés et à toutes les routes d'analyse : alterner les routes ne le
  contourne pas.
- **Fenêtre glissante** : une requête admise à l'instant `t` compte jusqu'à
  `t + 60 s` exactement ; il n'y a pas de remise à zéro à heure fixe.
- **Ordre** : limite de taille du corps (`413`), puis authentification (`401`
  ou `503 auth_not_configured`), puis créneau d'analyse (`503 service_busy`,
  voir [Analyses simultanées](#analyses-simultanées)), puis quota (`429`), puis
  traitement. Les requêtes rejetées avant le quota n'en consomment pas. Une
  admission consommée reste comptée si le traitement échoue ensuite (par
  exemple sur une erreur provider).
- Une requête invalide (JSON mal formé ou non conforme au schéma) est rejetée
  en `422` par FastAPI avant l'authentification et le quota : elle ne consomme
  pas de quota, et aucun traitement métier ni appel provider ne s'exécute.
- **Réponse** au-delà du quota :

  ```http
  HTTP/1.1 429 Too Many Requests
  Retry-After: 42

  {"error": {"code": "rate_limited", "message": "Too many requests. Retry later."}}
  ```

  `Retry-After` donne, en secondes entières (arrondi supérieur, au moins 1),
  le délai avant que la plus ancienne requête admise sorte de la fenêtre. Les
  requêtes refusées ne sont pas comptées et ne prolongent donc pas le blocage.

Limites de cette version :

- le limiteur est **uniquement en mémoire** : il est remis à zéro à chaque
  redémarrage ;
- chaque worker ou processus (par exemple `uvicorn --workers 4`) a son propre
  compteur, et plusieurs instances ne partagent rien : aucune limitation globale
  n'est garantie derrière plusieurs workers ou instances ;
- aucun en-tête IP de proxy (`X-Forwarded-For`, `Forwarded`, etc.) n'est lu ni
  pris en compte, et il n'y a pas de quota par IP ;
- un déploiement distribué nécessite un rate limiter centralisé ou une API
  gateway correctement configurée ;
- le quota ne limite pas à lui seul les requêtes exécutées simultanément : c'est
  le rôle de la limite d'[analyses simultanées](#analyses-simultanées) ;
- l'API n'est toujours pas prête pour une exposition publique sur Internet sans
  protections complémentaires (HTTPS, gateway, supervision, etc.).

## Analyses simultanées

Au plus **8 analyses** (`inspect`, `assess`, `investigate` et `relationships/usdt`
confondues) peuvent être en cours en même temps dans un processus ; une requête
multi-transaction occupe un seul créneau pour toutes ses transactions. Une
requête supplémentaire n'attend pas : elle est refusée immédiatement.

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 1

{"error": {"code": "service_busy", "message": "Analysis capacity is temporarily exhausted."}}
```

- Ce `503 service_busy` est distinct de `auth_not_configured`,
  `provider_not_configured` et `provider_unavailable` ; le `429` du quota est
  inchangé.
- Le créneau est pris après l'authentification et avant le quota : une requête
  refusée pour surcharge ne consomme pas de quota, et une requête non
  authentifiée (`401`) ou trop volumineuse (`413`) ne prend aucun créneau.
- Il est conservé pendant tout le traitement (quota, service, providers, Risk
  Engine, sérialisation de la réponse), puis toujours libéré : succès, erreur
  de validation, erreur provider, exception ou annulation.
- Un JSON syntaxiquement invalide est rejeté en `422` avant toute admission.

Limites :

- protection **par processus uniquement**, en mémoire : aucune limite globale
  entre plusieurs workers (`uvicorn --workers N` autorise `8 × N` analyses) ou
  instances, et aucune protection distribuée ;
- pas de contrôle de concurrence propre à chaque provider (Ethereum, TRON) ni
  au nombre d'appels RPC émis par une analyse ;
- la sûreté des transports HTTP partagés par les providers lors d'appels
  simultanés n'est pas garantie sans audit supplémentaire ;
- ce n'est ni une garantie de disponibilité ni une préparation à une exposition
  sur Internet.

## Investigation d'adresse (v0.2.0, en développement)

`POST /api/v1/addresses/investigate` résume l'activité **observée** d'une
adresse dans un échantillon de 1 à 3 transactions **fournies par l'analyste**,
toutes sur le même réseau. ChainShield n'explore pas automatiquement le
wallet : aucune autre transaction n'est recherchée, et aucune source externe
n'est consultée.

```json
{
  "network": "ethereum",
  "address": "0x...",
  "tx_hashes": ["0x...", "0x..."]
}
```

L'adresse est validée puis normalisée (EIP-55 sur Ethereum, Base58Check sur
TRON). Chaque hash est validé selon le réseau, et les doublons sont détectés
après normalisation. Une entrée invalide est rejetée en `422`, sans aucun appel
RPC ni consommation de quota.

Interprétation de la réponse :

- `sample_scope: "supplied_transactions_only"` : seules les transactions
  fournies ont été inspectées. Ce n'est pas l'historique du wallet.
- Pour chaque transaction : son statut, les rôles observés de l'adresse
  (`transaction_sender`, `transaction_recipient`, `usdt_transfer_sender`,
  `usdt_transfer_recipient`) et ses événements USDT officiels (`incoming`,
  `outgoing` ou `self_transfer`, avec la contrepartie et le montant exact).
- `presence: "not_observed"` signifie seulement que l'adresse n'apparaît pas
  dans les champs inspectés, jamais qu'elle est sans lien ou sûre.
- `usdt_observations: null` (transaction `pending`, `unconfirmed` ou
  `not_found`) signifie **inconnu**, jamais zéro ; `[]` signifie qu'une
  transaction finale ne contient aucun événement USDT impliquant l'adresse.
- `summary.transfer_coverage` vaut `complete`, `partial` ou `none`. Les
  compteurs et les montants `known_*` ne portent que sur les transactions dont
  les événements sont connus. Ils valent `null` quand aucune ne l'est.
- Un self-transfer compte dans les deux directions : il est inclus dans les
  totaux entrants et sortants, et signalé à part (`self_transfer_count`,
  `known_self_transfer_amount_atomic`).
- Les montants sont des sommes exactes d'événements, en chaînes décimales. Ce
  ne sont ni un solde, ni un flux net, ni un volume économique dédupliqué.
  `counterparties` liste les autres parties des événements connus, sans rien
  en déduire sur le contrôle des adresses.
- Aucun score, solde ni verdict n'est produit.

Quota et protections : la route exige le token Bearer, occupe un seul créneau
d'analyse pendant toute l'investigation et consomme **une unité de quota par
hash**, en une seule admission, une fois le corps validé et avant tout appel
provider.

**Fail-fast** : si l'inspection d'une seule transaction échoue (erreur
provider, données incohérentes...), toute l'investigation échoue avec l'erreur
sûre correspondante. Aucun résultat partiel n'est renvoyé, et les transactions
suivantes ne sont pas inspectées.

## Graphe de relations USDT (v0.2.0, en développement)

`POST /api/v1/relationships/usdt` construit un graphe factuel à partir de 1 à
3 transactions Ethereum ou TRON **fournies par l'analyste**. Il réutilise les
inspections et décodeurs existants : aucun historique de wallet n'est exploré,
aucun propriétaire ou contrôle commun n'est inféré, et aucun score, solde,
verdict de fraude ou lien causal entre transactions n'est calculé.

```json
{
  "network": "ethereum",
  "tx_hashes": ["0x...", "0x..."]
}
```

Le réseau et tous les hashes sont validés avant le premier appel RPC. Les
hashes sont normalisés en minuscules et les doublons sont refusés après cette
normalisation. Les champs supplémentaires sont interdits. Une entrée invalide
est rejetée en `422`, sans appel provider ni consommation de quota.

La réponse contient :

- `sample_scope: "supplied_transactions_only"`, qui borne explicitement les
  résultats aux seules transactions fournies ;
- `transactions`, dans l'ordre de la requête, avec le hash, le statut,
  `transfer_data_available` et `usdt_event_count` ;
- `nodes`, les adresses canoniques distinctes qui sont l'émetteur ou le
  destinataire d'au moins un événement connu, triées lexicographiquement ;
- `edges`, les événements individuels dans l'ordre des transactions puis dans
  l'ordre des transferts USDT. Chaque arête orientée `from_address ->
  to_address` conserve `event_id`, le réseau, le hash, `event_position`, le
  vrai `log_index` Ethereum (`null` sur TRON), les deux adresses,
  `amount_atomic` et le contrat USDT officiel ;
- `grouped_relationships`, trié par `from_address` puis `to_address`, qui
  fournit pour chaque couple orienté le nombre d'événements, leur somme exacte
  et les transactions distinctes concernées, dans l'ordre fourni ;
- `known_total_usdt_amount_atomic`, somme exacte des montants des arêtes dont
  les données sont connues.

`event_id` est déterministe :
`<network>:<transaction_hash>:<event_position>`. La position, indexée à partir
de zéro, est celle de l'événement dans la liste ordonnée des transferts USDT de
la transaction. Sur Ethereum, le vrai `log_index` est conservé séparément. Sur
TRON, aucun `log_index` blockchain n'est inventé. Deux événements ayant les
mêmes adresses et le même montant gardent des identifiants et des arêtes
distincts. Un self-transfer reste une boucle `A -> A`.

Les relations sont **orientées** : `A -> B` et `B -> A` ne sont jamais
fusionnées. Aucun netting n'est effectué et les arêtes sous-jacentes restent
présentes pour l'audit. Tous les montants sont des chaînes d'entiers décimaux
exactes dans le JSON, sans `float`; une somme agrégée peut dépasser `uint256`.
Les agrégats décrivent uniquement les événements observés. En particulier, les
événements successifs d'un appel via un routeur ne prouvent pas l'existence de
plusieurs paiements économiques indépendants.

`transfer_coverage` vaut `complete`, `partial` ou `none`. Pour une transaction
`pending`, `unconfirmed` ou `not_found`, le nombre d'événements est `null` :
l'inconnu n'est jamais présenté comme zéro et aucune fausse arête n'est créée.
En couverture partielle, les données connues restent disponibles. Si aucune
transaction n'a de données USDT connues, `nodes`, `edges`,
`grouped_relationships` et le total connu valent `null`. Si toutes les
transactions sont finales et sans événement, la couverture est `complete`,
les trois collections valent `[]` et le total vaut `"0"`.

La route exige le même Bearer token et partage le même limiteur de concurrence
que les autres analyses. Chaque hash coûte une unité du quota partagé ; les 1 à
3 unités sont admises atomiquement avant tout appel provider. L'inspection est
fail-fast : la première erreur interrompt la requête, conserve le code d'erreur
sûr, ne renvoie aucun graphe partiel et n'inspecte pas les hashes suivants.

## Sémantique des statuts et limites blockchain

`transaction.status` décrit ce que le nœud interrogé permet d'établir, rien de
plus :

| Statut | Réseau | Signification |
|---|---|---|
| `success` | Ethereum | Transaction minée avec un reçu indiquant une exécution réussie. Ce n'est **pas** une finalité de consensus : une réorganisation reste théoriquement possible. |
| `success` | TRON | Transaction solidifiée dont l'exécution a réussi. |
| `reverted` | Ethereum, TRON | Échec d'exécution établi par les données accessibles (reçu Ethereum, résultat d'une transaction TRON solidifiée). Aucun transfert USDT n'est alors rapporté. |
| `pending` | Ethereum | Transaction connue du nœud mais pas encore incluse dans un bloc. |
| `unconfirmed` | TRON | Transaction incluse dans un bloc mais pas encore solidifiée : son résultat d'exécution n'est pas rapporté. |
| `not_found` | Ethereum, TRON | Le nœud interrogé ne connaît pas la transaction. Cela ne prouve pas qu'elle n'existe pas. |

- Pour `pending`, `unconfirmed` et `not_found`, `usdt_transfers` vaut `null`
  (inconnu), jamais `[]`.
- Un nœud à historique ou à index de transactions limité peut ne pas retrouver
  certaines transactions anciennes et répondre `not_found`.
- Sur TRON, une transaction pas encore incluse dans un bloc apparaît
  `not_found` plutôt que `pending`.
- Quand le résultat d'exécution n'est pas disponible ou pas établi, ChainShield
  ne le devine pas : il répond par une erreur (`503 receipt_unavailable` si les
  données d'exécution manquent, `502 execution_result_unknown` ou
  `502 provider_malformed_response` si elles sont incomplètes ou incohérentes).
- Le réseau Ethereum est contrôlé (`eth_chainId` doit valoir 1). En revanche,
  ChainShield ne vérifie pas cryptographiquement que l'endpoint TRON configuré
  sert le mainnet : c'est la responsabilité de l'opérateur.
- L'absence de signal de risque ne signifie jamais qu'une transaction est sûre.

## Limites des fournisseurs RPC

- Certains fournisseurs RPC Ethereum, en particulier des endpoints publics
  répartis sur plusieurs nœuds, peuvent ponctuellement renvoyer un reçu
  indisponible pour une transaction minée : la réponse est alors
  `503 receipt_unavailable`, et une nouvelle tentative ultérieure peut réussir.
- TronGrid peut appliquer des restrictions importantes aux requêtes sans clé
  API (réponse `503 provider_unavailable`). Une clé, fournie via
  `CHAINSHIELD_TRON_API_KEY`, est recommandée pour un usage fiable.
- Aucune nouvelle tentative automatique n'est implémentée.
- Chaque opération RPC a un timeout de 10 secondes, mais une analyse enchaîne
  plusieurs opérations (jusqu'à 9 par transaction) : sa durée totale peut donc
  dépasser ce timeout.
- Ces comportements dépendent du fournisseur choisi et peuvent évoluer. Le
  projet n'est pas prêt pour une exposition publique sur Internet.

## Tests

```powershell
python -m pytest
```
