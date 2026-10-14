# ChainShield

ChainShield est une plateforme **défensive** d'aide à l'évaluation des risques liés aux arnaques crypto.

> ⚠️ ChainShield fournit des indicateurs de risque destinés à assister une analyse humaine.
> Ses résultats ne constituent **jamais** une preuve de fraude.

## État actuel

- `GET /health` ;
- `POST /api/v1/transactions/inspect` : lecture seule d'une transaction Ethereum
  ou TRON (statut, valeur native) et de ses transferts USDT officiels, identifiés
  par l'adresse du contrat (registre vérifié), avec des montants exacts.
- `POST /api/v1/transactions/assess` : même inspection, plus des caractéristiques
  factuelles et le rapprochement avec des signalements d'adresses **fournis par
  le client** (50 au maximum par requête).

Les signalements ne sont ni vérifiés, ni récupérés, ni enrichis :
`source_reference` n'est jamais consulté. Une correspondance recommande
seulement une revue humaine ; elle ne prouve rien contre l'adresse ni contre
les autres participants. Aucun score n'est calculé, `risk_determination` reste
toujours `indeterminate`, et l'absence de correspondance ne signifie jamais
qu'une transaction est sûre.

Le corps de chaque requête est limité à 256 Kio (262 144 octets, comptés à la
réception) : au-delà, la réponse est `413 request_too_large`, avant tout
traitement. C'est une limite opérationnelle, pas un seuil de risque.

Les deux routes `POST /api/v1/transactions/*` exigent un token Bearer (voir
[Authentification](#authentification)) et partagent un quota de 30 requêtes
par 60 secondes (voir [Limitation de débit](#limitation-de-débit)).
`GET /health`, `/docs` et `/openapi.json` restent publiques et non limitées.

Cette API est une interface de développement uniquement : pas encore de
stockage, et une limitation de débit uniquement locale au processus. Elle ne
doit pas être exposée publiquement en l'état.

## Périmètre envisagé (non implémenté)

- NLP FR / AR / EN ;
- modèles de ML ;
- analyse de graphes ;
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

Les routes `POST /api/v1/transactions/inspect` et `POST /api/v1/transactions/assess`
acceptent au plus **30 requêtes par fenêtre glissante de 60 secondes**, pour
limiter les abus et la consommation des ressources RPC.

- **Quota global** : l'authentification repose sur un seul secret partagé, il
  n'y a donc pas d'identité de client. Le quota est commun à tous les clients
  authentifiés et aux deux routes : alterner les routes ne le contourne pas.
- **Fenêtre glissante** : une requête admise à l'instant `t` compte jusqu'à
  `t + 60 s` exactement ; il n'y a pas de remise à zéro à heure fixe.
- **Ordre** : limite de taille du corps (`413`), puis authentification (`401`
  ou `503 auth_not_configured`), puis quota (`429`), puis traitement. Les
  requêtes rejetées avant le quota n'en consomment pas. Une requête admise
  consomme une unité même si elle échoue ensuite (validation `422` d'un JSON
  bien formé, erreur provider, etc.).
- Un JSON syntaxiquement invalide est rejeté en `422` par FastAPI avant
  l'authentification et le quota : il ne consomme pas de quota et n'est pas
  limité, mais aucun traitement métier ni appel provider ne s'exécute.
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
- ce n'est pas une limite du nombre de requêtes exécutées simultanément : jusqu'à
  30 requêtes admises peuvent être en cours en même temps ;
- l'API n'est toujours pas prête pour une exposition publique sur Internet sans
  protections complémentaires (HTTPS, gateway, supervision, etc.).

## Tests

```powershell
python -m pytest
```
