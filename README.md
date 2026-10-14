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
[Authentification](#authentification)). `GET /health`, `/docs` et
`/openapi.json` restent publiques.

Cette API est une interface de développement uniquement : pas encore de rate
limiting ni de stockage. Elle ne doit pas être exposée publiquement en l'état.

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
du rate limiting, une gestion et une rotation des secrets, de la journalisation
et d'autres protections opérationnelles.

## Tests

```powershell
python -m pytest
```
