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

Cette API est une interface de développement uniquement : pas encore
d'authentification, de rate limiting ni de stockage. Elle ne doit pas être
exposée publiquement en l'état.

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

Configurer au moins un réseau (jamais de clé dans Git) :

```powershell
$env:CHAINSHIELD_ETHEREUM_RPC_URL = "https://..."   # Ethereum mainnet
$env:CHAINSHIELD_TRON_RPC_URL = "https://..."       # TRON mainnet
$env:CHAINSHIELD_TRON_API_KEY = "..."               # optionnel
python -m uvicorn app.main:app --reload
```

Documentation interactive : http://127.0.0.1:8000/docs

## Tests

```powershell
python -m pytest
```
