# ChainShield

ChainShield est une plateforme **défensive** d'aide à l'évaluation des risques liés aux arnaques crypto.

> ⚠️ ChainShield fournit des indicateurs de risque destinés à assister une analyse humaine.
> Ses résultats ne constituent **jamais** une preuve de fraude.

## État actuel

Squelette initial uniquement :

- application FastAPI minimale ;
- endpoint `GET /health` retournant `{"status": "ok"}` ;
- test pytest associé.

Aucune fonctionnalité d'analyse n'est encore implémentée.

## Périmètre envisagé (non implémenté)

- USDT sur Ethereum et TRON ;
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

## Tests

```powershell
python -m pytest
```
