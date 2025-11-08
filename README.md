# Phishing Feature Extractor

Pipeline Python pour extraire des features (générales, host/content/additional) à partir de JSON d'analyse phishing  
et construire un dataset CSV prêt pour l'entraînement de modèles ML.

---

## Structure du dépôt

- `orchestrator.py` : script principal qui parcourt les dossiers `benign` et `malicious`, appelle chaque extracteur et construit le DataFrame final.  
- `extract_general_features.py` : extraction des features liées à l'URL et au statut HTTP/DNS.  
- `extract_hostinfo_features.py` : extraction des features liées à l'hôte (DNS / SSL / ASN).  
- `extract_contentinfo_features.py` : extraction des features liées au contenu (HTML, screenshot, headers).  
- `extract_additional_features.py` : comparaison `rd` (root domain) vs `sd` (subdomain), wayback, etc.  
- `output/` : dossier généré contenant `phishing_dataset.csv`. 

---

## Prérequis

- Python 3.8+ (recommandé)  
- `pip` (ou utiliser un environnement virtuel)  

---

## Installation (recommandé : virtualenv)

### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux / macOS (bash)
```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Exemple de `requirements.txt` minimal :**
```
pandas
tqdm
numpy
```
---

## Configuration avant exécution

Ouvre `orchestrator.py` et modifie les variables globales en haut du fichier pour indiquer l'emplacement des dossiers contenant tes JSON :

```python
BENIGN_PATH = r"D:\Downloads\benign"       # chemin vers dossiers JSON bénins
MALICIOUS_PATH = r"D:\Downloads\malicious" # chemin vers dossiers JSON malicieux
```

Assure-toi que ces dossiers existent et contiennent des fichiers `.json`.

---

## Format attendu des JSON

- Les fichiers JSON minifiés (tout sur une seule ligne) sont acceptés par `json.load()` — pas besoin de retours à la ligne.  
- Chaque fichier doit être un JSON valide et contenir (idéalement) les clés top-level attendues, par exemple :
```json
{
  "url": "...",
  "host_info": {...},
  "content_info": {...},
  "additional": {...}
}
```
- Le script contient des protections contre certains cas malformés, mais des JSON fortement corrompus peuvent provoquer des erreurs.  

---

## Exécution

Depuis la racine du projet (avec l'environnement virtuel activé) :

```bash
python orchestrator.py
```

Ce que produit le script :
- `output/phishing_dataset.csv` — CSV final contenant toutes les features agrégées.  
- Un aperçu du DataFrame est affiché dans la console (configurable dans `orchestrator.py`).  
---
