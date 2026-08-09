# soc_reader_client — client Python de lecture OpenSearch (SOC)

Brique **L6.1 · PFA-27** du projet *Plateforme SOC maison*.

Client Python **en lecture seule** vers OpenSearch. Il expose des méthodes de
haut niveau pour interroger les événements de logs et les alertes de sécurité
indexés dans le SIEM, et renvoie des structures Python normalisées prêtes à
être stockées ou analysées.

C'est une **brique réutilisable** : elle est consommée par le backend, puis par
la console de requêtes (L6.2) et les outils MCP de lecture (L6.3). Elle ne
connaît pas ses consommateurs — elle lit OpenSearch et expose des objets
propres, rien de plus.

---

## Sommaire

1. [Ce que fait le module](#1-ce-que-fait-le-module)
2. [Arborescence](#2-arborescence)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Compte de lecture seule](#5-compte-de-lecture-seule)
6. [Démarrage rapide](#6-démarrage-rapide)
7. [Référence de l'API](#7-référence-de-lapi)
8. [Structures de données](#8-structures-de-données)
9. [Tests](#9-tests)
10. [Intégration par le backend](#10-intégration-par-le-backend)
11. [Correspondance avec le ticket PFA-27](#11-correspondance-avec-le-ticket-pfa-27)
12. [Points à finaliser](#12-points-à-finaliser)

---

## 1. Ce que fait le module

- Se connecte à OpenSearch en **TLS** avec un **compte dédié en lecture seule**.
- Recherche des **événements** de logs (Windows, Linux, réseau — format ECS) par
  période, par hôte, avec filtres additionnels.
- Recherche des **alertes** Wazuh par période, agent, règle, niveau de sévérité.
- Recherche des **findings** des détecteurs Security Analytics par période et par
  détecteur (règles Sigma, sévérité, techniques ATT&CK).
- Recherche des **alertes de détecteur** (déclenchées par les triggers) par
  période, détecteur et état.
- Calcule des **agrégations simples** : top des hôtes, répartition par sévérité.
- **Pagine** de gros volumes de résultats via `search_after` (robuste, sans
  la limite des 10 000 documents de `from`/`size`).
- **Normalise** les résultats OpenSearch en objets Python (`LogEvent`, `Alert`)
  avec une méthode `to_dict()` prête pour l'insertion en base.

Le module **n'expose aucune opération d'écriture ou de suppression**. Le compte
utilisé n'a de toute façon pas ces droits côté cluster.

---

## 2. Arborescence

```
Platforme/
├── soc_reader_client/          # LE MODULE — c'est ce dossier qu'on déploie
│   ├── __init__.py             # exporte SOCReader, OpenSearchConfig, constantes
│   ├── config.py               # configuration via variables d'environnement
│   ├── client.py               # classe SOCReader : connexion + méthodes de requête
│   └── models.py               # dataclasses LogEvent / Alert / Finding / DetectorAlert
├── requirements.txt            # dépendance : opensearch-py
├── .env.example                # modèle de configuration (à copier en .env)
├── .gitignore                  # ignore .env, venv/, __pycache__/
├── README.md                   # ce fichier
├── api_docs.html               # référence API consultable dans le navigateur
├── INTEGRATION_M1.md           # guide d'intégration avec le backend (M1)
└── exemple_integration_m1.py   # script d'exemple pour le backend (M1)
```

> Le cœur livrable est le paquet `soc_reader_client/` : c'est le seul dossier à
> copier chez le consommateur (backend). Les autres fichiers sont la
> documentation et les guides d'intégration.

### Rôle de chaque fichier du paquet

| Fichier       | Responsabilité |
|---------------|----------------|
| `config.py`   | Lit la configuration de connexion depuis l'environnement. Définit les noms d'index. Aucun secret en dur. |
| `client.py`   | Établit la connexion OpenSearch (auth + TLS). Fournit toutes les méthodes de requête, d'agrégation et de pagination. |
| `models.py`   | Convertit les documents OpenSearch bruts en objets `LogEvent` / `Alert`. Point d'alignement avec le schéma PostgreSQL. |
| `__init__.py` | Rend les objets principaux importables directement : `from soc_reader_client import SOCReader`. |

---

## 3. Installation

### Installation locale (développement / tests)

```bash
# créer et activer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# installer les dépendances
pip install -r requirements.txt
```

Dépendance principale : `opensearch-py` (client officiel OpenSearch).

### Déploiement chez un consommateur (backend, MCP)

Le module est une **librairie importée**, pas un service réseau. Pour l'utiliser
depuis un autre projet (le backend sur la VM plateforme, par exemple), il suffit
de **copier le dossier `soc_reader_client/`** là où tourne le code consommateur,
puis d'importer.

```bash
# 1. copier le paquet dans le dépôt du consommateur (VM plateforme)
scp -r soc_reader_client/ soc-platform@10.10.40.20:~/soc-platform/backend/

# 2. installer la dépendance dans l'environnement du consommateur
pip install opensearch-py

# 3. configurer la connexion — OpenSearch est sur SOC01, pas en local
export SOC_OS_HOST=10.10.40.10
export SOC_OS_PORT=9201
export SOC_OS_PASSWORD='...'

# 4. importer et utiliser
python3 -c "from soc_reader_client import SOCReader; print(SOCReader().ping())"
```

| Étape       | Où                              | Quoi |
|-------------|---------------------------------|------|
| 1. copier   | dépôt du backend (SOC-PLATFORM) | déposer `soc_reader_client/` à côté du code backend |
| 2. installer| venv du backend                 | `opensearch-py` |
| 3. configurer | environnement                 | `SOC_OS_HOST=10.10.40.10`, port, mot de passe |
| 4. importer | code backend                    | `from soc_reader_client import SOCReader` |

> **Réseau** : le consommateur sur SOC-PLATFORM (`10.10.40.20`) lit OpenSearch
> sur SOC01 (`10.10.40.10`). Le flux `40.20 → 40.10:9201` doit être ouvert.
>
> **Seul le dossier `soc_reader_client/` est nécessaire** au déploiement. Les
> fichiers `example.py` et `test_soc_reader.py` restent dans le dépôt source mais
> ne sont pas requis chez le consommateur.

---

## 4. Configuration

Toute la configuration passe par des **variables d'environnement**. Aucun
identifiant n'est écrit dans le code.

Copier le modèle et le renseigner :

```bash
cp .env.example .env
chmod 600 .env          # lisible par le seul propriétaire (convention équipe)
```

| Variable          | Rôle                                        | Défaut       | Obligatoire |
|-------------------|---------------------------------------------|--------------|-------------|
| `SOC_OS_HOST`     | hôte OpenSearch                             | `localhost`  | non |
| `SOC_OS_PORT`     | port du cluster SIEM                        | `9201`       | non |
| `SOC_OS_USER`     | compte de lecture seule                     | `soc_reader` | non |
| `SOC_OS_PASSWORD` | mot de passe du compte                      | —            | **oui** |
| `SOC_OS_VERIFY`   | vérifier le certificat TLS                  | `false`      | non |
| `SOC_OS_CA_CERT`  | chemin du bundle CA (si `VERIFY=true`)      | —            | non |

Charger la configuration avant utilisation :

```bash
set -a; source .env; set +a
```

> Le fichier `.env` **ne doit jamais être commité** (il est dans `.gitignore`).
> Sur la VM plateforme, penser à `SOC_OS_HOST=10.10.40.10` (OpenSearch tourne
> sur SOC01, pas en local) et à ouvrir le flux réseau `40.20 -> 40.10:9201`.

---

## 5. Compte de lecture seule

Le module se connecte avec un compte OpenSearch dédié (`soc_reader`) rattaché à
un rôle restreint **en lecture seule** sur les seuls index nécessaires :

```
soc-windows-*                logs Windows (ECS)
soc-linux-waf-vpn-*          logs Linux / WAF / VPN (ECS)
wazuh-alerts-4.x-*           alertes Wazuh
.opensearch-sap-*findings*   findings des détecteurs Security Analytics
```

Ce compte n'a **aucun droit d'écriture** et **pas d'accès à la racine `/`** du
cluster (permission `cluster:monitor/main`). C'est volontaire : application du
principe du moindre privilège. C'est pourquoi la méthode `ping()` interroge un
index autorisé plutôt que la racine, et pourquoi `info()` peut renvoyer un 403
avec ce compte.

---

## 6. Démarrage rapide

```python
from soc_reader_client import SOCReader

reader = SOCReader()                       # configuration lue dans l'environnement

# vérifier la connexion
print(reader.ping())                       # True

# 5 dernières alertes de la dernière heure, typées
for alerte in reader.search_alerts_typed(start="now-1h", size=5):
    print(alerte.agent_name, alerte.rule_level, alerte.rule_description)
```

Démonstration complète de toutes les fonctions :

```bash
set -a; source .env; set +a
python3 example.py
```

### Exemple complet — les 4 sources

```python
from soc_reader_client import SOCReader

reader = SOCReader()

# 1. Événements de logs (Windows / Linux / réseau)
for ev in reader.search_events_typed(start="now-1h", size=2):
    print(ev.host, ev.event_action, ev.destination_ip)
# OPNsense.internal pass 199.232.210.172
# → hôte source | action (pass = paquet autorisé) | IP de destination

# 2. Alertes Wazuh
for al in reader.search_alerts_typed(start="now-1h", size=2):
    print(al.agent_name, al.rule_level, al.rule_description)
# pc-lnx01 3 ClamAV database update
# → agent émetteur | niveau de la règle Wazuh | description

# 3. Findings des détecteurs (règles Sigma)
for f in reader.search_findings_typed(detector_name="Detector-Windows", size=2):
    print(f.detector_name, f.severity, f.rule_names, f.attack_techniques)
# Detector-Windows low ['Potential Data Exfiltration - ...'] ['attack.exfiltration', 'attack.t1041']
# → détecteur | sévérité de la règle | règles Sigma matchées | techniques MITRE ATT&CK

# 4. Alertes de détecteur (triggers)
for a in reader.search_detector_alerts_typed(detector_name="Detector-Windows", size=2):
    print(a.trigger_name, a.severity_label, a.state)
# Trigger 1 critical ACTIVE
# → trigger déclencheur | sévérité lisible | état de l'alerte

# Agrégations
print(reader.top_hosts(start="now-24h", n=3))
# [('pc-ln01', 43745), ('srv-web01', 34579), ('DC01.corp.lab.local', 15064)]
# → liste de (nom_hôte, nombre_d_événements)

print(reader.list_detectors())
# [('Detector-Windows', 43)]
# → liste de (nom_du_détecteur, nombre_de_findings)
```

Chaque objet typé possède une méthode `to_dict()` renvoyant un dictionnaire
prêt à insérer en base (voir section 10 pour l'intégration backend).

---

## 7. Référence de l'API

Toutes les méthodes ci-dessous sont exposées par la classe `SOCReader`.
Les bornes temporelles `start` / `end` acceptent une date ISO 8601
(`"2026-08-09T00:00:00Z"`) ou une expression relative OpenSearch
(`"now-1h"`, `"now-24h"`, `"now-7d"`).

### Connexion

#### `ping() -> bool`
Retourne `True` si le cluster répond, en interrogeant un index autorisé (pas la
racine, hors périmètre du compte restreint).

#### `info() -> dict`
Informations du cluster (version, nom). **Nécessite un accès à la racine `/`** —
peut renvoyer 403 avec le compte de lecture seule. Réservé au diagnostic avec un
compte plus privilégié.

### Recherche d'événements

#### `search_events(start=None, end=None, host=None, index=INDEX_ALL_LOGS, size=100, extra_filters=None) -> list[dict]`
Recherche d'événements de logs, triés du plus récent au plus ancien. Retourne
les documents bruts (`_source`).
- `host` : valeur exacte de `host.name`.
- `extra_filters` : liste de clauses OpenSearch DSL supplémentaires.

```python
reader.search_events(start="now-24h", host="PC-WIN01", size=50)
```

#### `search_events_typed(...) -> list[LogEvent]`
Identique, mais renvoie des objets `LogEvent` (voir section 8). À privilégier
côté backend.

### Recherche d'alertes

#### `search_alerts(start=None, end=None, agent_name=None, rule_id=None, min_level=None, index=INDEX_WAZUH, size=100) -> list[dict]`
Recherche d'alertes Wazuh. Les champs Wazuh sont imbriqués sous `wazuh.*`.
- `agent_name` : filtre sur `wazuh.agent.name` (le vrai agent, pas le collecteur).
- `rule_id` : filtre sur `wazuh.rule.id`.
- `min_level` : niveau minimal (`wazuh.rule.level >= min_level`).

```python
reader.search_alerts(start="now-24h", agent_name="pc-lnx01", min_level=7)
```

#### `search_alerts_typed(...) -> list[Alert]`
Identique, mais renvoie des objets `Alert` (voir section 8).

### Agrégations

#### `top_hosts(start=None, end=None, index=INDEX_ALL_LOGS, field="host.name", n=10) -> list[tuple[str, int]]`
Top N des hôtes par nombre d'événements.

**Retour** : liste de tuples `(nom_hôte, nombre_d_événements)`, du plus actif au
moins actif.

```python
reader.top_hosts(start="now-24h", n=10)
# [('pc-ln01', 43745), ('srv-web01', 34579), ...]
# → l'hôte 'pc-ln01' a généré 43 745 événements sur la période.
```

#### `count_by_severity(start=None, end=None, index=INDEX_WAZUH, field="wazuh.rule.level", n=20) -> list[tuple]`
Répartition des alertes par niveau de sévérité.

**Retour** : liste de tuples `(niveau_de_sévérité, nombre_d_alertes)`. Le niveau
correspond à `wazuh.rule.level` (échelle Wazuh 0–15 ; plus le nombre est élevé,
plus l'alerte est critique).

```python
reader.count_by_severity(start="now-24h")
# [(3, 1284), (5, 210), (7, 44), (10, 3)]
# → 1284 alertes de niveau 3, 210 de niveau 5, 44 de niveau 7, 3 de niveau 10.
```

### Findings des détecteurs

Les findings sont produits par les détecteurs Security Analytics (règles Sigma).
Leur champ temporel est `timestamp` (epoch millisecondes), distinct du
`@timestamp` des logs et alertes.

#### `search_findings(start=None, end=None, detector_name=None, index=INDEX_FINDINGS, size=100) -> list[dict]`
Recherche de findings, triés du plus récent au plus ancien.
- `detector_name` : filtre exact sur `monitor_name` (ex : `"Detector-Windows"`).

```python
reader.search_findings(start="now-7d", detector_name="Detector-Windows")
```

#### `search_findings_typed(...) -> list[Finding]`
Identique, mais renvoie des objets `Finding` (voir section 8).

```python
for f in reader.search_findings_typed(detector_name="Detector-Windows", size=5):
    print(f.severity, f.rule_names, f.attack_techniques)
# low ['Potential Data Exfiltration - ...'] ['attack.exfiltration', 'attack.t1041']
```

#### `list_detectors(index=INDEX_FINDINGS, n=50) -> list[tuple[str, int]]`
Liste les détecteurs présents dans les findings, avec leur nombre. Utile pour
connaître les valeurs de `detector_name` disponibles (des détecteurs supprimés
peuvent laisser des findings orphelins).

**Retour** : liste de tuples `(nom_du_détecteur, nombre_de_findings)`.

```python
reader.list_detectors()
# [('Detector-Windows', 43)]
# → le détecteur 'Detector-Windows' a produit 43 findings.
```

### Alertes de détecteur

Alertes déclenchées par les triggers des détecteurs Security Analytics (index
`.opensearch-sap-*-alerts`). Distinctes des findings : une alerte référence les
findings qui l'ont déclenchée et possède un cycle de vie (`state`). Champ
temporel : `start_time` (epoch millisecondes). Sévérité : chaîne `"1"`–`"5"`
(`"1"` = le plus critique).

#### `search_detector_alerts(start=None, end=None, detector_name=None, state=None, index=INDEX_DETECTOR_ALERTS, size=100) -> list[dict]`
Recherche d'alertes de détecteur, triées par `start_time` décroissant. Par
défaut, interroge les index **courants**. Pour inclure l'historique archivé,
passer `index=INDEX_DETECTOR_ALERTS_ALL`.
- `detector_name` : filtre exact sur `monitor_name`.
- `state` : filtre sur l'état (`ACTIVE`, `ACKNOWLEDGED`, `COMPLETED`, `ERROR`).

```python
reader.search_detector_alerts(detector_name="Detector-Windows", state="ACTIVE")
```

#### `search_detector_alerts_typed(...) -> list[DetectorAlert]`
Identique, mais renvoie des objets `DetectorAlert` (voir section 8).

```python
for a in reader.search_detector_alerts_typed(detector_name="Detector-Windows"):
    print(a.start_time, a.trigger_name, a.severity_label, a.state)
# 2026-08-03T23:54:20 Trigger 1 critical ACTIVE
```

### Pagination

#### `paginate(index, query=None, sort=None, page_size=500, max_docs=None) -> Iterator[dict]`
Générateur qui parcourt **tous** les documents correspondant à la requête, page
par page, via `search_after`. Un champ `_id` est ajouté au tri comme
départage pour garantir la stabilité. `max_docs` borne le nombre total.

```python
for source in reader.paginate(index="wazuh-alerts-4.x-*", max_docs=5000):
    traiter(source)
```

---

## 8. Structures de données

Définies dans `models.py`. Chaque classe fournit `from_os_hit(source)` (mapping
depuis un document OpenSearch) et `to_dict()` (dictionnaire prêt pour la base).

### LogEvent

| Attribut           | Source ECS            |
|--------------------|-----------------------|
| `timestamp`        | `@timestamp`          |
| `host`             | `host.hostname` ou `host.name` |
| `user`             | `user.name`           |
| `source_ip` / `source_port`         | `source.ip` / `source.port` |
| `destination_ip` / `destination_port` | `destination.ip` / `destination.port` |
| `process_name`     | `process.name`        |
| `command_line`     | `process.command_line`|
| `event_action` / `event_category` / `event_module` / `event_outcome` | `event.*` |
| `message`          | `message`             |
| `raw`              | document complet (non sérialisé par `to_dict`) |

### Alert

| Attribut           | Source (priorité `wazuh.*`) |
|--------------------|-----------------------------|
| `timestamp`        | `@timestamp`                |
| `agent_name`       | `wazuh.agent.name`          |
| `agent_ip` / `agent_id` | `wazuh.agent.ip` / `wazuh.agent.id` |
| `rule_id`          | `wazuh.rule.id`             |
| `rule_level`       | `wazuh.rule.level`          |
| `rule_description` | `wazuh.rule.description`    |
| `rule_groups`      | `wazuh.rule.groups`         |
| `location`         | `wazuh.location`            |
| `full_log`         | `wazuh.full_log`            |
| `raw`              | document complet            |

> **Note sur les alertes Wazuh** : le champ `agent.name` à la racine du document
> vaut toujours `soc01` (le collecteur Filebeat). Le véritable agent émetteur est
> sous `wazuh.agent.name`. Le mapping lit en priorité la structure `wazuh.*` et
> retombe sur les champs racine pour les documents antérieurs au parsing JSON du
> pipeline.

Les trois classes d'alertes (`Alert`, `Finding`, `DetectorAlert`) exposent aussi
une méthode **`severite_m1()`** qui convertit leur échelle propre vers l'enum
`Severite` de M1 (`faible`/`moyenne`/`haute`/`critique`). Cette valeur est incluse
dans `to_dict()` sous la clé `severite`.

### Finding

Finding produit par un détecteur Security Analytics (index
`.opensearch-sap-*findings*`). Structure identique pour tous les détecteurs.

| Attribut            | Source                          |
|---------------------|---------------------------------|
| `timestamp`         | `timestamp` (epoch ms) converti en ISO 8601 |
| `timestamp_ms`      | `timestamp` (epoch ms brut)     |
| `finding_id`        | `id`                            |
| `detector_name`     | `monitor_name`                  |
| `detector_id`       | `monitor_id`                    |
| `source_index`      | `index` (où le document a matché) |
| `rule_names`        | `queries[].name` (règles Sigma) |
| `severity`          | extrait des `tags` (`low`/`medium`/`high`/`critical`) |
| `attack_techniques` | tags `attack.*` (techniques ATT&CK) |
| `tags`              | tous les tags des règles        |
| `related_doc_ids`   | `related_doc_ids` (documents déclencheurs) |
| `raw`               | document complet                |

Le mapping est **défensif** : tout champ absent devient `None` (ou `[]`), jamais
d'exception `KeyError`.

### DetectorAlert

Alerte déclenchée par un trigger de détecteur Security Analytics (index
`.opensearch-sap-*-alerts`).

| Attribut          | Source                          |
|-------------------|---------------------------------|
| `start_time`      | `start_time` (epoch ms) → ISO 8601 |
| `start_time_ms`   | `start_time` (epoch ms brut)    |
| `end_time`        | `end_time` → ISO (None si active) |
| `alert_id`        | `id`                            |
| `detector_name`   | `monitor_name`                  |
| `detector_id`     | `monitor_id`                    |
| `trigger_name`    | `trigger_name`                  |
| `severity`        | `severity` (`"1"`–`"5"`, brut)  |
| `severity_label`  | libellé lisible (`critical`…`informational`) |
| `state`           | `state` (`ACTIVE`, `ACKNOWLEDGED`, `COMPLETED`, `ERROR`) |
| `finding_ids`     | `finding_ids` (findings déclencheurs) |
| `related_doc_ids` | `related_doc_ids`               |
| `raw`             | document complet                |

> **Sévérité Security Analytics** : échelle inversée par rapport à Wazuh — `"1"`
> est le plus critique, `"5"` le moins. Le champ `severity_label` fournit le
> libellé lisible.

---

## 9. Tests

Les tests s'exécutent **contre le cluster réel** (pas de mocks), conformément à
la sous-tâche 5 du ticket. Ils se désactivent automatiquement (skip) si
`SOC_OS_PASSWORD` n'est pas défini, pour ne pas échouer en intégration continue.

```bash
set -a; source .env; set +a
pip install pytest
python3 -m pytest -v test_soc_reader.py
```

Résultat attendu : **16 tests passants**. Couverture :

| Test | Vérifie |
|------|---------|
| `test_ping` | connexion via un index autorisé |
| `test_reader_can_query_authorized_index` | lecture effective d'un index autorisé |
| `test_search_events_returns_list` | forme du retour de `search_events` |
| `test_search_events_typed` | objets `LogEvent` bien formés |
| `test_search_alerts_typed` | objets `Alert`, `agent_name` peuplé |
| `test_top_hosts_returns_tuples` | agrégation top hôtes |
| `test_count_by_severity` | agrégation par sévérité |
| `test_paginate_respects_max_docs` | la pagination respecte `max_docs` |
| `test_from_os_hit_defensive` | mapping robuste aux champs absents |
| `test_search_findings_typed` | objets `Finding` bien formés |
| `test_list_detectors` | liste des détecteurs présents |
| `test_findings_empty_detector` | détecteur sans finding → liste vide |
| `test_finding_from_os_hit_defensive` | mapping `Finding` défensif + extraction sévérité/ATT&CK |
| `test_search_detector_alerts_typed` | objets `DetectorAlert` bien formés |
| `test_detector_alerts_filter_by_detector` | filtre par détecteur (`monitor_name.keyword`) |
| `test_detector_alert_from_os_hit_defensive` | mapping `DetectorAlert` + conversion sévérité |

> `pytest` doit être lancé via `python3 -m pytest` pour utiliser le Python du
> venv (et donc trouver `opensearch-py`).

---

## 10. Intégration par le backend

Le module est une **librairie** importée dans le même processus Python que le
backend — il n'y a pas d'API réseau entre les deux. Le backend importe la classe,
appelle ses méthodes de lecture, récupère des objets, puis les écrit lui-même
dans PostgreSQL.

Chaque objet typé expose `to_dict()`, qui renvoie les **valeurs lisibles** (noms,
identifiants métier, sévérité brute) **plus le document OpenSearch complet** sous
la clé `donnees_brutes` (destinée à la colonne JSON de la base).

```python
from soc_reader_client import SOCReader

reader = SOCReader()

for alerte in reader.search_alerts_typed(start="now-5m", min_level=5):
    row = alerte.to_dict()
    # row contient : agent_name, agent_ip, rule_id, rule_description, rule_level,
    #                severite (déjà convertie), donnees_brutes (doc complet), ...
    backend.inserer_alerte(row)   # le backend résout les UUID et insère
```

### Schéma normalisé : la résolution des références se fait côté backend

La base de M1 est **normalisée**. La table `alertes` référence `agents(id)` et
`regles(id)` par **UUID**, et l'API attend un `AlerteCreate` à 4 champs :

```python
class AlerteCreate(BaseModel):
    regle_id: uuid.UUID                    # à résoudre côté backend
    agent_id: uuid.UUID                    # à résoudre côté backend
    severite: Severite                     # faible / moyenne / haute / critique
    donnees_brutes: Optional[dict] = None  # fourni par le client
```

Le client fournit les **valeurs lisibles** (`agent_name`, `agent_ip`, `rule_id`,
`rule_description`) qui permettent au backend de résoudre les UUID dans ses tables
`agents` / `regles`. Le client n'accède pas à PostgreSQL — c'est volontaire
(découplage).

**La sévérité est déjà convertie.** Chaque objet expose `severite_m1()` et inclut
la clé `severite` dans `to_dict()`, dans l'enum de M1
(`faible`/`moyenne`/`haute`/`critique`). Le backend n'a donc pas à la mapper :

| Source | Échelle d'origine | → enum M1 |
|--------|-------------------|-----------|
| `Alert` (Wazuh) | niveau 0–4 / 5–7 / 8–11 / 12–15 | faible / moyenne / haute / critique |
| `Finding` (Sigma) | low / medium / high / critical | faible / moyenne / haute / critique |
| `DetectorAlert` | "4","5" / "3" / "2" / "1" | faible / moyenne / haute / critique |

Le détail complet, source par source, ainsi que les questions ouvertes (findings
sans agent, événements non stockés) sont dans **`INTEGRATION_M1.md`**.

Déploiement : voir la section 3 (« Déploiement chez un consommateur »).

---

## 11. Correspondance avec le ticket PFA-27

| Sous-tâche demandée | Où c'est réalisé | État |
|---------------------|------------------|------|
| Client OpenSearch (auth + TLS) avec compte lecture seule dédié | `config.py`, `client.py`, compte `soc_reader` | fait |
| Recherche d'événements/alertes par période, règle/détecteur, hôte | `search_events`, `search_alerts`, `search_findings`, `search_detector_alerts` (+ variantes typées) | fait |
| Agrégations simples (top hôtes, comptes par sévérité) | `top_hosts`, `count_by_severity` | fait |
| Pagination (`search_after`) + limites de taille | `paginate` (`page_size`, `max_docs`) | fait |
| Mapping des résultats vers structures internes | `models.py` (`LogEvent`, `Alert`, `Finding`, `DetectorAlert`, `to_dict`) | fait (résolution UUID côté M1, voir `INTEGRATION_M1.md`) |
| Confirmer les noms d'index ECS + tests contre l'index réel | `test_soc_reader.py` (16 tests réels) | tests faits ; noms à confirmer M2/M3 |
| Module réutilisable + doc d'usage | paquet `soc_reader_client/` + ce README | fait |

---

## 12. Points à finaliser

- **Intégration schéma PostgreSQL (M1).** La base de M1 est normalisée (table
  `alertes` avec FK UUID vers `agents` / `regles`, enums `severite` /
  `statutalerte`). Le client fournit les valeurs lisibles + `donnees_brutes` ;
  la résolution des UUID et le mapping des enums se font côté backend. Détail de
  la correspondance dans `INTEGRATION_M1.md`. Points ouverts à valider avec M1 :
  la table `alertes` reçoit-elle aussi les findings et alertes de détecteur ?
  les événements de logs sont-ils stockés en base ou restent-ils dans OpenSearch ?
- **Noms d'index (M2/M3).** Confirmer `soc-windows-*`, `soc-linux-waf-vpn-*`,
  `wazuh-alerts-4.x-*`, `.opensearch-sap-*findings*` avec les responsables de
  l'ingestion (L4/L5).
- **Réseau.** Sur la VM plateforme, `SOC_OS_HOST=10.10.40.10` et ouverture du
  flux `40.20 -> 40.10:9201`.
- **Secrets.** Les mots de passe ayant circulé en clair pendant le développement
  doivent être régénérés avant mise en production.
