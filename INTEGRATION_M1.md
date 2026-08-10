# Persistance en base PostgreSQL — guide d'intégration

Ce document explique comment **un composant qui souhaite écrire les données lues
en base PostgreSQL** (la console de requêtes L6.2, le serveur MCP L6.3, ou un
backend) peut consommer la brique de lecture (L6.1 / PFA-28) et insérer dans le
schéma de la base de données de la plateforme.

> **Important** : la persistance en base n'est **pas** le rôle de la brique. La
> brique lit OpenSearch et renvoie des objets Python ; ses consommateurs directs
> (console, MCP) l'utilisent surtout pour **afficher / exposer** des résultats.
> Ce guide ne concerne que le cas — secondaire — où l'on veut aussi **stocker**
> ces résultats dans PostgreSQL. Il s'appuie sur le schéma réel observé dans
> `soc-agentique/backend` (`models/models.py`, `app/schemas/alertes.py`).

## Principe

La brique est en **lecture seule sur OpenSearch**. Elle ne touche pas PostgreSQL.
Chaque objet typé expose `to_dict()` produisant les **valeurs lisibles** (noms,
identifiants métier, sévérité déjà convertie vers l'enum de la plateforme) plus
le **document
OpenSearch complet** sous la clé `donnees_brutes`.

C'est le **composant écrivain** (console, MCP ou backend) qui insère : il résout
les références (UUID d'agent, de règle) et remplit la table.

## Schéma réel de la base (table `alertes`)

Modèle SQLAlchemy `Alerte` :

| Colonne          | Type                       | Contrainte |
|------------------|----------------------------|------------|
| `id`             | UUID                       | PK, auto (uuid4) |
| `regle_id`       | UUID → `regles.id`         | **NOT NULL**, FK |
| `agent_id`       | UUID → `agents.id`         | **NOT NULL**, FK |
| `timestamp`      | DateTime                   | auto |
| `statut`         | enum `StatutAlerte`        | NOT NULL, défaut `nouvelle` |
| `severite`       | enum `Severite`            | NOT NULL |
| `donnees_brutes` | JSON                       | nullable |

Schéma Pydantic `AlerteCreate` (ce que le backend attend pour créer une alerte) :

```python
class AlerteCreate(BaseModel):
    regle_id: uuid.UUID
    agent_id: uuid.UUID
    severite: Severite                       # faible / moyenne / haute / critique
    donnees_brutes: Optional[dict] = None
```

### Enums de la base

- `Severite` : `faible`, `moyenne`, `haute`, `critique`
- `StatutAlerte` : `nouvelle`, `en_cours`, `cloturee`, `escaladee`

## Correspondance champ par champ (Alerte Wazuh)

Ce que fournit `Alert.to_dict()` → ce que le composant écrivain en fait :

| Champ `AlerteCreate` | Fourni par la brique                 | Traitement côté composant écrivain |
|----------------------|--------------------------------------|----------------------------|
| `regle_id` (UUID)    | `rule_id` (ex `52507`), `rule_description` | résoudre → UUID dans `regles` (créer la règle si absente) |
| `agent_id` (UUID)    | `agent_name` (`pc-lnx01`), `agent_ip` | résoudre → UUID dans `agents` (créer l'agent si absent) |
| `severite` (enum)    | **`severite`** (déjà converti : `faible`…`critique`) | insertion directe |
| `donnees_brutes`     | **`donnees_brutes`** (doc OpenSearch complet) | insertion directe (JSON) |

> La brique **convertit déjà la sévérité** vers l'enum de la base via `severite_m1()`
> (exposé sous la clé `severite` de `to_dict()`). Il ne reste que les **UUID** à
> résoudre.

Table de conversion appliquée par la brique :

| Source                | Valeur              | → enum base|
|-----------------------|---------------------|------------|
| Wazuh `rule.level`    | 0–4                 | `faible`   |
|                       | 5–7                 | `moyenne`  |
|                       | 8–11                | `haute`    |
|                       | 12–15               | `critique` |
| Finding Sigma         | informational / low | `faible`   |
|                       | medium              | `moyenne`  |
|                       | high                | `haute`    |
|                       | critical            | `critique` |
| Alerte détecteur      | "1"                 | `critique` |
|                       | "2"                 | `haute`    |
|                       | "3"                 | `moyenne`  |
|                       | "4" / "5"           | `faible`   |

## Points ouverts à clarifier (si persistance retenue)

1. **Le modèle `Alerte` est conçu pour Wazuh/Sigma, pas pour les 4 sources.**
   La table n'a qu'une entrée par alerte avec `regle_id` + `agent_id`
   **obligatoires**. Or :
   - un **finding** référence un `source_index` et des `related_doc_ids`, pas un
     agent unique clairement identifié ;
   - une **alerte de détecteur** référence des `finding_ids` et un trigger.

   → **Comment stocker findings et alertes de détecteur ?** Même table
   `alertes` (avec quel `agent_id` / `regle_id` ?) ou tables dédiées ?

2. **`regle_id` et `agent_id` sont NOT NULL.** Si une source n'a pas d'agent ou
   de règle identifiable côté base, l'insert échouera. À définir : valeur par
   défaut, agent « inconnu », ou rendre nullable ?

3. **Événements de logs** : aucune table `events` n'existe. `LogEvent` sert donc
   la console de requêtes (L6.2), pas l'insertion en base. À confirmer.

## Ce qui est prêt côté client

- Les 4 `to_dict()` incluent `donnees_brutes` (document OpenSearch complet).
- Les 3 sources d'alertes exposent `severite` déjà convertie vers l'enum de la base.
- Toutes les valeurs lisibles nécessaires à la résolution des UUID sont fournies
  (`agent_name`, `agent_ip`, `rule_id`, `rule_description`).
- Le mapping est défensif (champs absents → `None`).

## Script d'intégration (guide de démarrage)

Exemple concret côté backend. Les fonctions `resoudre_agent`, `resoudre_regle`
et `inserer_alerte` sont à implémenter par le composant écrivain (elles accèdent
à la base ; la
brique, elle, ne fait que lire OpenSearch). Voir aussi
`exemple_integration_m1.py`.

```python
from soc_reader_client import SOCReader
# from app.schemas.alertes import AlerteCreate   # schéma de la plateforme

reader = SOCReader()

for alerte in reader.search_alerts_typed(start="now-5m"):
    d = alerte.to_dict()
    # d fournit : agent_name, agent_ip, rule_id, rule_description,
    #             severite (DÉJÀ convertie), donnees_brutes (doc complet)

    # --- côté backend (accès base) : résoudre les références en UUID ---
    agent_id = resoudre_agent(d["agent_name"], d["agent_ip"])      # -> UUID
    regle_id = resoudre_regle(d["rule_id"], d["rule_description"]) # -> UUID

    alerte_create = AlerteCreate(
        regle_id=regle_id,                    # UUID de la règle (PAS agent_id !)
        agent_id=agent_id,                    # UUID de l'agent
        severite=d["severite"],               # enum plateforme, fourni par la brique
        donnees_brutes=d["donnees_brutes"],   # doc brut, fourni par la brique
    )
    inserer_alerte(alerte_create)             # insertion en base
```

> Deux pièges évités ici : `regle_id` reçoit bien `regle_id` (et non `agent_id`),
> et la sévérité n'est **pas** re-mappée — la brique fournit déjà `d["severite"]`
> dans l'enum de la base.
