"""
Exemple d'intégration — persistance des données en base PostgreSQL.

Montre comment le backend consomme la brique de lecture (L6.1) et insère les
alertes dans PostgreSQL. Ce fichier est un GUIDE : les fonctions
`resoudre_agent`, `resoudre_regle` et l'insertion en base sont à implémenter
côté backend (elles ont accès à la base, ce que la brique n'a pas).

Principe :
    - la brique fournit des valeurs LISIBLES (agent_name, rule_id...) + la
      sévérité déjà convertie (clé "severite") + le document brut ("donnees_brutes")
    - le backend résout les UUID (agent_id, regle_id) dans ses tables, puis insère.
"""

from soc_reader_client import SOCReader

# Ces imports viennent du backend de la plateforme (adapter selon l'arborescence) :
# from app.schemas.alertes import AlerteCreate
# from app.crud import inserer_alerte, resoudre_agent, resoudre_regle


def synchroniser_alertes_wazuh() -> None:
    """Lit les alertes Wazuh récentes et les insère en base."""
    reader = SOCReader()

    for alerte in reader.search_alerts_typed(start="now-5m"):
        d = alerte.to_dict()
        # d contient notamment :
        #   agent_name, agent_ip        -> pour résoudre l'agent
        #   rule_id, rule_description   -> pour résoudre la règle
        #   severite                    -> DÉJÀ convertie (faible/moyenne/haute/critique)
        #   donnees_brutes              -> document OpenSearch complet (colonne JSON)

        # --- Étapes à implémenter côté backend (accès base) ---
        # Résoudre les références vers des UUID (créer si absent) :
        agent_id = resoudre_agent(d["agent_name"], d["agent_ip"])       # -> UUID
        regle_id = resoudre_regle(d["rule_id"], d["rule_description"])   # -> UUID

        # Construire l'objet attendu par l'API (Pydantic AlerteCreate) :
        alerte_create = AlerteCreate(
            regle_id=regle_id,                     # UUID de la règle
            agent_id=agent_id,                     # UUID de l'agent
            severite=d["severite"],                # enum plateforme, fourni par la brique
            donnees_brutes=d["donnees_brutes"],    # doc brut, fourni par la brique
        )

        # Insérer en base :
        inserer_alerte(alerte_create)


def synchroniser_findings() -> None:
    """
    Exemple pour les findings de détecteurs.
    NB : le modèle `alertes` exige agent_id/regle_id (NOT NULL). Un finding
    n'a pas toujours d'agent unique — à clarifier (voir INTEGRATION_M1.md).
    """
    reader = SOCReader()
    for finding in reader.search_findings_typed(start="now-1h"):
        d = finding.to_dict()
        # d contient : detector_name, rule_names, severite (convertie),
        #              source_index, attack_techniques, donnees_brutes, ...
        # ... résolution + insertion selon la décision de modélisation retenue
        ...


if __name__ == "__main__":
    # Démonstration : nécessite les fonctions backend (resoudre_*, inserer_*).
    # synchroniser_alertes_wazuh()
    print(
        "Guide d'intégration — implémenter resoudre_agent, resoudre_regle "
        "et inserer_alerte côté backend, puis décommenter."
    )
