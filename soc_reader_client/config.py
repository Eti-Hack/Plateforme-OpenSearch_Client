"""
Configuration de connexion au cluster OpenSearch SOC.

Toutes les valeurs sensibles (identifiants) sont lues depuis des variables
d'environnement — jamais codées en dur. Voir le fichier .env.example fourni.

Variables d'environnement attendues :
    SOC_OS_HOST      hôte OpenSearch      (défaut : localhost)
    SOC_OS_PORT      port du cluster SIEM (défaut : 9201)
    SOC_OS_USER      compte lecture seule (défaut : soc_reader)
    SOC_OS_PASSWORD  mot de passe du compte   (OBLIGATOIRE)
    SOC_OS_VERIFY    "true"/"false" — vérifier le certificat TLS (défaut : false)
    SOC_OS_CA_CERT   chemin du bundle CA si SOC_OS_VERIFY=true (optionnel)
"""

import os
from dataclasses import dataclass


def _as_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class OpenSearchConfig:
    """Paramètres de connexion, immuables une fois construits."""

    host: str = "localhost"
    port: int = 9201
    user: str = "soc_reader"
    password: str = ""
    verify_certs: bool = False
    ca_certs: str | None = None

    @classmethod
    def from_env(cls) -> "OpenSearchConfig":
        """Construit la configuration depuis les variables d'environnement."""
        password = os.environ.get("SOC_OS_PASSWORD", "")
        if not password:
            raise RuntimeError(
                "SOC_OS_PASSWORD n'est pas défini. "
                "Exportez-le avant de lancer le client, par exemple :\n"
                "  export SOC_OS_PASSWORD='...'\n"
                "Ne codez jamais le mot de passe en dur dans le source."
            )
        return cls(
            host=os.environ.get("SOC_OS_HOST", "localhost"),
            port=int(os.environ.get("SOC_OS_PORT", "9201")),
            user=os.environ.get("SOC_OS_USER", "soc_reader"),
            password=password,
            verify_certs=_as_bool(os.environ.get("SOC_OS_VERIFY", "false")),
            ca_certs=os.environ.get("SOC_OS_CA_CERT") or None,
        )


# Noms des index ECS produits en L4/L5.
# À FAIRE CONFIRMER avec M2/M3 (sous-tâche 5 du ticket) — valeurs connues à ce jour.
INDEX_WINDOWS = "soc-windows-*"
INDEX_LINUX = "soc-linux-waf-vpn-*"
INDEX_WAZUH = "wazuh-alerts-4.x-*"
INDEX_FINDINGS = ".opensearch-sap-*findings*"

# Alertes déclenchées par les triggers des détecteurs Security Analytics.
# Index COURANTS uniquement (on exclut volontairement les *-history-* et
# *-correlation-* pour ne garder que les alertes vivantes).
INDEX_DETECTOR_ALERTS = ".opensearch-sap-windows-alerts,.opensearch-sap-linux-alerts"

# Variante incluant l'historique archivé (pour analyses long terme).
INDEX_DETECTOR_ALERTS_ALL = ".opensearch-sap-*alerts*"

# Regroupements pratiques
INDEX_ALL_LOGS = f"{INDEX_WINDOWS},{INDEX_LINUX}"
INDEX_ALL_ALERTS = f"{INDEX_WAZUH},{INDEX_FINDINGS}"