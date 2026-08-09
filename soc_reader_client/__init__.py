"""
Client Python de lecture seule vers OpenSearch pour la plateforme SOC (L6.1).

Expose les objets principaux du module :
    SOCReader        — le client de lecture (connexion + méthodes de requête)
    OpenSearchConfig — la configuration de connexion (via variables d'env)
    LogEvent, Alert, Finding, DetectorAlert — structures de données normalisées

Exemple minimal :
    from soc_reader_client import SOCReader
    reader = SOCReader()
    print(reader.ping())
"""

from .client import SOCReader
from .config import (
    OpenSearchConfig,
    INDEX_WINDOWS,
    INDEX_LINUX,
    INDEX_WAZUH,
    INDEX_FINDINGS,
    INDEX_DETECTOR_ALERTS,
    INDEX_DETECTOR_ALERTS_ALL,
    INDEX_ALL_LOGS,
    INDEX_ALL_ALERTS,
)
from .models import LogEvent, Alert, Finding, DetectorAlert

__all__ = [
    "SOCReader",
    "OpenSearchConfig",
    "LogEvent",
    "Alert",
    "Finding",
    "DetectorAlert",
    "INDEX_WINDOWS",
    "INDEX_LINUX",
    "INDEX_WAZUH",
    "INDEX_FINDINGS",
    "INDEX_DETECTOR_ALERTS",
    "INDEX_DETECTOR_ALERTS_ALL",
    "INDEX_ALL_LOGS",
    "INDEX_ALL_ALERTS",
]

__version__ = "0.3.0"