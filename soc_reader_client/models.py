"""
Structures internes normalisées pour la plateforme SOC.

Ces dataclasses représentent un événement de log (LogEvent) et une alerte
(Alert) sous une forme neutre, indépendante d'OpenSearch. Le backend (M1)
consomme ces objets et les écrit dans PostgreSQL.

Chaque classe fournit :
    - from_os_hit(source) : construit l'objet depuis le _source d'un document
      OpenSearch, de façon DÉFENSIVE (champs imbriqués/absents gérés via .get()).
    - to_dict()           : produit un dictionnaire prêt à insérer en base.

⚠️ ALIGNEMENT SCHÉMA POSTGRESQL (M1 / PFA-27) :
   Les noms des attributs ci-dessous sont provisoires. Quand M1 fournira le
   schéma exact de ses tables (colonnes des tables events et alerts), il
   suffira d'ajuster :
     - les noms d'attributs des dataclasses, OU
     - les clés retournées par to_dict()  (recommandé : ne toucher que to_dict)
   pour qu'ils correspondent exactement aux colonnes SQL. Voir les TODO.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _get(source: dict[str, Any], *path: str, default: Any = None) -> Any:
    """
    Accès défensif à un champ imbriqué.
    _get(src, "wazuh", "rule", "level") équivaut à
    src["wazuh"]["rule"]["level"] mais retourne default si un maillon manque.
    """
    current: Any = source
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


# ---------------------------------------------------------------------- #
# Conversion de sévérité vers l'enum PostgreSQL de M1
# ---------------------------------------------------------------------- #
# La table `alertes` de M1 utilise un enum `severite` en français :
#   faible / moyenne / haute / critique
# Les sources n'utilisent pas la même échelle :
#   - Wazuh          : niveau numérique 0-15 (croissant)
#   - Findings Sigma : informational / low / medium / high / critical
#   - Alertes dét.   : "1".."5" ("1" = le plus critique)
# Les helpers ci-dessous convertissent chaque échelle vers l'enum M1.

# Valeurs de l'enum Severite de M1
SEVERITE_FAIBLE = "faible"
SEVERITE_MOYENNE = "moyenne"
SEVERITE_HAUTE = "haute"
SEVERITE_CRITIQUE = "critique"


def wazuh_level_to_severite_m1(level: int | None) -> str | None:
    """Niveau Wazuh (0-15) -> enum severite de M1."""
    if level is None:
        return None
    if level <= 4:
        return SEVERITE_FAIBLE
    if level <= 7:
        return SEVERITE_MOYENNE
    if level <= 11:
        return SEVERITE_HAUTE
    return SEVERITE_CRITIQUE


def sigma_severity_to_severite_m1(severity: str | None) -> str | None:
    """Sévérité Sigma (low/medium/high/critical) -> enum severite de M1."""
    if not severity:
        return None
    mapping = {
        "informational": SEVERITE_FAIBLE,
        "low": SEVERITE_FAIBLE,
        "medium": SEVERITE_MOYENNE,
        "high": SEVERITE_HAUTE,
        "critical": SEVERITE_CRITIQUE,
    }
    return mapping.get(severity.lower())


def sap_severity_to_severite_m1(severity: str | None) -> str | None:
    """Sévérité alerte détecteur ("1".."5", 1=critique) -> enum severite de M1."""
    if not severity:
        return None
    mapping = {
        "1": SEVERITE_CRITIQUE,
        "2": SEVERITE_HAUTE,
        "3": SEVERITE_MOYENNE,
        "4": SEVERITE_FAIBLE,
        "5": SEVERITE_FAIBLE,
    }
    return mapping.get(str(severity))


# ---------------------------------------------------------------------- #
# Événement de log (Windows / Linux / réseau — format ECS)
# ---------------------------------------------------------------------- #

@dataclass
class LogEvent:
    """Événement de log normalisé (issu des index soc-windows-* / soc-linux-*)."""

    timestamp: str | None = None          # @timestamp
    host: str | None = None               # host.hostname ou host.name
    user: str | None = None               # user.name
    source_ip: str | None = None          # source.ip
    source_port: int | None = None        # source.port
    destination_ip: str | None = None     # destination.ip
    destination_port: int | None = None   # destination.port
    process_name: str | None = None       # process.name
    command_line: str | None = None       # process.command_line
    event_action: str | None = None       # event.action
    event_category: str | None = None     # event.category
    event_module: str | None = None       # event.module
    event_outcome: str | None = None      # event.outcome
    message: str | None = None            # message
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_os_hit(cls, source: dict[str, Any]) -> "LogEvent":
        """Construit un LogEvent depuis le _source d'un document OpenSearch."""
        # host peut être host.hostname (réseau/Linux) ou host.name (Windows)
        host = _get(source, "host", "hostname") or _get(source, "host", "name")

        return cls(
            timestamp=_get(source, "@timestamp"),
            host=host,
            user=_get(source, "user", "name"),
            source_ip=_get(source, "source", "ip"),
            source_port=_to_int(_get(source, "source", "port")),
            destination_ip=_get(source, "destination", "ip"),
            destination_port=_to_int(_get(source, "destination", "port")),
            process_name=_get(source, "process", "name"),
            command_line=_get(source, "process", "command_line"),
            event_action=_get(source, "event", "action"),
            event_category=_get(source, "event", "category"),
            event_module=_get(source, "event", "module"),
            event_outcome=_get(source, "event", "outcome"),
            message=_get(source, "message"),
            raw=source,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Dictionnaire prêt pour insertion en base.
        TODO(M1) : renommer les clés pour coller aux colonnes de la table events.
        """
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "user": self.user,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "event_action": self.event_action,
            "event_category": self.event_category,
            "event_module": self.event_module,
            "event_outcome": self.event_outcome,
            "message": self.message,
            "donnees_brutes": self.raw,  # document OpenSearch complet (colonne JSON M1)
        }


# ---------------------------------------------------------------------- #
# Alerte Wazuh
# ---------------------------------------------------------------------- #

@dataclass
class Alert:
    """
    Alerte de sécurité normalisée (issue des index wazuh-alerts-4.x-*).

    IMPORTANT : les vrais champs Wazuh sont sous "wazuh.*" (le champ agent.name
    racine vaut "soc01", le collecteur Filebeat, PAS le véritable agent).
    On lit donc en priorité wazuh.agent.name, wazuh.rule.*, etc.
    Les anciens documents (avant le fix de pipeline) n'ont pas la structure
    "wazuh.*" — le mapping retombe alors sur les champs racine quand ils existent.
    """

    timestamp: str | None = None          # @timestamp
    agent_name: str | None = None         # wazuh.agent.name
    agent_ip: str | None = None           # wazuh.agent.ip
    agent_id: str | None = None           # wazuh.agent.id
    rule_id: str | None = None            # wazuh.rule.id
    rule_level: int | None = None         # wazuh.rule.level
    rule_description: str | None = None   # wazuh.rule.description
    rule_groups: list[str] = field(default_factory=list)  # wazuh.rule.groups
    location: str | None = None           # wazuh.location
    full_log: str | None = None           # wazuh.full_log
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_os_hit(cls, source: dict[str, Any]) -> "Alert":
        """Construit un Alert depuis le _source d'un document OpenSearch."""
        # Nouvelle structure (wazuh.*) en priorité, repli sur racine sinon.
        agent_name = (
            _get(source, "wazuh", "agent", "name")
            or _get(source, "agent", "name")
        )
        rule_level = _to_int(
            _get(source, "wazuh", "rule", "level")
            if _get(source, "wazuh", "rule", "level") is not None
            else _get(source, "rule", "level")
        )

        return cls(
            timestamp=_get(source, "@timestamp"),
            agent_name=agent_name,
            agent_ip=_get(source, "wazuh", "agent", "ip"),
            agent_id=_get(source, "wazuh", "agent", "id"),
            rule_id=_get(source, "wazuh", "rule", "id")
            or _get(source, "rule", "id"),
            rule_level=rule_level,
            rule_description=_get(source, "wazuh", "rule", "description")
            or _get(source, "rule", "description"),
            rule_groups=_get(source, "wazuh", "rule", "groups", default=[]) or [],
            location=_get(source, "wazuh", "location"),
            full_log=_get(source, "wazuh", "full_log"),
            raw=source,
        )

    def severite_m1(self) -> str | None:
        """Sévérité convertie vers l'enum `severite` de M1 (faible/moyenne/haute/critique)."""
        return wazuh_level_to_severite_m1(self.rule_level)

    def to_dict(self) -> dict[str, Any]:
        """
        Dictionnaire prêt pour insertion en base.
        Les clés lisibles servent au backend M1 pour résoudre les UUID
        (agent_id, regle_id) ; `severite` est déjà convertie vers son enum ;
        `donnees_brutes` alimente directement la colonne JSON.
        """
        return {
            "timestamp": self.timestamp,
            "agent_name": self.agent_name,
            "agent_ip": self.agent_ip,
            "agent_id": self.agent_id,
            "rule_id": self.rule_id,
            "rule_level": self.rule_level,
            "rule_description": self.rule_description,
            "rule_groups": self.rule_groups,
            "location": self.location,
            "full_log": self.full_log,
            "severite": self.severite_m1(),  # enum M1 (faible/moyenne/haute/critique)
            "donnees_brutes": self.raw,  # document OpenSearch complet (colonne JSON M1)
        }


# ---------------------------------------------------------------------- #
# Helper de conversion
# ---------------------------------------------------------------------- #

def _to_int(value: Any) -> int | None:
    """Convertit en int si possible (les ports ECS arrivent parfois en str)."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------- #
# Finding Security Analytics (détecteurs Sigma)
# ---------------------------------------------------------------------- #

# Niveaux de sévérité connus dans les tags Sigma (pour les distinguer des
# autres tags comme "windows" ou "attack.*").
_SEVERITIES = {"informational", "low", "medium", "high", "critical"}


@dataclass
class Finding:
    """
    Finding produit par un détecteur Security Analytics (index
    .opensearch-sap-*findings*).

    Un finding est une correspondance règle Sigma -> document source : il
    indique quel détecteur a matché, quelle(s) règle(s), sur quel index, et
    référence le(s) document(s) déclencheur(s). Sa structure est identique
    pour tous les détecteurs (windows, linux, ...).

    Note : le champ timestamp est un epoch en millisecondes (entier), pas une
    date ISO. On expose l'entier brut (timestamp_ms) et sa version ISO
    (timestamp) pour l'affichage.
    """

    timestamp: str | None = None          # timestamp converti en ISO 8601 UTC
    timestamp_ms: int | None = None       # timestamp brut (epoch millisecondes)
    finding_id: str | None = None         # id
    detector_name: str | None = None      # monitor_name
    detector_id: str | None = None        # monitor_id
    source_index: str | None = None       # index où le document a matché
    rule_names: list[str] = field(default_factory=list)      # queries[].name
    severity: str | None = None           # sévérité extraite des tags
    attack_techniques: list[str] = field(default_factory=list)  # tags attack.*
    tags: list[str] = field(default_factory=list)            # tous les tags
    related_doc_ids: list[str] = field(default_factory=list)  # documents source
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_os_hit(cls, source: dict[str, Any]) -> "Finding":
        """Construit un Finding depuis le _source d'un document OpenSearch."""
        queries = source.get("queries") or []

        # Agréger noms de règles et tags de toutes les queries du finding
        rule_names: list[str] = []
        all_tags: list[str] = []
        for q in queries:
            name = q.get("name")
            if name:
                rule_names.append(name)
            for t in (q.get("tags") or []):
                if t not in all_tags:
                    all_tags.append(t)

        # Extraire la sévérité et les techniques ATT&CK des tags
        severity = next((t for t in all_tags if t.lower() in _SEVERITIES), None)
        attack = [t for t in all_tags if t.lower().startswith("attack.")]

        # timestamp epoch ms -> ISO 8601
        ts_ms = _to_int(source.get("timestamp"))
        ts_iso = _epoch_ms_to_iso(ts_ms)

        return cls(
            timestamp=ts_iso,
            timestamp_ms=ts_ms,
            finding_id=source.get("id"),
            detector_name=source.get("monitor_name"),
            detector_id=source.get("monitor_id"),
            source_index=source.get("index"),
            rule_names=rule_names,
            severity=severity,
            attack_techniques=attack,
            tags=all_tags,
            related_doc_ids=source.get("related_doc_ids") or [],
            raw=source,
        )

    def severite_m1(self) -> str | None:
        """Sévérité Sigma convertie vers l'enum `severite` de M1."""
        return sigma_severity_to_severite_m1(self.severity)

    def to_dict(self) -> dict[str, Any]:
        """
        Dictionnaire prêt pour insertion en base.
        `severite` est convertie vers l'enum M1 ; `donnees_brutes` alimente la
        colonne JSON. Voir INTEGRATION_M1.md pour la résolution des références.
        """
        return {
            "timestamp": self.timestamp,
            "finding_id": self.finding_id,
            "detector_name": self.detector_name,
            "detector_id": self.detector_id,
            "source_index": self.source_index,
            "rule_names": self.rule_names,
            "severity": self.severity,
            "severite": self.severite_m1(),  # enum M1 (faible/moyenne/haute/critique)
            "attack_techniques": self.attack_techniques,
            "related_doc_ids": self.related_doc_ids,
            "donnees_brutes": self.raw,  # document OpenSearch complet (colonne JSON M1)
        }


def _epoch_ms_to_iso(ms: int | None) -> str | None:
    """Convertit un epoch en millisecondes vers une chaîne ISO 8601 UTC."""
    if ms is None:
        return None
    from datetime import datetime, timezone
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


# ---------------------------------------------------------------------- #
# Alerte de détecteur Security Analytics (déclenchée par un trigger)
# ---------------------------------------------------------------------- #

# Échelle de sévérité Security Analytics : "1" (le plus critique) à "5".
# Distincte de l'échelle Wazuh (niveau numérique croissant).
_SAP_SEVERITY_LABELS = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
    "5": "informational",
}


@dataclass
class DetectorAlert:
    """
    Alerte déclenchée par un trigger de détecteur Security Analytics
    (index .opensearch-sap-*-alerts).

    À ne pas confondre avec :
      - Alert   : alerte Wazuh (index wazuh-alerts-*)
      - Finding : correspondance règle Sigma -> document (index *findings*)

    Une alerte de détecteur est produite quand la condition d'un trigger est
    remplie ; elle référence les findings qui l'ont déclenchée (finding_ids)
    et possède un cycle de vie (state : ACTIVE, ACKNOWLEDGED, COMPLETED...).

    Les temps (start_time, end_time) sont des epoch millisecondes.
    La sévérité est une chaîne "1".."5" ("1" = le plus critique) ; le libellé
    lisible est exposé via severity_label.
    """

    start_time: str | None = None         # start_time (epoch ms) -> ISO
    start_time_ms: int | None = None       # start_time brut
    end_time: str | None = None            # end_time (epoch ms) -> ISO (None si active)
    alert_id: str | None = None            # id
    detector_name: str | None = None       # monitor_name
    detector_id: str | None = None         # monitor_id
    trigger_name: str | None = None        # trigger_name
    severity: str | None = None            # "1".."5" (brut)
    severity_label: str | None = None      # libellé lisible (critical..informational)
    state: str | None = None               # ACTIVE, ACKNOWLEDGED, COMPLETED, ERROR
    finding_ids: list[str] = field(default_factory=list)      # findings déclencheurs
    related_doc_ids: list[str] = field(default_factory=list)  # documents source
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_os_hit(cls, source: dict[str, Any]) -> "DetectorAlert":
        """Construit un DetectorAlert depuis le _source d'un document OpenSearch."""
        sev = source.get("severity")
        sev = str(sev) if sev is not None else None

        return cls(
            start_time=_epoch_ms_to_iso(_to_int(source.get("start_time"))),
            start_time_ms=_to_int(source.get("start_time")),
            end_time=_epoch_ms_to_iso(_to_int(source.get("end_time"))),
            alert_id=source.get("id"),
            detector_name=source.get("monitor_name"),
            detector_id=source.get("monitor_id"),
            trigger_name=source.get("trigger_name"),
            severity=sev,
            severity_label=_SAP_SEVERITY_LABELS.get(sev) if sev else None,
            state=source.get("state"),
            finding_ids=source.get("finding_ids") or [],
            related_doc_ids=source.get("related_doc_ids") or [],
            raw=source,
        )

    def severite_m1(self) -> str | None:
        """Sévérité détecteur ("1".."5") convertie vers l'enum `severite` de M1."""
        return sap_severity_to_severite_m1(self.severity)

    def to_dict(self) -> dict[str, Any]:
        """
        Dictionnaire prêt pour insertion en base.
        `severite` est convertie vers l'enum M1 ; `donnees_brutes` alimente la
        colonne JSON. Voir INTEGRATION_M1.md pour la résolution des références.
        """
        return {
            "start_time": self.start_time,
            "end_time": self.end_time,
            "alert_id": self.alert_id,
            "detector_name": self.detector_name,
            "detector_id": self.detector_id,
            "trigger_name": self.trigger_name,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "severite": self.severite_m1(),  # enum M1 (faible/moyenne/haute/critique)
            "state": self.state,
            "finding_ids": self.finding_ids,
            "related_doc_ids": self.related_doc_ids,
            "donnees_brutes": self.raw,  # document OpenSearch complet (colonne JSON M1)
        }