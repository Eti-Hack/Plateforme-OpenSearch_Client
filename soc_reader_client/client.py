"""
Client de lecture vers OpenSearch pour la plateforme SOC.

Expose une classe SOCReader qui encapsule opensearch-py et fournit des
méthodes de haut niveau pour interroger événements et alertes :
    - recherche par période, par hôte, par règle/détecteur
    - agrégations simples (top hôtes, comptes par sévérité)
    - pagination robuste via search_after

Le client est en LECTURE SEULE : il n'expose aucune méthode d'écriture.
Le compte utilisé (soc_reader) n'a de toute façon pas les droits d'écriture
côté cluster.
"""

from __future__ import annotations

from typing import Any, Iterator

from opensearchpy import OpenSearch

from .models import LogEvent, Alert, Finding, DetectorAlert
from .config import (
    OpenSearchConfig,
    INDEX_ALL_LOGS,
    INDEX_ALL_ALERTS,
    INDEX_WAZUH,
    INDEX_FINDINGS,
    INDEX_DETECTOR_ALERTS,
)


class SOCReader:
    """Client de lecture pour le cluster OpenSearch du SOC."""

    def __init__(self, config: OpenSearchConfig | None = None) -> None:
        self.config = config or OpenSearchConfig.from_env()
        self._client = OpenSearch(
            hosts=[{"host": self.config.host, "port": self.config.port}],
            http_auth=(self.config.user, self.config.password),
            http_compress=True,
            use_ssl=True,
            verify_certs=self.config.verify_certs,
            ca_certs=self.config.ca_certs,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )

    # ------------------------------------------------------------------ #
    # Connexion / diagnostic
    # ------------------------------------------------------------------ #

    def ping(self) -> bool:
        """
        Vérifie la connectivité en interrogeant un index autorisé.
        N'utilise pas le HEAD / racine (hors périmètre du compte lecture
        seule restreint, qui renverrait 403).
        """
        try:
            self._client.count(index=INDEX_ALL_LOGS)
            return True
        except Exception:
            return False

    def info(self) -> dict[str, Any]:
        """Informations de base sur le cluster (version, nom)."""
        return self._client.info()

    # ------------------------------------------------------------------ #
    # Helper interne : construit la partie "filtre temporel"
    # ------------------------------------------------------------------ #

    @staticmethod
    def _time_range(start: str | None, end: str | None,
                    field: str = "@timestamp") -> dict[str, Any] | None:
        """Construit un filtre range sur un champ date, ou None si pas de bornes."""
        if not start and not end:
            return None
        bounds: dict[str, str] = {}
        if start:
            bounds["gte"] = start
        if end:
            bounds["lte"] = end
        return {"range": {field: bounds}}

    # ------------------------------------------------------------------ #
    # Recherche d'événements (logs ECS Windows / Linux)
    # ------------------------------------------------------------------ #

    def search_events(
        self,
        start: str | None = None,
        end: str | None = None,
        host: str | None = None,
        index: str = INDEX_ALL_LOGS,
        size: int = 100,
        extra_filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Recherche d'événements de logs sur une période, optionnellement filtrés
        par hôte. Retourne la liste des _source des documents trouvés.

        start / end : dates ISO 8601 ou expressions OpenSearch ("now-1h", etc.)
        host        : valeur exacte de host.name
        size        : nombre max de résultats (utiliser paginate() au-delà)
        """
        filters: list[dict[str, Any]] = []
        tr = self._time_range(start, end)
        if tr:
            filters.append(tr)
        if host:
            filters.append({"term": {"host.name": host}})
        if extra_filters:
            filters.extend(extra_filters)

        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        body = {
            "size": size,
            "query": query,
            "sort": [{"@timestamp": "desc"}],
        }
        resp = self._client.search(index=index, body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    # ------------------------------------------------------------------ #
    # Recherche d'alertes Wazuh
    # ------------------------------------------------------------------ #

    def search_alerts(
        self,
        start: str | None = None,
        end: str | None = None,
        agent_name: str | None = None,
        rule_id: str | None = None,
        min_level: int | None = None,
        index: str = INDEX_WAZUH,
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Recherche d'alertes Wazuh sur une période. Les champs Wazuh sont
        imbriqués sous "wazuh.*" (voir le pipeline Logstash 30-wazuh.conf).

        agent_name : wazuh.agent.name
        rule_id    : wazuh.rule.id
        min_level  : niveau minimal (wazuh.rule.level >= min_level)
        """
        filters: list[dict[str, Any]] = []
        tr = self._time_range(start, end)
        if tr:
            filters.append(tr)
        if agent_name:
            filters.append({"term": {"wazuh.agent.name": agent_name}})
        if rule_id:
            filters.append({"term": {"wazuh.rule.id": rule_id}})
        if min_level is not None:
            filters.append({"range": {"wazuh.rule.level": {"gte": min_level}}})

        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        body = {
            "size": size,
            "query": query,
            "sort": [{"@timestamp": "desc"}],
        }
        resp = self._client.search(index=index, body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    # ------------------------------------------------------------------ #
    # Agrégations simples
    # ------------------------------------------------------------------ #

    def top_hosts(
        self,
        start: str | None = None,
        end: str | None = None,
        index: str = INDEX_ALL_LOGS,
        field: str = "host.name",
        n: int = 10,
    ) -> list[tuple[str, int]]:
        """Top N des hôtes par nombre d'événements sur la période."""
        filters: list[dict[str, Any]] = []
        tr = self._time_range(start, end)
        if tr:
            filters.append(tr)
        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        body = {
            "size": 0,
            "query": query,
            "aggs": {"by_host": {"terms": {"field": field, "size": n}}},
        }
        resp = self._client.search(index=index, body=body)
        buckets = resp["aggregations"]["by_host"]["buckets"]
        return [(b["key"], b["doc_count"]) for b in buckets]

    def count_by_severity(
        self,
        start: str | None = None,
        end: str | None = None,
        index: str = INDEX_WAZUH,
        field: str = "wazuh.rule.level",
        n: int = 20,
    ) -> list[tuple[Any, int]]:
        """Répartition des alertes par niveau/sévérité sur la période."""
        filters: list[dict[str, Any]] = []
        tr = self._time_range(start, end)
        if tr:
            filters.append(tr)
        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        body = {
            "size": 0,
            "query": query,
            "aggs": {"by_sev": {"terms": {"field": field, "size": n}}},
        }
        resp = self._client.search(index=index, body=body)
        buckets = resp["aggregations"]["by_sev"]["buckets"]
        return [(b["key"], b["doc_count"]) for b in buckets]

    # ------------------------------------------------------------------ #
    # Pagination robuste via search_after
    # ------------------------------------------------------------------ #

    def paginate(
        self,
        index: str,
        query: dict[str, Any] | None = None,
        sort: list[dict[str, Any]] | None = None,
        page_size: int = 500,
        max_docs: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """
        Itère sur TOUS les documents correspondant à la requête, page par page,
        en utilisant search_after (plus robuste que from/size sur gros volumes).

        Le tri DOIT inclure un champ unique (_id via _shard_doc n'existant pas
        partout, on ajoute _id comme tie-breaker) pour garantir la stabilité.

        Rendement : un _source par document, jusqu'à max_docs si précisé.
        """
        query = query or {"match_all": {}}
        # Tri stable : le champ demandé + _id comme départage.
        sort = sort or [{"@timestamp": "asc"}]
        if not any("_id" in s for s in sort):
            sort = sort + [{"_id": "asc"}]

        search_after: list[Any] | None = None
        yielded = 0

        while True:
            body: dict[str, Any] = {
                "size": page_size,
                "query": query,
                "sort": sort,
            }
            if search_after is not None:
                body["search_after"] = search_after

            resp = self._client.search(index=index, body=body)
            hits = resp["hits"]["hits"]
            if not hits:
                break

            for hit in hits:
                yield hit["_source"]
                yielded += 1
                if max_docs is not None and yielded >= max_docs:
                    return

            search_after = hits[-1]["sort"]
            if len(hits) < page_size:
                break

    # ------------------------------------------------------------------ #
    # Variantes TYPÉES : renvoient des objets LogEvent / Alert
    # (c'est ce que le backend M1 consommera de préférence)
    # ------------------------------------------------------------------ #

    def search_events_typed(
        self,
        start: str | None = None,
        end: str | None = None,
        host: str | None = None,
        index: str = INDEX_ALL_LOGS,
        size: int = 100,
        extra_filters: list[dict[str, Any]] | None = None,
    ) -> list["LogEvent"]:
        """Comme search_events, mais renvoie une liste de LogEvent."""
        hits = self.search_events(
            start=start, end=end, host=host, index=index,
            size=size, extra_filters=extra_filters,
        )
        return [LogEvent.from_os_hit(h) for h in hits]

    def search_alerts_typed(
        self,
        start: str | None = None,
        end: str | None = None,
        agent_name: str | None = None,
        rule_id: str | None = None,
        min_level: int | None = None,
        index: str = INDEX_WAZUH,
        size: int = 100,
    ) -> list["Alert"]:
        """Comme search_alerts, mais renvoie une liste d'Alert."""
        hits = self.search_alerts(
            start=start, end=end, agent_name=agent_name, rule_id=rule_id,
            min_level=min_level, index=index, size=size,
        )
        return [Alert.from_os_hit(h) for h in hits]

    # ------------------------------------------------------------------ #
    # Findings Security Analytics (détecteurs Sigma)
    # ------------------------------------------------------------------ #

    def search_findings(
        self,
        start: str | None = None,
        end: str | None = None,
        detector_name: str | None = None,
        index: str = INDEX_FINDINGS,
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Recherche de findings produits par les détecteurs Security Analytics.

        Le champ temporel des findings est 'timestamp' (epoch millisecondes),
        distinct du '@timestamp' des logs/alertes. Les bornes start/end
        acceptent les mêmes expressions ("now-24h", ISO 8601).

        detector_name : filtre exact sur monitor_name (ex : "Detector-Windows").
                        Voir list_detectors() pour les noms disponibles.
        """
        filters: list[dict[str, Any]] = []
        tr = self._time_range(start, end, field="timestamp")
        if tr:
            filters.append(tr)
        if detector_name:
            filters.append({"term": {"monitor_name": detector_name}})

        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        body = {
            "size": size,
            "query": query,
            "sort": [{"timestamp": "desc"}],
        }
        resp = self._client.search(index=index, body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    def search_findings_typed(
        self,
        start: str | None = None,
        end: str | None = None,
        detector_name: str | None = None,
        index: str = INDEX_FINDINGS,
        size: int = 100,
    ) -> list["Finding"]:
        """Comme search_findings, mais renvoie une liste de Finding."""
        hits = self.search_findings(
            start=start, end=end, detector_name=detector_name,
            index=index, size=size,
        )
        return [Finding.from_os_hit(h) for h in hits]

    def list_detectors(
        self,
        index: str = INDEX_FINDINGS,
        n: int = 50,
    ) -> list[tuple[str, int]]:
        """
        Liste les détecteurs présents dans les findings, avec leur nombre de
        findings. Utile pour connaître les valeurs de detector_name
        disponibles (les détecteurs supprimés peuvent laisser des findings
        orphelins).
        """
        body = {
            "size": 0,
            "aggs": {"detectors": {"terms": {"field": "monitor_name", "size": n}}},
        }
        resp = self._client.search(index=index, body=body)
        buckets = resp["aggregations"]["detectors"]["buckets"]
        return [(b["key"], b["doc_count"]) for b in buckets]

    # ------------------------------------------------------------------ #
    # Alertes de détecteur Security Analytics (triggers)
    # ------------------------------------------------------------------ #

    def search_detector_alerts(
        self,
        start: str | None = None,
        end: str | None = None,
        detector_name: str | None = None,
        state: str | None = None,
        index: str = INDEX_DETECTOR_ALERTS,
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Recherche d'alertes déclenchées par les triggers des détecteurs
        Security Analytics.

        Par défaut, interroge les index COURANTS (INDEX_DETECTOR_ALERTS).
        Pour inclure l'historique archivé, passer
        index=INDEX_DETECTOR_ALERTS_ALL.

        Le champ temporel est 'start_time' (epoch millisecondes).
        detector_name : filtre exact sur monitor_name.
        state         : filtre sur l'état (ACTIVE, ACKNOWLEDGED, COMPLETED...).
        """
        filters: list[dict[str, Any]] = []
        tr = self._time_range(start, end, field="start_time")
        if tr:
            filters.append(tr)
        if detector_name:
            filters.append({"term": {"monitor_name.keyword": detector_name}})
        if state:
            filters.append({"term": {"state": state}})

        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        body = {
            "size": size,
            "query": query,
            "sort": [{"start_time": "desc"}],
        }
        resp = self._client.search(index=index, body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    def search_detector_alerts_typed(
        self,
        start: str | None = None,
        end: str | None = None,
        detector_name: str | None = None,
        state: str | None = None,
        index: str = INDEX_DETECTOR_ALERTS,
        size: int = 100,
    ) -> list["DetectorAlert"]:
        """Comme search_detector_alerts, mais renvoie une liste de DetectorAlert."""
        hits = self.search_detector_alerts(
            start=start, end=end, detector_name=detector_name,
            state=state, index=index, size=size,
        )
        return [DetectorAlert.from_os_hit(h) for h in hits]