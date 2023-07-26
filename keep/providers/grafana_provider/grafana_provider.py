"""
Grafana Provider is a class that allows to ingest/digest data from Grafana.
"""

import dataclasses
import datetime
import random

import pydantic
import requests
from grafana_api.alerting import Alerting
from grafana_api.alerting_provisioning import AlertingProvisioning
from grafana_api.model import APIEndpoints, APIModel

from keep.api.models.alert import AlertDto
from keep.providers.base.base_provider import BaseProvider
from keep.providers.base.provider_exceptions import GetAlertException
from keep.providers.grafana_provider.grafana_alert_format_description import (
    GrafanaAlertFormatDescription,
)
from keep.providers.models.provider_config import ProviderConfig
from keep.providers.providers_factory import ProvidersFactory


@pydantic.dataclasses.dataclass
class GrafanaProviderAuthConfig:
    """
    Grafana authentication configuration.
    """

    token: str = dataclasses.field(
        metadata={"required": True, "description": "Token", "hint": "Grafana Token"},
    )
    host: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Grafana host",
            "hint": "e.g. https://keephq.grafana.net",
        },
    )


class GrafanaProvider(BaseProvider):
    """
    Grafana provider class.
    """

    def __init__(self, provider_id: str, config: ProviderConfig):
        super().__init__(provider_id, config)

    def dispose(self):
        """
        Dispose the provider.
        """
        pass

    def validate_config(self):
        """
        Validates required configuration for Grafana provider.

        """
        self.authentication_config = GrafanaProviderAuthConfig(
            **self.config.authentication
        )

    def _query(self, **kwargs: dict):
        pass

    def get_alerts_configuration(self, alert_id: str | None = None):
        api = f"{self.authentication_config.host}{APIEndpoints.ALERTING_PROVISIONING.value}/alert-rules"
        headers = {"Authorization": f"Bearer {self.authentication_config.token}"}
        response = requests.get(api, headers=headers)
        if not response.ok:
            self.logger.warn(
                "Could not get alerts", extra={"response": response.json()}
            )
            error = response.json()
            if response.status_code == 403:
                error[
                    "message"
                ] += f"\nYou can test your permissions with \n\tcurl -H 'Authorization: Bearer {{token}}' -X GET '{self.authentication_config.host}/api/access-control/user/permissions' | jq \nDocs: https://grafana.com/docs/grafana/latest/administration/service-accounts/#debug-the-permissions-of-a-service-account-token"
            raise GetAlertException(message=error, status_code=response.status_code)
        return response.json()

    def deploy_alert(self, alert: dict, alert_id: str | None = None):
        self.logger.info("Deploying alert")
        api = f"{self.authentication_config.host}{APIEndpoints.ALERTING_PROVISIONING.value}/alert-rules"
        headers = {"Authorization": f"Bearer {self.authentication_config.token}"}
        response = requests.post(api, json=alert, headers=headers)

        if not response.ok:
            response_json = response.json()
            self.logger.warn(
                "Could not deploy alert", extra={"response": response_json}
            )
            raise Exception(response_json)

        self.logger.info(
            "Alert deployed",
            extra={
                "response": response.json(),
                "status": response.status_code,
            },
        )

    @staticmethod
    def get_alert_schema():
        return GrafanaAlertFormatDescription.schema()

    @staticmethod
    def format_alert(event: dict) -> AlertDto:
        alert = event.get("alerts", [{}])[0]
        return AlertDto(
            id=alert.get("fingerprint"),
            name=event.get("title"),
            status=event.get("status"),
            severity=alert.get("severity", None),
            lastReceived=str(datetime.datetime.fromisoformat(alert.get("startsAt"))),
            fatigueMeter=random.randint(0, 100),
            description=alert.get("annotations", {}).get("summary", ""),
            source=["grafana"],
            **alert.get("labels", {}),
        )

    def __extract_rules(self, alerts: dict, source: list) -> list[AlertDto]:
        alert_ids = []
        alert_dtos = []
        for group in alerts.get("data", {}).get("groups", []):
            for rule in group.get("rules", []):
                for alert in rule.get("alerts", []):
                    alert_id = rule.get(
                        "id", rule.get("name", "").replace(" ", "_").lower()
                    )

                    if alert_id in alert_ids:
                        # de duplicate alerts
                        continue

                    description = alert.get("annotations", {}).pop(
                        "description", None
                    ) or alert.get("annotations", {}).get("summary", rule.get("name"))

                    labels = {k.lower(): v for k, v in alert.get("labels", {}).items()}
                    annotations = {
                        k.lower(): v for k, v in alert.get("annotations", {}).items()
                    }
                    alert_dto = AlertDto(
                        id=alert_id,
                        name=rule.get("name"),
                        description=description,
                        status=alert.get("state", rule.get("state")),
                        lastReceived=alert.get("activeAt"),
                        source=source,
                        **labels,
                        **annotations,
                    )
                    alert_ids.append(alert_id)
                    alert_dtos.append(alert_dto)
        return alert_dtos

    def get_alerts(self) -> list[AlertDto]:
        source_by_api_url = {
            f"{self.authentication_config.host}/api/prometheus/grafana/api/v1/rules": [
                "grafana"
            ],
            f"{self.authentication_config.host}/api/prometheus/grafanacloud-prom/api/v1/rules": [
                "grafana",
                "prometheus",
            ],
        }
        headers = {"Authorization": f"Bearer {self.authentication_config.token}"}
        alert_dtos = []
        for url in source_by_api_url:
            try:
                response = requests.get(url, headers=headers)
                if not response.ok:
                    continue
                rules = response.json()
                alert_dtos.extend(self.__extract_rules(rules, source_by_api_url[url]))
            except Exception:
                self.logger.exception("Could not get alerts", extra={"api": url})
        return alert_dtos


if __name__ == "__main__":
    # Output debug messages
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])

    # Load environment variables
    import os

    host = os.environ.get("GRAFANA_HOST")
    token = os.environ.get("GRAFANA_TOKEN")

    config = {
        "authentication": {"host": host, "token": token},
    }
    provider = ProvidersFactory.get_provider(
        provider_id="grafana-keephq", provider_type="grafana", provider_config=config
    )
    alerts = provider.get_alerts_configuration()
    print(alerts)
