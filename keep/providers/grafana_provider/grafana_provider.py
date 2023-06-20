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
        default=None,
    )
    host: str = dataclasses.field(
        metadata={
            "required": False,
            "description": "Grafana host",
            "hint": "e.g. https://keephq.grafana.net",
        },
        default=None,
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
