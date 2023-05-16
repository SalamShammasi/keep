"""
Datadog Provider is a class that allows to ingest/digest data from Datadog.
"""

import pydantic
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v1.api.monitors_api import MonitorsApi
from datadog_api_client.v1.model.monitor import Monitor
from datadog_api_client.v1.model.monitor_type import MonitorType

from keep.providers.base.base_provider import BaseProvider
from keep.providers.datadog_provider.datadog_alert_format_description import (
    DatadogAlertFormatDescription,
)
from keep.providers.models.provider_config import ProviderConfig
from keep.providers.providers_factory import ProvidersFactory


@pydantic.dataclasses.dataclass
class DatadogAuthConfig:
    """
    Datadog authentication configuration.
    """

    api_key: str
    app_key: str


class DatadogProvider(BaseProvider):
    """
    Datadog provider class.
    """

    def __init__(self, provider_id: str, config: ProviderConfig):
        super().__init__(provider_id, config)
        self.configuration = Configuration()
        self.configuration.api_key["apiKeyAuth"] = self.authentication_config.api_key
        self.configuration.api_key["appKeyAuth"] = self.authentication_config.app_key

    def dispose(self):
        """
        Dispose the provider.
        """
        pass

    def validate_config(self):
        """
        Validates required configuration for Datadog provider.

        """
        self.authentication_config = DatadogAuthConfig(**self.config.authentication)

    def query(self, **kwargs: dict):
        pass

    def get_alerts(self, alert_id: str | None = None):
        with ApiClient(self.configuration) as api_client:
            api = MonitorsApi(api_client)
            monitors = api.list_monitors()
            monitors = [monitor.to_dict() for monitor in monitors]
            if alert_id:
                monitors = list(
                    filter(lambda monitor: monitor["id"] == alert_id, monitors)
                )
        return monitors

    def deploy_alert(self, alert: dict, alert_id: str | None = None):
        body = Monitor(**alert)
        with ApiClient(self.configuration) as api_client:
            api_instance = MonitorsApi(api_client)
            try:
                response = api_instance.create_monitor(body=body)
            except Exception as e:
                raise Exception({"message": e.body["errors"][0]})
        return response

    @staticmethod
    def get_alert_format_description():
        return DatadogAlertFormatDescription.schema()


if __name__ == "__main__":
    # Output debug messages
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])

    # Load environment variables
    import os

    api_key = os.environ.get("DATADOG_API_KEY")
    app_key = os.environ.get("DATADOG_APP_KEY")

    config = {
        "authentication": {"api_key": api_key, "app_key": app_key},
    }
    provider = ProvidersFactory.get_provider(
        provider_id="datadog-keephq", provider_type="datadog", provider_config=config
    )
    alerts = provider.deploy_alert(
        {
            "name": "Error Rate Alert",
            "type": "metric alert",
            "query": "sum:myapp.server.errors{service:talboren/simple-crud-service}.as_count().rollup(sum, 600) > 5",
            "message": "The error rate for talboren/simple-crud-service has exceeded 5% in the last 10 minutes. Please investigate immediately",
            "tags": ["service:talboren/simple-crud-service", "severity:critical"],
            "options": {
                "thresholds": {"critical": 5},
                "notify_audit": False,
                "notify_no_data": False,
                "require_full_window": True,
                "timeout_h": 1,
                "silenced": {},
            },
            "restricted_roles": [],
            "priority": 2,
        }
    )
    print(alerts)
