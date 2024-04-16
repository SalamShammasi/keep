"""
AppDynamics Provider is a class that allows to ingest/digest data from AppDynamics.
"""

import dataclasses
import datetime
import json
import tempfile
from typing import Optional, List
from urllib.parse import urljoin, urlencode
import logging

import pydantic
import requests
from grafana_api.model import APIEndpoints

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_exception import ProviderException
from keep.providers.base.base_provider import BaseProvider
from keep.providers.base.provider_exceptions import GetAlertException
# from keep.providers.grafana_provider.grafana_alert_format_description import (
#     AppDynamicsAlertFormatDescription,
# )
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.providers_factory import ProvidersFactory

logger = logging.getLogger(__name__)


class HTTPActionTemplateAlreadyExists(Exception):
    def __init__(self, *args):
        super().__init__(*args)


@pydantic.dataclasses.dataclass
class AppDynamicsProviderAuthConfig:
    """
    AppDynamics authentication configuration.
    """

    appDynamicsUsername: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Token",
            "hint": "AppDynamics Token"
        },
    )
    appDynamicsAccountName: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Token",
            "hint": "AppDynamics Token"
        },
    )
    appDynamicsPassword: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Token",
            "hint": "AppDynamics Token",
            "sensitive": True,
        },
    )
    appName: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "AppDynamics host",
            "hint": "e.g. https://keephq.grafana.net",
        },
    )
    host: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "AppDynamics host",
            "hint": "e.g. https://keephq.grafana.net",
        },
    )


class AppDynamicsProvider(BaseProvider):
    """Pull/Push alerts from AppDynamics."""

    KEEP_GRAFANA_WEBHOOK_INTEGRATION_NAME = "keep-grafana-webhook-integration"
    PROVIDER_SCOPES = [
        ProviderScope(
            name="authenticated",
            description="User is Authorized",
            mandatory=True,
            mandatory_for_webhook=False,
            documentation_url="https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/custom-role-actions-scopes/",
            alias="Rules Reader",
        ),
        ProviderScope(
            name="administrator",
            description="Administrator privileges",
            mandatory=True,
            mandatory_for_webhook=False,
            documentation_url="https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/custom-role-actions-scopes/",
            alias="Rules Reader",
        ),

    ]

    SEVERITIES_MAP = {
        "ERROR": AlertSeverity.CRITICAL,
        "WARN": AlertSeverity.WARNING,
        "INFO": AlertSeverity.INFO,
    }

    def __init__(
            self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def dispose(self):
        """
        Dispose the provider.
        """
        pass

    def validate_config(self):
        """
        Validates required configuration for AppDynamics provider.

        """
        self.authentication_config = AppDynamicsProviderAuthConfig(
            **self.config.authentication
        )
        if not self.authentication_config.host.startswith(
                "https://"
        ) and not self.authentication_config.host.startswith("http://"):
            self.authentication_config.host = (
                f"https://{self.authentication_config.host}"
            )

    def __get_url(self, paths: List[str] = [], query_params: dict = None, **kwargs):
        """
        Helper method to build the url for AppDynamics api requests.

        Example:

        paths = ["issue", "createmeta"]
        query_params = {"projectKeys": "key1"}
        url = __get_url("test", paths, query_params)

        # url = https://test.atlassian.net/rest/api/2/issue/createmeta?projectKeys=key1
        """

        url = urljoin(
            f"{self.authentication_config.host}/controller",
            "/".join(str(path) for path in paths),
        )

        # add query params
        if query_params:
            url = f"{url}?{urlencode(query_params)}"

        return url

    def validate_scopes(self) -> dict[str, bool | str]:
        administrator = "Missing Administrator Privileges"
        response = requests.get(
            url=self.__get_url(
                paths=['controller/api/rbac/v1/users/name', self.authentication_config.appDynamicsUsername]),
            auth=self.__get_auth())
        if response.ok:
            authenticated = True
            response = response.json()
            for role in response['roles']:
                if role['name'] == 'Account Administrator' or role['name'] == 'Administrator':
                    administrator = True
                    break
        else:
            authenticated = False
        return {
            "authenticated": authenticated,
            "administrator": administrator
        }

    def __get_auth(self) -> tuple[str, str]:
        return (f"{self.authentication_config.appDynamicsUsername}@{self.authentication_config.appDynamicsAccountName}",
                self.authentication_config.appDynamicsPassword)

    def __create_http_response_template(self, keep_api_url: str):
        keep_api_host, keep_api_path = keep_api_url.rsplit("/", 1)

        temp = tempfile.NamedTemporaryFile(mode='w+t', delete=True)

        template = json.load(open(r'./httpactiontemplate.json'))
        template["host"] = keep_api_host
        template["path"] = keep_api_path

        temp.write(json.dumps(template))
        temp.seek(0)

        res = requests.post(self.__get_url(paths=["controller/actiontemplate/httprequest"]),
                            files={"template": temp}, auth=self.__get_auth())
        res = res.json()
        temp.close()
        if res["success"] == "True":
            logger.info("HTTP Response template Successfully Created")
        else:
            logger.info("HTTP Response template creation failed", extra=res)
            if 'already exists' in res['error'][0]:
                logger.info("HTTP Response template creation failed as it already exists", extra=res)
                raise HTTPActionTemplateAlreadyExists()
            raise Exception(res["errors"])

    def setup_webhook(
            self, tenant_id: str, keep_api_url: str, api_key: str, setup_alerts: bool = True
    ):
        try:
            self.__create_http_response_template(keep_api_url=keep_api_url)
        except HTTPActionTemplateAlreadyExists as e:
            logger.info("Template already exists, proceeding with webhook setup")
        except Exception as e:
            raise e

        # Listing all policies in the specified app
        policies_response = requests.get(
            url=self.__get_url(paths=["alerting/rest/v1/applications", self.authentication_config.appName, "policies"]),
            auth=self.__get_auth(),
        )

        policies = policies_response.json()
        policy_config = {
            "actionName": "KeepWebhook",
            "actionType": "HTTP_REQUEST",
        }
        for policy in policies:
            if policy_config not in policy["actions"]:
                policy["actions"].append(policy_config)
            request = requests.put(
                url=self.__get_url(
                    paths=["/alerting/rest/v1/applications", self.authentication_config.appName, "policies",
                           policy["id"]]),
                auth=self.__get_auth(),
                data=policy,
            )
            if not request.ok:
                logger.error("Failed to add Webhook", extra=request.json())
                raise Exception("Could not create webhook")
            logger.info("Webhook created")

    @staticmethod
    def _format_alert(
            event: dict,
            provider_instance: Optional["AppDynamicsProvider"],
    ) -> AlertDto:
        return AlertDto(
            **event,
            severity=AppDynamicsProvider.SEVERITIES_MAP.get(event['severity']),
            source=['appdynamics']
        )


if __name__ == "__main__":
    # Output debug messages
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])

    # Load environment variables
    import os

    host = os.environ.get("APPDYNAMICS_HOST")
    appDynamicsUsername = os.environ.get("APPDYNAMICS_USERNAME")
    appDynamicsPassword = os.environ.get("APPDYNAMICS_PASSWORD")
    appDynamicsAccountName = os.environ.get("APPDYNAMICS_ACCOUNT_NAME")
    appName = os.environ.get("APPDYNAMICS_APP_NAME")
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )
    config = {
        "authentication": {"host": host, "appDynamicsUsername": appDynamicsUsername,
                           "appDynamicsPassword": appDynamicsPassword,
                           "appDynamicsAccountName": appDynamicsAccountName,
                           "appName": appName},
    }
    provider = ProvidersFactory.get_provider(
        context_manager,
        provider_id="appdynamics-keephq",
        provider_type="appdynamics",
        provider_config=config,
    )
    alerts = provider.setup_webhook("test", "http://localhost:8000", "1234", True)
    print(alerts)