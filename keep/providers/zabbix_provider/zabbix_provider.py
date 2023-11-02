"""
Zabbix Provider is a class that allows to ingest/digest data from Zabbix.
"""
import dataclasses
import datetime
import os
import random

import pydantic
import requests

from keep.api.models.alert import AlertDto
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.base.provider_exceptions import ProviderMethodException
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.models.provider_method import ProviderMethod
from keep.providers.providers_factory import ProvidersFactory


@pydantic.dataclasses.dataclass
class ZabbixProviderAuthConfig:
    """
    Zabbix authentication configuration.
    """

    zabbix_frontend_url: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Zabbix Frontend URL",
            "hint": "https://zabbix.example.com",
            "sensitive": False,
        }
    )
    auth_token: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Zabbix Auth Token",
            "hint": "Users -> Api tokens",
            "sensitive": True,
        }
    )


class ZabbixProvider(BaseProvider):
    """
    Zabbix provider class.
    """

    KEEP_ZABBIX_WEBHOOK_INTEGRATION_NAME = "keep"  # keep-zabbix
    KEEP_ZABBIX_WEBHOOK_SCRIPT_FILENAME = (
        "zabbix_provider_script.js"  # zabbix mediatype script file
    )
    KEEP_ZABBIX_WEBHOOK_MEDIATYPE_TYPE = 4
    PROVIDER_SCOPES = [
        ProviderScope(
            name="problem.get",
            description="The method allows to retrieve problems.",
            mandatory=True,
            mandatory_for_webhook=False,
            documentation_url="https://www.zabbix.com/documentation/current/en/manual/api/reference/problem/get",
        ),
        ProviderScope(
            name="mediatype.get",
            description="The method allows to retrieve media types.",
            mandatory=False,
            mandatory_for_webhook=True,
            documentation_url="https://www.zabbix.com/documentation/current/en/manual/api/reference/mediatype/get",
        ),
        ProviderScope(
            name="mediatype.update",
            description="This method allows to update existing media types.",
            mandatory=False,
            mandatory_for_webhook=True,
            documentation_url="https://www.zabbix.com/documentation/current/en/manual/api/reference/mediatype/update",
        ),
        ProviderScope(
            name="mediatype.create",
            description="This method allows to create new media types.",
            mandatory=False,
            mandatory_for_webhook=True,
            documentation_url="https://www.zabbix.com/documentation/current/en/manual/api/reference/mediatype/create",
        ),
        ProviderScope(
            name="user.get",
            description="The method allows to retrieve users.",
            mandatory=False,
            mandatory_for_webhook=True,
            documentation_url="https://www.zabbix.com/documentation/current/en/manual/api/reference/user/get",
        ),
        ProviderScope(
            name="user.update",
            description="This method allows to update existing users.",
            mandatory=False,
            mandatory_for_webhook=True,
            documentation_url="https://www.zabbix.com/documentation/current/en/manual/api/reference/user/update",
        ),
        ProviderScope(
            name="event.acknowledge",
            description="This method allows to update events.",
            documentation_url="https://www.zabbix.com/documentation/current/en/manual/api/reference/event/acknowledge",
        ),
    ]
    PROVIDER_METHODS = [
        ProviderMethod(
            name="Close Problem",
            func_name="close_problem",
            scopes=["event.acknowledge"],
            type="action",
        ),
        ProviderMethod(
            name="Unsuppress Problem",
            func_name="unsurrpress_problem",
            scopes=["event.acknowledge"],
            type="action",
        ),
    ]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def dispose(self):
        """
        Dispose the provider.
        """
        pass

    def close_problem(self, id: str):
        """
        Close a problem.

        https://www.zabbix.com/documentation/current/en/manual/api/reference/event/acknowledge

        Args:
            id (str): The problem id.
        """
        try:
            self.__send_request("event.acknowledge", {"eventids": id, "action": 1})
        except Exception as e:
            raise ProviderMethodException(e.args[0].get("data"))

    def unsurrpress_problem(self, id: str):
        try:
            self.__send_request("event.acknowledge", {"eventids": id, "action": 64})
        except Exception as e:
            raise ProviderMethodException(e.args[0].get("data"))

    def validate_config(self):
        """
        Validates required configuration for Zabbix provider.

        """
        self.authentication_config = ZabbixProviderAuthConfig(
            **self.config.authentication
        )

    def validate_scopes(self) -> dict[str, bool | str]:
        validated_scopes = {}
        for scope in self.PROVIDER_SCOPES:
            try:
                self.__send_request(scope.name)
            except Exception as e:
                error = e.args[0]["data"]
                if "permission" in error or "not authorized" in error.lower():
                    validated_scopes[scope.name] = e.args[0]["data"]
                    continue
            validated_scopes[scope.name] = True
        return validated_scopes

    def __send_request(self, method: str, params: dict = None):
        """
        Send a request to Zabbix API.

        Args:
            method (str): The method to call.
            params (dict): The parameters to send.

        Returns:
            dict: The response from Zabbix API.
        """
        url = f"{self.authentication_config.zabbix_frontend_url}/api_jsonrpc.php"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.authentication_config.auth_token}",
        }
        data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": random.randint(1000, 2000),
        }

        # zabbix < 6.4 compatibility
        data["auth"] = f"{self.authentication_config.auth_token}"

        response = requests.post(url, json=data, headers=headers)

        response.raise_for_status()
        response_json = response.json()
        if "error" in response_json:
            raise Exception(response_json["error"])
        return response_json

    def get_alerts(self) -> list[AlertDto]:
        # https://www.zabbix.com/documentation/current/en/manual/api/reference/problem/get
        problems = self.__send_request("problem.get", {"recent": False})
        formatted_alerts = []
        for problem in problems.get("result", []):
            name = problem.pop("name")
            problem.pop("source")
            status = (
                "PROBLEM"
                if problem.pop("acknowledged") == "0"
                else "ACKED"
                if problem.pop("suppressed") == "0"
                else "SURPRESSED"
            )
            formatted_alerts.append(
                AlertDto(
                    id=problem.pop("eventid"),
                    name=name,
                    status=status,
                    lastReceived=datetime.datetime.fromtimestamp(
                        int(problem.get("clock"))
                    ).isoformat(),
                    source=["zabbix"],
                    message=name,
                    severity=self.__get_severity(problem.pop("severity")),
                    **problem,
                )
            )
        return formatted_alerts

    def setup_webhook(
        self, tenant_id: str, keep_api_url: str, api_key: str, setup_alerts: bool = True
    ):
        # Copied from https://git.zabbix.com/projects/ZBX/repos/zabbix/browse/templates/media/ilert/media_ilert.yaml?at=release%2F6.4
        # Based on @SomeAverageDev hints and suggestions ;) Thanks!
        # TODO: this can be done once when loading the provider file
        self.logger.info("Reading webhook JS script file")
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__))
        )

        with open(
            os.path.join(
                __location__, ZabbixProvider.KEEP_ZABBIX_WEBHOOK_SCRIPT_FILENAME
            )
        ) as f:
            script = f.read()

        self.logger.info("Creating or updating webhook")
        mediatype_name = f"{ZabbixProvider.KEEP_ZABBIX_WEBHOOK_INTEGRATION_NAME}"  # -{tenant_id.replace('-', '')}

        self.logger.info("Getting existing media types")
        existing_mediatypes = self.__send_request(
            "mediatype.get",
            {
                "output": ["mediatypeid", "name"],
                "filter": {"type": [ZabbixProvider.KEEP_ZABBIX_WEBHOOK_MEDIATYPE_TYPE]},
            },
        )

        mediatype_description = "Please refer to https://docs.keephq.dev/providers/documentation/zabbix-provider or https://platform.keephq.dev/."

        self.logger.info("Got existing media types")
        mediatype_list = [
            mt
            for mt in existing_mediatypes.get("result", [])
            if mt["name"] == mediatype_name
        ]

        parameters = [
            {"name": "keepApiKey", "value": api_key},
            {"name": "keepApiUrl", "value": keep_api_url},
            {"name": "id", "value": "{EVENT.ID}"},
            {"name": "triggerId", "value": "{TRIGGER.ID}"},
            {"name": "lastReceived", "value": "{EVENT.DATE} {EVENT.TIME}"},
            {"name": "message", "value": "{ALERT.MESSAGE}"},
            {"name": "name", "value": "{EVENT.NAME}"},
            {"name": "service", "value": "{HOST.HOST}"},
            {"name": "severity", "value": "{TRIGGER.SEVERITY}"},
            {"name": "status", "value": "{TRIGGER.STATUS}"},
            {"name": "ALERT.SUBJECT", "value": "{ALERT.SUBJECT}"},
            {"name": "EVENT.SEVERITY", "value": "{EVENT.SEVERITY}"},
            {"name": "EVENT.TAGS", "value": "{EVENT.TAGS}"},
            {"name": "EVENT.TIME", "value": "{EVENT.TIME}"},
            {"name": "EVENT.VALUE", "value": "{EVENT.VALUE}"},
            {"name": "HOST.IP", "value": "{HOST.IP}"},
            {"name": "HOST.NAME", "value": "{HOST.NAME}"},
            {"name": "description", "value": "{TRIGGER.DESCRIPTION}"},
            {"name": "ZABBIX.URL", "value": "{$ZABBIX.URL}"},
        ]

        if mediatype_list:
            existing_mediatype = mediatype_list[0]
            self.logger.info("Updating existing media type")
            media_type_id = str(existing_mediatype["mediatypeid"])
            self.__send_request(
                "mediatype.update",
                {
                    "mediatypeid": str(existing_mediatype["mediatypeid"]),
                    "script": script,
                    "status": "0",
                    "parameters": parameters,
                    "description": mediatype_description,
                },
            )
            self.logger.info("Updated existing media type")
        else:
            self.logger.info("Creating new media type")
            params = {
                "name": mediatype_name,
                "type": f"{ZabbixProvider.KEEP_ZABBIX_WEBHOOK_MEDIATYPE_TYPE}",  # webhook
                "parameters": parameters,
                "script": script,
                "process_tags": 1,
                "show_event_menu": 0,
                "description": mediatype_description,
                "message_templates": [
                    {
                        "eventsource": 0,
                        "recovery": 0,
                        "subject": "Problem: {EVENT.NAME}",
                        "message": "Problem started at {EVENT.TIME} on {EVENT.DATE}\nProblem name: {EVENT.NAME}\nHost: {HOST.NAME}\nSeverity: {EVENT.SEVERITY}\nOperational data: {EVENT.OPDATA}\nOriginal problem ID: {EVENT.ID}\n{TRIGGER.URL}\n",
                    },
                    {
                        "eventsource": 0,
                        "recovery": 2,
                        "subject": "Updated problem in {EVENT.AGE}: {EVENT.NAME}",
                        "message": "{USER.FULLNAME} {EVENT.UPDATE.ACTION} problem at {EVENT.UPDATE.DATE} {EVENT.UPDATE.TIME}.\n{EVENT.UPDATE.MESSAGE}\n\nCurrent problem status is {EVENT.STATUS}, age is {EVENT.AGE}, acknowledged: {EVENT.ACK.STATUS}.\n",
                    },
                    {
                        "eventsource": 0,
                        "recovery": 1,
                        "subject": "Resolved in {EVENT.DURATION}: {EVENT.NAME}",
                        "message": "Problem has been resolved at {EVENT.RECOVERY.TIME} on {EVENT.RECOVERY.DATE}\nProblem name: {EVENT.NAME}\nProblem duration: {EVENT.DURATION}\nHost: {HOST.NAME}\nSeverity: {EVENT.SEVERITY}\nOriginal problem ID: {EVENT.ID}\n{TRIGGER.URL}\n",
                    },
                ],
            }
            response_json = self.__send_request("mediatype.create", params)
            media_type_id = str(
                response_json.get("result", {}).get("mediatypeids", [])[0]
            )
            self.__send_request(
                "mediatype.update",
                {
                    "mediatypeid": media_type_id,
                    "status": "0",
                },
            )
            self.logger.info("Created media type")
        self.logger.info(
            "Updating users to include new created media type",
            extra={"media_type_id": media_type_id},
        )
        users = self.__send_request("user.get", {"selectMedias": "extend"}).get(
            "result", []
        )
        user_update_params = []
        for user in users:
            username = user.get("username")
            if username == "guest":
                self.logger.debug("skipping guest user")
                continue
            media_exists = next(
                iter(
                    [
                        m
                        for m in user.get("medias", [])
                        if m["mediatypeid"] == media_type_id
                    ]
                ),
                None,
            )
            if media_exists:
                self.logger.info(f"skipping user {username} because media exists")
            else:
                current_user_medias = user.get("medias", [])
                # We need to clean irrelevant data or the request will fail
                # https://www.zabbix.com/documentation/current/en/manual/api/reference/user/object#media
                current_user_medias = [
                    {
                        "mediatypeid": media["mediatypeid"],
                        "sendto": media["sendto"],
                        "active": media["active"],
                        "severity": media["severity"],
                        "period": media["period"],
                    }
                    for media in current_user_medias
                ]
                current_user_medias.append(
                    {
                        "mediatypeid": media_type_id,
                        "sendto": "KEEP",
                        "active": "0",
                    }
                )
                user_update_params.append(
                    {"userid": user["userid"], "medias": current_user_medias}
                )
        if user_update_params:
            self.logger.info(
                "Updating users", extra={"user_update_params": user_update_params}
            )
            self.__send_request("user.update", user_update_params)
            self.logger.info("Updated users")
        else:
            self.logger.info("No users to update")
        self.logger.info("Finished installing webhook")

    @staticmethod
    def __get_severity(priority: str):
        if priority == "disaster" or priority == "5":
            return "critical"
        elif priority == "high" or priority == "4":
            return "high"
        elif priority == "average" or priority == "3":
            return "medium"
        else:
            return "low"

    @staticmethod
    def format_alert(event: dict) -> AlertDto:
        environment = "unknown"
        tags = event.get("tags", {})
        if isinstance(tags, dict):
            environment = tags.get("environment", "unknown")
        severity = ZabbixProvider.__get_severity(event.pop("severity", "").lower())
        event_id = event.get("id")
        trigger_id = event.get("triggerId")
        zabbix_url = event.pop("ZABBIX.URL", None)
        url = None
        if event_id and trigger_id and zabbix_url:
            url = (
                f"{zabbix_url}/tr_events.php?triggerid={trigger_id}&eventid={event_id}"
            )
        return AlertDto(
            **event,
            environment=environment,
            pushed=True,
            source=["zabbix"],
            severity=severity,
            url=url,
        )


if __name__ == "__main__":
    # Output debug messages
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )
    # Load environment variables
    import os

    auth_token = os.environ.get("ZABBIX_AUTH_TOKEN")

    provider_config = {
        "authentication": {
            "auth_token": auth_token,
            "zabbix_frontend_url": "http://localhost",
        },
    }
    provider = ProvidersFactory.get_provider(
        context_manager,
        provider_id="zabbix",
        provider_type="zabbix",
        provider_config=provider_config,
    )
    provider.setup_webhook(
        "e1faa321-35df-486b-8fa8-3601ee714011", "http://localhost:8080", "abc"
    )
