"""
Keep Provider is a class that allows to ingest/digest data from Keep.
"""
import dataclasses
import datetime
import json
import logging
import os
import random
from uuid import uuid4

import pydantic
import requests

from keep.api.models.alert import AlertDto
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig
from keep.providers.providers_factory import ProvidersFactory


@pydantic.dataclasses.dataclass
class KeepProviderAuthConfig:
    """
    Keep authentication configuration.
    """


class KeepProvider(BaseProvider):
    """
    Keep provider class.
    """

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
        Validates required configuration for Keep provider.

        """
        self.authentication_config = KeepProviderAuthConfig(
            **self.config.authentication
        )

    def _query(self, alert_id: str | None = None, **kwargs: dict):
        return super()._query(**kwargs)

    @staticmethod
    def format_alert(event: dict) -> AlertDto:
        return AlertDto(
            **event,
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
