"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CTE Palo Alto Networks Cortex XDR plugin's main file which contains
the implementation of all the plugin's methods.
"""
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import string
import traceback
from typing import Dict, List, Tuple

from urllib.parse import urlparse
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import (
    PluginBase,
)
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .utils.palo_alto_networks_cortex_xdr_constants import (
    DEFAULT_BATCH_SIZE,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_CHECKPOINT,
    PLUGIN_NAME,
    PLUGIN_VERSION,
)
from .utils.palo_alto_networks_cortex_xdr_helper import (
    PaloAltoCortexNetworksXDRPluginException,
    PaloAltoCortexNetworksXDRPluginHelper,
)


class PaloAltoNetworksCortexXDRPlugin(PluginBase):
    """PaloAltoNetworksCortexXDRPlugin class having implementation all
    plugin's methods."""

    def __init__(self, name, *args, **kwargs):
        """PaloAltoCortexXDR plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.palo_alto_cortex_helper = PaloAltoCortexNetworksXDRPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
            return manifest_json.get("name", ""), manifest_json.get("version", "")
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Could not get plugin info from manifest.json. {e}"
            )
            return "", ""

    def _get_incident_extra_data_filter(self, incident_id: str, alerts_limit: int) -> dict:
        return {
            "incident_id": incident_id,
            "alerts_limit": alerts_limit
        }

    def get_incidents(self,
                      modification_time: int = None,
                      after_modification: bool = False,
                      creation_time: int = None,
                      after_creation: bool = False,
                      incident_id_list: List[str] = None,
                      description: str = None,
                      description_contains: bool = False,
                      alert_sources: List[str] = None,
                      status: str = None,
                      status_equal: bool = True,
                      search_from: int = None,
                      search_to: int = None,
                      ) -> dict:
        """
        Get a list of incidents filtered by various criteria.

        :param modification_time: Time the incident has been modified.
        :param after_modification: If the modification date will be the upper or lower bound limit.
        :param creation_time: Incident's creation time.
        :param after_creation: If the creation date will be the upper or lower bound limit.
        :param incident_id_list: List of incident IDs.
        :param description: Incident description.
        :param description_contains: If the description will contain the search string.
        :param alert_sources: Source which detected the alert.
        :param status: Represents the status of the incident.
        :param status_equal: If the status will be equal to the given status.
        :param search_from: Starting offset within the query result set from which you want incidents returned.
        :param search_to: End offset within the result set after which you do not want incidents returned.
        :return: Dictionary of incidents if successful.
        """
        filters = []
        if modification_time is not None:
            filters.append(self._request_gte_lte_filter("modification_time", modification_time, after_modification))

        if creation_time is not None:
            filters.append(self._request_gte_lte_filter("creation_time", creation_time, after_creation))

        if incident_id_list is not None:
            filters.append(self._request_filter("incident_id_list", "in", incident_id_list))

        if description is not None:
            filters.append(self._request_in_contains_filter("description", description, description_contains))

        if alert_sources is not None:
            filters.append(self._request_filter("alert_sources", "in", alert_sources))

        if status is not None:
            filters.append(self._request_eq_neq_filter("status", status, status_equal))

        request_data = self._new_request_data(filters=filters, search_from=search_from, search_to=search_to)
        response = self._call_api("get_incidents", request_data)
        return response.json()

    def get_incident_extra_data(self,
                                incident_id: str,
                                alerts_limit: int = 1000,
                                ) -> dict:
        """
        Get extra data fields of a specific incident including alerts and key artifacts.

        :param incident_id: The ID of the incident for which you want to retrieve extra data.
        :param alerts_limit: Maximum number of related alerts in the incident that you want to retrieve (default 1000).
        :return: Dictionary of extra incident data if successful.
        """
        request_data = self._new_request_data(other=self._get_incident_extra_data_filter(incident_id, alerts_limit))
        response = self._call_api("get_incident_extra_data", request_data)
        return response.json()

    def _request_gte_lte_filter(self, field, value, is_gte):
        return {
            "field": field,
            "operator": "gte" if is_gte else "lte",
            "value": value
        }

    def _request_filter(self, field, operator, values):
        return {
            "field": field,
            "operator": operator,
            "value": values
        }

    def _request_in_contains_filter(self, field, value, contains):
        return {
            "field": field,
            "operator": "contains" if contains else "in",
            "value": value
        }

    def _request_eq_neq_filter(self, field, value, is_eq):
        return {
            "field": field,
            "operator": "eq" if is_eq else "neq",
            "value": value
        }

    def _new_request_data(self, filters, search_from=None, search_to=None, other=None):
        data = {
            "request_data": {
                "filters": filters
            }
        }
        if search_from is not None:
            data["request_data"]["search_from"] = search_from
        if search_to is not None:
            data["request_data"]["search_to"] = search_to
        if other:
            data["request_data"].update(other)
        return data

    def _call_api(self, call_name, json_value):
        base_url = (
            self.configuration.get("base_url", "").strip().strip("/")
        )
        if call_name == "get_incidents":
            url = f"{base_url}/public_api/v1/incidents/get_incidents"
        elif call_name == "get_incident_extra_data":
            url = f"{base_url}/public_api/v1/incidents/get_incident_extra_data"
        else:
            raise ValueError(f"Unknown call name: {call_name}")

        response = self.palo_alto_cortex_helper.get_data(url, json_value)
        response.raise_for_status()
        return response

    def pull_incidents(self):
        """Pull incidents from the Palo Alto Cortex XDR platform."""
        is_pull_required = self.configuration.get("is_pull_required", "").strip()

        if is_pull_required == "Yes":
            storage = self.storage if self.storage is not None else {}
            try:
                incidents = self.get_incidents()
                for incident in incidents.get("result", {}).get("incidents", []):
                    incident_id = incident.get("incident_id")
                    if incident_id:
                        extra_data = self.get_incident_extra_data(incident_id)
                        # Process extra data as needed
                        # ...

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched incidents from {PLATFORM_NAME}."
                )
            except PaloAltoCortexNetworksXDRPluginException:
                storage = self._checkpoint_helper(storage, True)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched incidents from {PLATFORM_NAME}."
                )
        else:
            self.logger.info(f"{self.log_prefix}: Pull not required.")
