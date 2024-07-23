import json
import os
import time
from typing import List, Optional, Tuple
from cortex_xdr_client.api.authentication import Authentication
from cortex_xdr_client.api.base_api import BaseAPI
from cortex_xdr_client.api.models.filters import (
    new_request_data,
    request_eq_neq_filter,
)
from cortex_xdr_client.api.models.incidents import (
    GetExtraIncidentDataResponse,
    GetIncidentsResponse,
)
from netskope.integrations.cte.plugin_base import PluginBase
from netskope.integrations.cte.utils import TagUtils
from palo_alto_networks_cortex_xdr_constants import (
    MODULE_NAME, PLATFORM_NAME, PLUGIN_NAME, PLUGIN_VERSION, PLUGIN_CHECKPOINT
)
from palo_alto_networks_cortex_xdr_helper import PaloAltoCortexNetworksXDRPluginHelper

# Obtener la configuración del manifest
def get_plugin_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.json")
    with open(config_path, "r") as config_file:
        config_data = json.load(config_file)
        return config_data["configuration"]

config = get_plugin_config()
config_dict = {item["key"]: item["default"] for item in config}

# Configuración de la autenticación y la API de incidentes
auth = Authentication(
    api_key=config_dict['api_key'],
    client_id=config_dict['api_key_id'],
    client_secret=config_dict['api_key']
)
fqdn = config_dict['base_url']
timeout = (10, 60)
fetch_interval = config_dict['fetch_interval']

class IncidentsAPI(BaseAPI):
    def __init__(self, auth: Authentication, fqdn: str, timeout: Tuple[int, int]) -> None:
        super(IncidentsAPI, self).__init__(auth, fqdn, "incidents", timeout)

    @staticmethod
    def _get_incident_extra_data_filter(incident_id: str, alerts_limit: int) -> dict:
        return {
            "request_data": new_request_data(
                filters=[
                    request_eq_neq_filter("incident_id_list", incident_id)
                ],
                alerts_limit=alerts_limit
            )
        }

    def get_incidents(self) -> GetIncidentsResponse:
        return self._http_request("POST", "get_incidents/", json_data={})

    def get_incident_extra_data(self, incident_id: str, alerts_limit: int) -> GetExtraIncidentDataResponse:
        payload = self._get_incident_extra_data_filter(incident_id, alerts_limit)
        return self._http_request("POST", "get_incident_extra_data/", json_data=payload)

incidents_api = IncidentsAPI(auth, fqdn, timeout)

class PaloAltoNetworksCortexXDRPlugin(PluginBase):
    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
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
        try:
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.json")
            with open(file_path, "r") as manifest_file:
                manifest_data = json.load(manifest_file)
                return manifest_data["name"], manifest_data["version"]
        except Exception as e:
            self.logger.error(f"{self.log_prefix}: Error getting plugin information. Error: {str(e)}")
            raise Exception("Error getting plugin information.")

    def fetch_incidents(self):
        try:
            response = incidents_api.get_incidents()
            incidents = response['reply']['incidents']
            return incidents
        except Exception as e:
            self.logger.error(f"{self.log_prefix}: Error fetching incidents: {e}")
            return []

    def get_incident_extra_data(self, incident_id: str, alerts_limit: int):
        try:
            extra_data = incidents_api.get_incident_extra_data(incident_id, alerts_limit)
            return extra_data['reply']
        except Exception as e:
            self.logger.error(f"{self.log_prefix}: Error fetching extra data for incident {incident_id}: {e}")
            return None

    def process_incidents(self):
        while True:
            incidents = self.fetch_incidents()
            for incident in incidents:
                self.palo_alto_cortex_helper.process_incident(incident)
                # Fetch and process extra data for each incident if needed
                extra_data = self.get_incident_extra_data(incident['incident_id'], alerts_limit=10)
                if extra_data:
                    # Procesar datos adicionales
                    self.logger.info(f"Extra data for incident {incident['incident_id']}: {extra_data}")
            time.sleep(fetch_interval)
