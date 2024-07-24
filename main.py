"""
BSD 3-Clause License

[License text omitted for brevity]

CTE Cortex XDR Incidents Plugin main file which contains the implementation of all the plugin's methods.
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
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from cortex_xdr_incidents_plugin_constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_CHECKPOINT,
    PLUGIN_NAME,
    PLUGIN_VERSION,
)
from cortex_xdr_incidents_plugin_helper import (
    CortexXDRIncidentsPluginHelper,
    PaloAltoCortexNetworksXDRPluginException,
)

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

class CortexXDRIncidentsPlugin(PluginBase):
    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.cortex_xdr_helper = CortexXDRIncidentsPluginHelper(
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
                self.cortex_xdr_helper.process_incident(incident)
                extra_data = self.get_incident_extra_data(incident['incident_id'], alerts_limit=10)
                if extra_data:
                    self.logger.info(f"Extra data for incident {incident['incident_id']}: {extra_data}")
            time.sleep(fetch_interval)

    def _validate_auth_params(self, configuration) -> ValidationResult:
        """Validate the authentication params with Palo Alto Cortex XDR platform."""
        try:
            self.logger.debug(f"{self.log_prefix}: Validating auth credentials.")
            base_url = configuration.get("base_url", "").strip().strip("/")
            headers = self._authorize_request(configuration=configuration)
            payload = json.dumps({
                "request_data": {
                    "filters": [],
                    "search_from": 0,
                    "search_to": 1,
                }
            })
            url = f"{base_url}/public_api/v1/incidents/get_incidents/"
            logger_msg = "validating auth credentials"
            response = self.cortex_xdr_helper.api_helper(
                url=url,
                method="POST",
                headers=headers,
                data=payload,
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=False,
                logger_msg=logger_msg,
            )
            if response.status_code == 200:
                self.logger.debug(f"{self.log_prefix}: Successfully validated auth credentials and plugin configuration.")
                return ValidationResult(success=True, message=f"Validation successful for {PLUGIN_NAME} plugin configuration.")
            elif response.status_code == 400:
                err_msg = "Received exit code 400. Resource not found. Verify FQDN Key provided in the configuration parameters."
                self.logger.error(message=f"{self.log_prefix}: {err_msg}", details=str(response.text))
                return ValidationResult(success=False, message=err_msg)
            elif response.status_code == 401:
                err_msg = "Received exit code 401, Unauthorized access. Verify API Key, API Key ID and Authentication Method provided in the configuration parameters."
                self.logger.error(message=f"{self.log_prefix}: {err_msg}", details=str(response.text))
                return ValidationResult(success=False, message=err_msg)
            elif response.status_code == 403:
                err_msg = "Received exit code 403, Forbidden access. Verify API Key provided in the configuration parameters."
                self.logger.error(message=f"{self.log_prefix}: {err_msg}", details=str(response.text))
                return ValidationResult(success=False, message=err_msg)
            self.cortex_xdr_helper.handle_error(resp=response, logger_msg=logger_msg)
        except PaloAltoCortexNetworksXDRPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(message=f"{self.log_prefix}: {err_msg}", details=str(traceback.format_exc()))
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(message=f"{self.log_prefix}: {err_msg} Error: {exp}", details=str(traceback.format_exc()))
            return ValidationResult(success=False, message=f"{err_msg} Check logs for more details.")

    def _authorize_request(self, configuration: Dict) -> Dict:
        """Authorize request on the basis of Authentication Method."""
        headers = {"Content-Type": "application/json"}
        auth_method = configuration.get("auth_method")
        api_key = configuration.get("api_key")
        api_key_id = configuration.get("api_key_id")
        if auth_method == "standard":
            headers.update({"x-xdr-auth-id": str(api_key_id), "Authorization": api_key})
            return headers
        elif auth_method == "advanced":
            nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
            timestamp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) * 1000
            auth_key = "%s%s%s" % (api_key, nonce, timestamp)
            auth_key = auth_key.encode("utf-8")
            api_key_hash = hashlib.sha256(auth_key).hexdigest()
            headers.update({
                "x-xdr-timestamp": str(timestamp),
                "x-xdr-nonce": nonce,
                "x-xdr-auth-id": str(api_key_id),
                "Authorization": api_key_hash,
            })
            return headers
        else:
            err_msg = "Invalid Authentication Method found in the configuration parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise PaloAltoCortexNetworksXDRPlugin
