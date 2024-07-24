import logging

class CortexXDRIncidentsPluginHelper:
    def __init__(self, logger: logging.Logger, log_prefix: str, plugin_name: str, plugin_version: str):
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def log_info(self, message: str):
        self.logger.info(f"{self.log_prefix}: {message}")

    def log_error(self, message: str):
        self.logger.error(f"{self.log_prefix}: {message}")

    def log_debug(self, message: str):
        self.logger.debug(f"{self.log_prefix}: {message}")

    def process_incident(self, incident):
        try:
            self.log_info(f"Processing incident {incident['incident_id']}")
            incident_id = incident.get("incident_id")
            description = incident.get("description")
            self.log_debug(f"Incident ID: {incident_id}, Description: {description}")

            # Additional processing logic can be added here

        except Exception as e:
            self.log_error(f"Error processing incident: {str(e)}")
