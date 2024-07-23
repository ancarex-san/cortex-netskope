# Constants for Palo Alto Networks Cortex XDR integration
MODULE_NAME = "Palo Alto Networks Cortex XDR incident"
PLATFORM_NAME = "Cortex XDR incidents"
PLUGIN_NAME = "CortexXDRIncidents"
PLUGIN_VERSION = "1.0.0"
PLUGIN_CHECKPOINT = "cortex_xdr_checkpoint"
FETCH_INTERVAL = 60  # Interval in seconds to fetch incidents

CORTEX_TO_CE_SEVERITY_MAPPING = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

DEFAULT_BATCH_SIZE = 200
INTERNAL_SEVERITY_TO_CORTEX = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "informational",
}

