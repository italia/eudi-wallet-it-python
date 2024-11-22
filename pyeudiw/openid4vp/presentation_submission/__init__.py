import os
import yaml
import importlib
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class PresentationSubmission:
    def __init__(self, submission: Dict[str, Any]):
        """
        Initialize the PresentationSubmission handler with the submission data.

        Args:
            submission (Dict[str, Any]): The presentation submission data.

        Raises:
            KeyError: If the 'format' key is missing in the submission.
            ValueError: If the format is not supported or not defined in the configuration.
            ImportError: If the module or class cannot be loaded.
        """
        self.config = self._load_config()
        self.submission = submission
        self.handlers = self._initialize_handlers()

    def _load_config(self) -> Dict[str, Any]:
        """
        Load the configuration from format_config.yml located in the same directory.

        Returns:
            Dict[str, Any]: The configuration dictionary.

        Raises:
            FileNotFoundError: If the configuration file is not found.
        """
        config_path = os.path.join(os.path.dirname(__file__), "format_config.yml")
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, "r") as config_file:
            return yaml.safe_load(config_file)

    def _initialize_handlers(self) -> Dict[int, object]:
        """
        Initialize handlers for each item in the 'descriptor_map' of the submission.

        Returns:
            Dict[int, object]: A dictionary mapping indices to handler instances.

        Raises:
            KeyError: If the 'format' key is missing in any descriptor.
            ValueError: If a format is not supported or not defined in the configuration.
            ImportError: If a module or class cannot be loaded.
        """
        handlers = {}

        try:
            descriptor_map = self.submission.get("descriptor_map", [])
        except KeyError:
            raise KeyError("The 'descriptor_map' key is missing in the submission.")

        for index, descriptor in enumerate(descriptor_map):
            format_name = descriptor.get("format")
            if not format_name:
                raise KeyError(f"The 'format' key is missing in descriptor at index {index}.")

            # Search for the format in the configuration
            format_conf = next((fmt for fmt in self.config.get("formats", []) if fmt["name"] == format_name), None)
            if not format_conf:
                raise ValueError(f"Format '{format_name}' is not supported or not defined in the configuration.")

            module_name = format_conf["module"]
            class_name = format_conf["class"]

            try:
                # Dynamically load the module and class
                module = importlib.import_module(module_name)
                cls = getattr(module, class_name)
                handlers[index] = cls()  # Instantiate the class
            except ModuleNotFoundError:
                logger.warning(f"Module '{module_name}' not found for format '{format_name}'. Skipping index {index}.")
            except AttributeError:
                logger.warning(f"Class '{class_name}' not found in module '{module_name}' for format '{format_name}'. Skipping index {index}.")
            except Exception as e:
                logger.warning(f"Error loading format '{format_name}' for index {index}: {e}")

        return handlers
