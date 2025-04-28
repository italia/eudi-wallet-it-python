import re
from typing import List, Dict, Union


class AttributeMapper:
    """
    Configuration for mapping JSON paths to attributes.
    It defines how to extract values from JSON data and where to map them.
    """
    def __init__(self, mappings: List[Dict[str, str]]):
        self.mappings = mappings

    def get_mappings(self):
        """
        Returns the list of mappings.
        """
        return self.mappings

    def add_mapping(self, src_path: str, dest_path: str):
        """
        Adds a new mapping to the configuration.
        """
        self.mappings.append({src_path: dest_path})

    def apply_mappings(self, data: List[Dict[str, Union[str, dict, list]]]):
        """
        Applies the mappings to the given data (JSON).
        Extracts values based on the mapping configuration and returns the results.
        """
        # Flatten the credentials data
        flat_data = self.flatten_data(data)
        print("Dati appiattiti:", flat_data)
        mapped_data = {}

        # Loop through each mapping in the presentation config
        for mapping in self.mappings:
            for src_pattern, dest_path in mapping.items():
                # Dividi il pattern in base al carattere jolly
                parts = src_pattern.split('[*]')
                if len(parts) == 2:
                    # Escapa la parte prima e la parte dopo il jolly
                    prefix = re.escape(parts[0])
                    suffix = re.escape(parts[1])
                    # Costruisci la regex con la parte per l'indice
                    regex_pattern = f"{prefix}\\[\\d+\\]{suffix}$"
                    print(f"Pattern sorgente: {src_pattern}, Regex generata: {regex_pattern}")

                    extracted_values = []
                    for flat_key, value in flat_data.items():
                        if re.match(regex_pattern, flat_key):
                            extracted_values.append(value)
                            print(f"Trovata corrispondenza! Chiave: {flat_key}, Valore: {value}")

                    if extracted_values:
                        if '.' not in dest_path:
                            if len(extracted_values) == 1:
                                mapped_data[dest_path] = extracted_values[0]
                            else:
                                mapped_data[dest_path] = extracted_values
                        else:
                            self.set_nested_value(mapped_data, dest_path, extracted_values[0] if len(extracted_values) == 1 else extracted_values)
                else:
                    # Se non c'è il carattere jolly, usa la logica precedente (dovrebbe essere raro in questo scenario)
                    regex_pattern = re.escape(src_pattern) + '$'
                    print(f"Pattern sorgente (senza jolly): {src_pattern}, Regex generata: {regex_pattern}")
                    for flat_key, value in flat_data.items():
                        if re.match(regex_pattern, flat_key):
                            if '.' not in dest_path:
                                mapped_data[dest_path] = value
                            else:
                                self.set_nested_value(mapped_data, dest_path, value)

        return mapped_data

    def flatten_data(self, data: List[Dict[str, Union[str, dict, list]]]):
        """
        Flattens the given JSON-like data into a flat dictionary with dot-separated keys.
        """
        flat_dict = {}
        for i, credential in enumerate(data):
            self.flatten_object(credential, f"credentials[{i}]", flat_dict)
        return flat_dict

    def flatten_object(self, obj: Union[dict, list, str, int, float, bool, None], prefix: str, flat_dict: dict):
        """
        Recursively flattens the object and adds keys with dot notation to flat_dict.
        Gestisce anche i casi in cui il valore non è un dizionario o una lista.
        """
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_key = f"{prefix}.{key}" if prefix else key
                self.flatten_object(value, new_key, flat_dict)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self.flatten_object(item, f"{prefix}[{i}]", flat_dict)
        else:
            flat_dict[prefix] = obj

    def set_nested_value(self, dict_obj: dict, path: str, value: Union[str, dict, list]):
        """
        Set the value in the destination path, creating nested structures if needed.
        """
        keys = path.split('.')
        temp = dict_obj

        for key in keys[:-1]:
            temp = temp.setdefault(key, {})

        temp[keys[-1]] = value