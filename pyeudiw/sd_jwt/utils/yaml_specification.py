import sys
from io import TextIOWrapper
from typing import Union

import yaml

from pyeudiw.sd_jwt.common import SDObj


class _SDKeyTag(yaml.YAMLObject):
    """
    YAML tag for selective disclosure keys.

    This class is used to define a custom YAML tag for selective disclosure keys. This tag is used to indicate
    that a key in a YAML mapping is a selective disclosure key, and that its value should be parsed as a selective
    disclosure object.
    """

    yaml_tag = "!sd"

    @classmethod
    def from_yaml(cls, loader, node):
        # If this is a scalar node, it can be a string, int, float, etc.; unfortunately, since we tagged
        # it with !sd, we cannot rely on the default YAML loader to parse it into the correct data type.
        # Instead, we must manually resolve it.
        if isinstance(node, yaml.ScalarNode):
            # If the 'style' is '"', then the scalar is a string; otherwise, we must resolve it.
            if node.style == '"':
                mp = loader.construct_yaml_str(node)
            else:
                resolved_type = yaml.resolver.Resolver().resolve(
                    yaml.ScalarNode, node.value, (True, False)
                )
                if resolved_type == "tag:yaml.org,2002:str":
                    mp = loader.construct_yaml_str(node)
                elif resolved_type == "tag:yaml.org,2002:int":
                    mp = loader.construct_yaml_int(node)
                elif resolved_type == "tag:yaml.org,2002:float":
                    mp = loader.construct_yaml_float(node)
                elif resolved_type == "tag:yaml.org,2002:bool":
                    mp = loader.construct_yaml_bool(node)
                elif resolved_type == "tag:yaml.org,2002:null":
                    mp = None
                else:
                    raise Exception(
                        f"Unsupported scalar type for selective disclosure (!sd): {resolved_type}; node is {node}, style is {node.style}"
                    )
            return SDObj(mp)
        elif isinstance(node, yaml.MappingNode):
            return SDObj(loader.construct_mapping(node))
        elif isinstance(node, yaml.SequenceNode):
            return SDObj(loader.construct_sequence(node))
        else:
            raise Exception(
                "Unsupported node type for selective disclosure (!sd): {}".format(
                    node
                )
            )

def yaml_load_specification_with_placeholder(file_buffer: TextIOWrapper):
    parsed = yaml.load(file_buffer, Loader=yaml.FullLoader) # nosec B506

    convert = lambda obj: (
        {(f"{{{{ {k.value} }}}}" if isinstance(k, SDObj) else k): convert(v)  for k, v in obj.items()}
        if isinstance(obj, dict)
        else [convert(i) for i in obj]
        if isinstance(obj, list)
        else (f"{{{{ {obj.value} }}}}" if isinstance(obj, SDObj) else obj)
    )

    return convert(parsed)

def yaml_load_specification(file_buffer: TextIOWrapper):
    return yaml.load(file_buffer, Loader=yaml.FullLoader)  # nosec

def load_yaml_specification(file_path: str) -> dict:
    """
    Load a YAML specification file and return the parsed content.

    :param file_path: Path to the YAML file.
    :type file_path: str

    :returns: The parsed content of the YAML file.
    :rtype: dict
    """

    # create new resolver for tags
    with open(file_path, "r") as f:
        example = yaml_load_specification(f)

    for property in ("user_claims", "holder_disclosed_claims"):
        if property not in example:
            sys.exit(f"Specification file must define '{property}'.")

    return example

def remove_sdobj_wrappers(data: Union[SDObj, dict, list, any]) -> Union[dict, list, any]:
    """
    Recursively remove SDObj wrappers from the data structure.

    :param data: The data structure to remove SDObj wrappers from.
    :type data: SDObj | dict | list | any

    :returns: The data structure with SDObj wrappers removed.
    :rtype: dict | list | any
    """

    if isinstance(data, SDObj):
        return remove_sdobj_wrappers(data.value)
    elif isinstance(data, dict):
        return {
            remove_sdobj_wrappers(key): remove_sdobj_wrappers(value)
            for key, value in data.items()
        }
    elif isinstance(data, list):
        return [remove_sdobj_wrappers(value) for value in data]
    else:
        return data
