import sys
if float(f"{sys.version_info.major}.{sys.version_info.minor}") >= 3.12:
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

TrustModuleConfiguration_T = TypedDict("_DynamicTrustConfiguration", {"module": str, "class": str, "config": dict})