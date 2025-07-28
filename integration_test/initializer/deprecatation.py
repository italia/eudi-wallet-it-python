import os
import sys

_INTEGRATION_TEST_README_PATH = "integration_test/README.md"
_PYTHONPATH = os.environ.get("PYTHONPATH", "")
_RUN_DEPRECATED = os.environ.get("RUN_DEPRECATED", "").strip().lower()

def _readme_link() -> str:
    root_path = _PYTHONPATH.split(os.pathsep)[0] if _PYTHONPATH else ""
    if root_path and os.path.isdir(root_path):
        abs_path = os.path.abspath(os.path.join(root_path, _INTEGRATION_TEST_README_PATH))
    else:
        abs_path = os.path.abspath(_INTEGRATION_TEST_README_PATH)
    return f"file://{abs_path}"

def show_deprecation_warning():
    if _RUN_DEPRECATED == "true":
        print("⚠️  RUN_DEPRECATED=true → skipping manual confirmation (running anyway).")
        return

    message = (
            "\n⚠️  WARNING: This integration test is deprecated.\n"
            "It does not follow the latest requirements and must be updated.\n"
            f"📄 See: {_readme_link()}\n"
            "Do you still want to run it? [Y/N]: "
        )
    response = input(message).strip().lower()
    if response not in ("y", "yes"):
        print("❌ Execution aborted.")
        sys.exit(1)
