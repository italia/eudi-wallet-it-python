import os
import pkgutil
import subprocess
import sys

import integration_test


def _discover_test_modules(package):
    package_path = package.__path__[0]
    runner_filename = os.path.basename(__file__)

    test_modules = []
    for module in pkgutil.iter_modules([package_path]):
        if module.ispkg:
            continue

        module_file = f"{module.name}.py"
        if module_file == runner_filename:
            continue

        full_path = os.path.join(package_path, module_file)
        if os.path.isfile(full_path):
            test_modules.append(f"{package.__name__}.{module.name}")
    return test_modules

def _run_tests_sequentially(test_module_names):
    has_failure = False

    for module in test_module_names:
        module_path = module.replace(".", "/") + ".py"
        print(f"\n▶️ Running: {module}")
        result = subprocess.run([sys.executable, module_path])

        if result.returncode == 0:
            print(f"✅ {module} passed")
        elif result.returncode == 3:
            print(f"⏭️ {module} skipped (deprecated test)")
        else:
            print(f"❌ {module} failed with exit code {result.returncode}")
            has_failure = True

    if has_failure:
        print("❌ TEST FAILURE: Some tests did not pass.")
        print("Please check the output above for details.")
        sys.exit(1)
    else:
        print("✅ All tests passed successfully!")
        sys.exit(0)

if __name__ == "__main__":
    test_modules = _discover_test_modules(integration_test)
    print("📦 Found test modules:", test_modules)
    _run_tests_sequentially(test_modules)
