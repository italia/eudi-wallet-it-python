# Integration Test

These integration tests verify full end-to-end flows for multiple scenarios involving the simulated IT-Wallet and
various relying party or issuer configurations.

## Requirements

### Environment

A running environment for the specific scenario under test is required.  
Each integration test may target a different relying party, credential issuer, or module setup.

For example, the `OpenID4VP Relying Party` integration scenario uses the [Satosa-Saml2Spid](https://github.com/italia/Satosa-Saml2Spid) repository as its reference relying party.  
Refer to the [documentation](../README.md) of each service to set up the required Docker or local environment.

Before running a test, ensure that the relevant configuration files (e.g., `pyeudiw_backend.yaml`) are correctly included in your service configuration (e.g., `proxy_conf.yaml`) and mounted in your environment.  
This project provides example configurations for each scenario:
- [pyeudiw_backend.yaml](./conf/pyeudiw_backend.yaml) (sample plugin configuration)
- [internal_attributes.yaml](./conf/internal_attributes.yaml) (to link modules and handlers, carrying user data and authentication context)
- Additional static and template files: [static/](./static/), [templates/](./templates/)

Each integration test script may have its own expected configuration files.  
Check the comments or README of each script for details.

#### RP base URL

By default, tests connect to the Relying Party at `https://localhost`. If your RP runs on a different host or port (e.g. Docker Compose with nginx on another port), set:

- `PYEUDIW_IDP_BASEURL` – base URL of the IdP/Satosa (e.g. `https://localhost:443`, `http://localhost:10000`)
- `PYEUDIW_RP_EID` – (optional) OpenID4VP entity URL; defaults to `{PYEUDIW_IDP_BASEURL}/OpenID4VP`

#### MongoDB Configuration for Tests

The MongoDB connection is configured dynamically using the environment variable `PYEUDIW_MONGO_TEST_AUTH_INLINE`.

#### How It Works
- The value of `PYEUDIW_MONGO_TEST_AUTH_INLINE` should be in the format `username:password@`.
- If the variable is not set, the configuration defaults to:
  - **Authentication**: Defaults to empty string.
  - **MongoDB URL**: `mongodb://localhost:27017/?timeoutMS=2000`.

#### Example Usage
1. **With Authentication**:
   Set the environment variable:
   ```bash
   export PYEUDIW_MONGO_TEST_AUTH_INLINE="satosa:thatpassword@"
   ```

   or just using `.env` file

#### Custom Behavior
You can override the default credentials by setting the environment variable:

```bash
export PYEUDIW_MONGO_TEST_AUTH_INLINE="customuser:custompassword@"
```

### Dependencies

Requirements exclusive to the integration test can be installed with

    pip install -r requirements_test.txt

To complete installation, the following command are required

    playwright install

**NOTE**: Installation might fail on a virtual or Windows environment as playwirght assumes that your environment con run a browser, which might not be the case on virtual machines or other minimal virtual environment. If installation fails, try with `playwright install-deps` or go to the check the official [playwright docs](https://playwright.dev/python/docs/intro#installing-playwright-pytest).

## Structure

This project provides multiple integration test scripts, each covering a different scenario.

| Script                                   | Configurations                                                                                                                                                                                                                                                                                | Description                                                                                                                                                                               |
|------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `same_device_integration_test.py`        | Use the default [pyeudiw_backend.yaml](./conf/pyeudiw_backend.yaml) (DCQL/Duckle flow).                                                                 | Same-device authentication flow with an OpenID4VP relying party.                                                                                                                         |
| `cross_device_integration_test.py`       | Use the default [pyeudiw_backend.yaml](./conf/pyeudiw_backend.yaml) (DCQL/Duckle flow).                                                                 | Cross-device authentication flow, e.g., mobile to desktop.                                                                                                                               |
| `user_denies_end_to_end_test.py`         | Use the custom [pyeudiw_backend.yaml](./conf/potential/wp2uc1/userdenies/pyeudiw_backend.yaml) (DCQL/Duckle flow).                                                                                                            | User denies sharing credentials; tests the OpenID4VP Authorization Error Response (same- and cross-device).                                                                              |

> ℹ️ **Note:** All tests use the **DCQL (Duckle) flow** with `config.dcql_query`. The default [pyeudiw_backend.yaml](./conf/pyeudiw_backend.yaml) is ready to run same-device and cross-device tests without any modification.  


## Usage

To execute the integration tests:

    python same_device_integration_test.py
    python cross_device_integration_test.py
    python user_denies_end_to_end_test.py

Otherwise, it's possible to run all the tests at once with:

    python runner.py

> ℹ️ **Note:** Before running any test outside of Docker, make sure to set the `PYTHONPATH` to the project root directory.