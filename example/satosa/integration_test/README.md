# Integration Test

This integration test will verify a full authentication flow of a simulated IT-Wallet with the provided Openid4VP Relying Party.

## Requirements

### Environment

An up an running Openid4VP Relying Party is a requirement of this project.
The intended Relying Party of this integration test is the example one provided in the repository [https://github.com/italia/Satosa-Saml2Spid](https://github.com/italia/Satosa-Saml2Spid).
That project will provide full instruction on how to setup such an environment with Docker.

Before starting, make sure that the `pyeudiw_backend.yaml` is properly configured and included in the file `proxy_conf.yaml` that is running in your Docker environment.
This project folder always provide up to date example of the pyeudiw plugin configuration in the file [pyeudiw_backend.yaml](./pyeudiw_backend.yaml), as well as other configuration file of the module in [static](./static/) and [template](./template/) folders.

#### MongoDB Configuration for Tests

The MongoDB connection is configured dynamically using the environment variable `PYEUDIW_MONGO_TEST_AUTH_INLINE`.

#### How It Works
- The value of `PYEUDIW_MONGO_TEST_AUTH_INLINE` should be in the format `username:password@`.
- If the variable is not set, the configuration defaults to:
  - **Authentication**: Defaults to empty string.
  - **MongoDB URL**: `mongodb://satosa:localhost:27017/?timeoutMS=2000`.

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

## Usage

To execute the integration tests

    python same_device_integration_test.py
    python cross_device_integration_test.py
