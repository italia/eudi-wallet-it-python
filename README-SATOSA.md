# SATOSA backend setup


1. Customize [example/satosa/pyeudiw_backend.yaml](example/satosa/pyeudiw_backend.yaml), then copy it in your satosa `plugins/backend` project folder. Example `plugins/backends/pyeudiw_backend.yaml`;
2. Add `  - "plugins/backends/pyeudiw_backend.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section `BACKEND_MODULES`;
3. Add `  - "plugins/microservices/disco_to_target_issuer.yaml"` and `  - "plugins/microservices/target_based_routing.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section `MICRO_SERVICES`;
4. In `plugins/microservices/target_based_routing.yaml` please add `    "https://eudi.wallet.gov.it": "OpenID4VP"`
5. Customize  [example/satosa/disco.html](example/satosa/disco.html), then copy it in satosa static file folder. Example `example/static/disco.html`

Then start the proxy.

# Parameters

TBD. A Markdown table with:

 - parameter name
 - description
 - example value 
