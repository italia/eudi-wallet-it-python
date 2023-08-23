# SATOSA backend setup

To install the OpenID4VP SATOSA backend you just need to:

1. install this package and the extra dependencies: `pip install pyeudiw[satosa]`
2. copy and customize [example/pyeudiw_backend.yml](example/pyeudiw_backend.yml)
3. copy and customize the content of the folders [static](example/satosa/static) and [templates](example/satosa/) to your satosa deployment.
4. include the backend configuration in your satosa configuration
5. customize the file `internal_attributes.yaml` used in your deployment, enabling the `openid4vp` protocol. See [example/satosa/internal_attributes.yaml](example/satosa/internal_attributes.yaml) as example. 
6. start Satosa.
7. configure an httpd fronted such NginX, see `uwsgi_setup` folder within the Satosa-Saml2Spid or integrate any additional parameter to your configuration, according to the `uwsgi_setup` examples distributes in Satosa-Saml2Spid.

## Backend configuration

1. Customize [example/satosa/pyeudiw_backend.yaml](example/satosa/pyeudiw_backend.yaml), then copy it in your satosa `plugins/backend` project folder. Example `plugins/backends/pyeudiw_backend.yaml`;
2. Add `  - "plugins/backends/pyeudiw_backend.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section `BACKEND_MODULES`;
3. Add `  - "plugins/microservices/disco_to_target_issuer.yaml"` and `  - "plugins/microservices/target_based_routing.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section `MICRO_SERVICES`;
4. In `plugins/microservices/target_based_routing.yaml` please add `    "https://eudi.wallet.gov.it": "OpenID4VP"`
5. Customize  [example/satosa/disco.html](example/satosa/disco.html), then copy it in satosa static file folder. Example `example/static/disco.html`

### Backend Configuration Parameters

TBD. A Markdown table with:

 - parameter name
 - description
 - example value 

## NginX

TBD.


