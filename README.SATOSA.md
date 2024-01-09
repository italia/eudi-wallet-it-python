# SATOSA backend setup

To install the OpenID4VP SATOSA backend you just need to:

1. install this package and the extra dependencies: `pip install pyeudiw[satosa]`
2. copy and customize [example/satosa/pyeudiw_backend.yaml](example/satosa/pyeudiw_backend.yaml)
3. copy and customize the content of the folders [static](example/satosa/static) and [templates](example/satosa/templates) to your satosa deployment.
4. include the backend configuration in your satosa configuration
5. customize the file `internal_attributes.yaml` used in your deployment, enabling the `openid4vp` protocol. See [example/satosa/internal_attributes.yaml](example/satosa/internal_attributes.yaml) as example. 
6. start Satosa.

## Backend configuration

1. Customize [example/satosa/pyeudiw_backend.yaml](example/satosa/pyeudiw_backend.yaml), then copy it in your satosa `plugins/backend` project folder. Example `plugins/backends/pyeudiw_backend.yaml`;
2. Add `  - "plugins/backends/pyeudiw_backend.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section `BACKEND_MODULES`;
3. Add `  - "plugins/microservices/disco_to_target_issuer.yaml"` and `  - "plugins/microservices/target_based_routing.yaml"` in your SATOSA `proxy_conf.yaml` file, within the section `MICRO_SERVICES`;
4. In `plugins/microservices/target_based_routing.yaml` please add `    "https://eudi.wallet.gov.it": "OpenID4VP"`
5. Customize [example/satosa/static/disco.html](example/satosa/static/disco.html), then copy it in satosa static file folder. Example `example/static/static/disco.html`
6. Customize [example/satosa/templates/*.html](example/satosa/templates/*.html), then copy it in satosa templates file folder (the path your have configured in your `pyeudiw_backend.yaml` file).
7. Customize [example/satosa/internal_attributes.yaml](example/satosa/internal_attributes.yaml), then copy it the path your have configured in your `proxy_conf.yaml` file).

### Backend Configuration Parameters

TBD. A Markdown table with:

 - parameter name
 - description
 - example value 

## NginX

Configure an httpd fronted such NginX, an example is available within the `uwsgi_setup` folder of [Satosa-Saml2Spid](https://github.com/italia/Satosa-Saml2Spid/tree/master/example/uwsgi_setup) 
remember to customize and add any additional parameter to your preferred httpd configuration.


