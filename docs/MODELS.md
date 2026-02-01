# Models

To automatically generate a Pydantic model, 
[datamodel-code-generator](https://github.com/koxudaxi/datamodel-code-generator/) can be used.

To install it, simply run:

```bash
$ pip install datamodel-code-generator
```

It is possible to generate a file from a remote file without downloading it as follows:

```bash
$ datamodel-codegen --url https://raw.githubusercontent.com/openid/oid4vc-haip-sd-jwt-vc/main/schemas/presentation_definition.json --output pyeudiw/presentation_exchange/schemas/oid4vc_presentation_definition.py  --output-model-type pydantic_v2.BaseModel
```
