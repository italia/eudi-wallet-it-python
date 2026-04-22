# tools.qrcode — QR Code Creation for Wallet Flows

The QR code functionality is used within SATOSA to display QR codes for **cross-device flows** in both OpenID4VP (Relying Party) and OpenID4VCI (Credential Issuer) setups. The QR code is rendered in HTML templates using a client-side web component; the payload is prepared by pyeudiw and passed to the template.

## Where QR Codes Are Used

- **OpenID4VP backend** (`PreRequestHandler`): Cross-device flow shows a QR code with the authorization/response URL for the wallet to scan.
- **OpenID4VCI frontend** (`CredentialOfferQrCodeHandler`): Credential offer by QR code, where the payload is the credential offer URI.

## Configuration

QR code settings are configured in the SATOSA backend/frontend YAML under `config.qrcode`:

```yaml
qrcode:
  size: 250              # Size in pixels
  color: "#0072CE"       # Hex color for QR modules
  expiration_time: 120   # Seconds until expiration
  logo_path: "it-wallet/wallet-icon-blue.svg"  # Logo in center (relative to static_storage_url)
  ui:
    static_storage_url: "https://localhost/static"
    template_folder: "templates"
    qrcode_template: "qr_code.html"
    authorization_error_template: "authorization_error.html"
```

## Template Variables

When rendering the QR code page, these variables are passed to the template:

| Variable | Description |
|----------|-------------|
| `qrcode_text` | The URL or payload to encode (e.g. response URL or credential offer URI) |
| `qrcode_size` | Size in pixels |
| `qrcode_color` | Hex color |
| `qrcode_logo_path` | Path to logo |
| `qrcode_expiration_time` | Expiration in seconds |
| `state` | Session/state for polling |
| `status_endpoint` | Endpoint for status polling (OpenID4VP) |

## Example Template (Jinja2)

Your `qr_code.html` template should include a component that encodes `qrcode_text` into a QR code. Example using Bootstrap Italia's `qr-code` web component:

```html
<qr-code
    contents="{{ qrcode_text }}"
    module-color="{{ qrcode_color }}"
    position-ring-color="{{ qrcode_color }}"
    position-center-color="{{ qrcode_color }}"
    style="width: {{ qrcode_size }}px; height: {{ qrcode_size }}px;"
>
    <img src="{{ static }}{{ qrcode_logo_path }}" slot="icon" />
</qr-code>
```

## Programmatic Access

The QR code payload is generated internally by:

- **OpenID4VP**: `PreRequestHandler._cross_device_http_response(response_url, state)` — builds the page with `qrcode_text=response_url`.
- **OpenID4VCI**: `CredentialOfferQrCodeHandler.to_qr_code_response(entity)` — builds the page with `qrcode_text=entity.redirect_uri`.

If you need to create a standalone QR code (e.g. for testing or custom flows), use a library like `qrcode` or `segno`:

```python
import qrcode

# Example: create QR for credential offer URI
uri = "openid-credential-offer://?..."
img = qrcode.make(uri)
img.save("credential_offer.png")
```
