# 🚀 Despliegue en Streamlit Community Cloud

Guía rápida para publicar OmniScanner en producción.

## URLs del proyecto

| Recurso | URL |
|---------|-----|
| App pública | `https://omniscanner-sigmac.streamlit.app` |
| Subdominio corporativo | `https://omniscanner.io.sigmac.com.mx` |
| Redirect URI OAuth | `https://omniscanner-sigmac.streamlit.app/oauth2callback` |
| Google Cloud Project | Proyecto **nuevo exclusivo para OmniScanner** (ver Paso 1) |

---

## Pasos de despliegue

### 1. Crear nuevo OAuth Client ID en Google Cloud Console

OmniScanner usa su **propio** proyecto OAuth (independiente del proyecto IAOps).

1. Ve a [console.cloud.google.com](https://console.cloud.google.com)
2. Crea un **nuevo proyecto** → nómbralo `OmniScanner-Sigmac` (o usa uno existente vacío)
3. Ve a **APIs & Services → OAuth consent screen**:
   - User Type: **External**
   - App name: `OmniScanner — Sigmac Corp`
   - User support email: `ragde83@gmail.com`
   - Scopes: agregar `email` y `profile`
   - Test users: agregar `ragde83@gmail.com`
4. Ve a **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**:
   - Application type: **Web application**
   - Name: `OmniScanner Web`
   - **Authorized JavaScript origins** → (SIN path, SIN barra al final):
     ```
     https://omniscanner-sigmac.streamlit.app
     ```
   - **Authorized redirect URIs** → (CON el path `/oauth2callback`):
     ```
     https://omniscanner-sigmac.streamlit.app/oauth2callback
     ```
   > ⚠️ Son dos campos separados. El error *"URIs must not contain a path"* aparece
   > si pones `/oauth2callback` en **JavaScript origins** — ese campo solo acepta la URL base.
5. Copia el **Client ID** y **Client Secret** → los usas en el Paso 3


### 2. Streamlit Community Cloud
- [share.streamlit.io](https://share.streamlit.io) → New app → este repo → `app.py`

### 3. Secrets en Streamlit Cloud
En **App → Settings → Secrets**:
```toml
[auth]
redirect_uri        = "https://omniscanner-sigmac.streamlit.app/oauth2callback"
cookie_secret       = "TU_COOKIE_SECRET_32_CHARS"
client_id           = "625399507015-ordofgt88rveq8h5v59mkj9fnemp30ko.apps.googleusercontent.com"
client_secret       = "TU_GOOGLE_CLIENT_SECRET"
server_metadata_url = "https://accounts.google.com/.well-known/openid-configuration"

[access]
allowed_emails = "ragde83@gmail.com"
```

### 4. CNAME en Hostgator cPanel
```
omniscanner.io.sigmac.com.mx  →  CNAME  →  omniscanner-sigmac.streamlit.app
```

### 5. Cron Job en Hostgator (anti-hibernación)
En cPanel → Cron Jobs → cada 12 horas:
```bash
curl -s https://omniscanner-sigmac.streamlit.app > /dev/null 2>&1
```

---

## Agregar nuevos usuarios
Editar en Streamlit Cloud → Settings → Secrets:
```toml
[access]
allowed_emails = "ragde83@gmail.com,nuevo@gmail.com"
```

> ⚠️ El archivo `.streamlit/secrets.toml` local está en `.gitignore` y NUNCA debe subirse a GitHub.
