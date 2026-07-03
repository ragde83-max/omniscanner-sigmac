# OmniScanner AI (Sigmac Corp) - Documentación Completa y Disaster Recovery

Esta documentación ha sido creada como **medida de contingencia y respaldo** (Disaster Recovery). Si el disco duro falla o se necesita migrar el proyecto a una nueva computadora, sigue las instrucciones de este archivo para levantar el proyecto desde cero.

---

## 1. ¿Qué es este proyecto?
**OmniScanner AI** es una plataforma desarrollada en Python (usando el framework Streamlit) para la consolidación, análisis y generación de reportes premium de ciberseguridad. Toma archivos XML de herramientas como ZAP, BurpSuite y Wapiti, y utiliza **Google Gemini 2.5 Pro** para analizar vulnerabilidades, eliminar falsos positivos y entregar reportes C-Level y Técnicos en formato HTML.

## 2. Estructura del Proyecto
Los archivos y carpetas vitales que conforman este proyecto son:

- `app.py`: El núcleo de la aplicación. Contiene la interfaz de Streamlit, la lógica de integración con Google Gemini, el parser de Markdown y el generador de reportes HTML.
- `requirements.txt`: Archivo indispensable que lista las dependencias de Python (librerías como `streamlit`, `google-genai`, `matplotlib`, `plotly`, etc.).
- `.streamlit/secrets.toml`: **[¡IMPORTANTE!]** Contiene las credenciales y la API Key de Gemini. Este archivo **no** se sube a GitHub por seguridad, por lo que debes respaldar tu API Key por separado.
- `MEMORIA_TECNICA.md`: Documentación detallada de los últimos cambios y mejoras a nivel de código y lógica.
- `DEPLOY_GUIDE.md` y `CONTENEDORES_SIGMAC_IAOPS.md`: Guías adicionales para despliegue y uso de contenedores.
- `.devcontainer/`: Configuración para abrir el entorno en Docker (VS Code Dev Containers).
- Archivos `.xml`: Ejemplos y resultados de escáneres usados como fuentes de prueba.

---

## 3. Guía de Recuperación ante Desastres (Disaster Recovery)

### Paso 1: Recuperar el código fuente
Afortunadamente, el proyecto está vinculado a un repositorio remoto en GitHub (`https://github.com/ragde83-max/omniscanner-sigmac.git`). 
En una computadora nueva, instala [Git](https://git-scm.com/) y ejecuta:
```bash
git clone https://github.com/ragde83-max/omniscanner-sigmac.git
cd omniscanner-sigmac
```

### Paso 2: Instalar Python y Dependencias
1. Descarga e instala **Python 3.10 o superior** (asegúrate de marcar "Add Python to PATH" durante la instalación).
2. Abre una terminal dentro de la carpeta del proyecto.
3. Se recomienda crear un entorno virtual para no contaminar el sistema:
```bash
python -m venv venv
# Activar entorno (Windows):
venv\Scripts\activate
# Activar entorno (Mac/Linux):
source venv/bin/activate
```
4. Instala las librerías necesarias ejecutando:
```bash
pip install -r requirements.txt
```

### Paso 3: Configurar Credenciales y Secrets
Dado que las credenciales no deben vivir en GitHub, deberás recrear la carpeta de configuración local:
1. Crea una carpeta llamada `.streamlit` en la raíz del proyecto.
2. Dentro, crea un archivo llamado `secrets.toml`.
3. Escribe dentro la configuración necesaria (reemplazando con tus claves reales):
```toml
# Ejemplo de .streamlit/secrets.toml
GEMINI_API_KEY = "TU_API_KEY_AQUI"

[google_oauth]
client_id = "TU_CLIENT_ID"
client_secret = "TU_CLIENT_SECRET"
redirect_uri = "TU_REDIRECT_URI"
```
> **Nota:** Guarda tu `GEMINI_API_KEY` en un gestor de contraseñas (como 1Password, Bitwarden o Google Password Manager) por si pierdes este equipo físico.

### Paso 4: Ejecutar la Aplicación
Con las dependencias instaladas y los *secrets* configurados, simplemente arranca el servidor local:
```bash
streamlit run app.py
```
Se abrirá automáticamente tu navegador (típicamente en `http://localhost:8501`) con la aplicación funcionando al 100%.

---

## 4. Medidas de Prevención Inmediatas (Action Items)

Para que este plan funcione si el disco duro falla **HOY**, debes asegurarte de subir (hacer *push*) todo el código actual a GitHub. 

Abre la terminal y ejecuta estos 3 comandos:
```bash
git add .
git commit -m "docs: Respaldo completo del proyecto y documentacion de recuperacion"
git push origin main
```
*(Cambia `main` por el nombre de tu rama si es distinta, por ejemplo `master`).*

Si ejecutas el `git push`, tu trabajo estará a salvo en la nube de GitHub, y esta guía te servirá como mapa para reconstruirlo en cualquier parte del mundo.
