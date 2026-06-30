import streamlit as st
import xml.etree.ElementTree as ET
import matplotlib
matplotlib.use('Agg')  # Vital para servidores en la nube
import matplotlib.pyplot as plt
import numpy as np
import os
import re
import json
import time
import html
import base64
from urllib.parse import urlparse
from datetime import datetime
from google import genai
import tempfile
from jinja2 import Template

# ==========================================
# 1. CONFIGURACIÓN GLOBAL CENTRALIZADA
# ==========================================
# Modelos de IA
MODELO_TRADUCCION = 'gemini-2.5-flash'
MODELO_EJECUTIVO  = 'gemini-2.5-flash'
MODELO_TECNICO    = 'gemini-2.5-pro'   # Pro para mayor profundidad en el análisis técnico

# Tamaños y límites
MAX_HALLAZGOS_EJECUTIVO = 15   # hallazgos en el prompt ejecutivo
MAX_HALLAZGOS_TECNICO   = 30   # hallazgos en el prompt técnico (Pro maneja contexto mayor)
LOTE_TRADUCCION         = 25   # tamaño de lote para traducción completa

# Reintentos con backoff exponencial (mitiga 429 RESOURCE_EXHAUSTED)
# Documentado como problema real en la infraestructura Sigmac-IAOps
REINTENTOS_IA   = 4
ESPERA_BASE_SEG = 6  # backoff: 6s → 12s → 24s → 48s

# --- Paleta corporativa oficial Sigmac Corp ---
COLOR_NAVY  = (15, 27, 45)       # #0F1B2D — banners y portada
COLOR_VERDE = (26, 140, 78)      # #1A8C4E — acentos, gráficas neutras
COLOR_TEXTO = (44, 62, 80)       # #2C3E50 — cuerpo de texto
COLOR_SUAVE = (107, 124, 147)    # #6B7C93 — metadatos, pies de página
COLOR_BORDE = (228, 235, 242)    # #E4EBF2 — líneas divisorias

# --- Paleta semántica de severidad (estándar de industria, independiente de marca) ---
COLORES_SEVERIDAD = {
    "Critical":      (139, 0, 0),
    "High":          (211, 47, 47),
    "Medium":        (245, 124, 0),
    "Low":           (251, 192, 45),
    "Informational": (69, 90, 100),
}

# --- Meses en español (sin depender del locale del sistema operativo) ---
MESES_ES = {
    1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril',
    5: 'mayo', 6: 'junio', 7: 'julio', 8: 'agosto',
    9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'
}


def _hex(rgb):
    """Convierte tupla RGB a string hex para matplotlib."""
    return '#%02x%02x%02x' % rgb


def fecha_larga_es(fecha=None):
    """Fecha en español ('27 de junio de 2026') sin depender del locale del SO.
    strftime('%B') devuelve el mes en inglés en Codespaces/servidores Linux."""
    fecha = fecha or datetime.now()
    return f"{fecha.day} de {MESES_ES[fecha.month]} de {fecha.year}"


# ==========================================
# 2. CONFIGURACIÓN DE PÁGINA
# ==========================================
st.set_page_config(
    page_title="OmniScanner | Sigmac Corp",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# 3. AUTENTICACIÓN GOOGLE (OIDC NATIVO)
# ==========================================
# NOTA DE DESPLIEGUE:
# En Streamlit Community Cloud, el redirect_uri se configura en el panel de Secrets
# de la app (no en este archivo). Streamlit lo lee automáticamente de [auth].redirect_uri.
# Ver guía de despliegue: DEPLOY_GUIDE.md


# Gate de autenticación — bloquea el acceso si no hay sesión activa
if not st.user.is_logged_in:
    if os.path.exists("logo_sigmac.jpg"):
        st.image("logo_sigmac.jpg", width=250)
    st.title("🛡️ OmniScanner — Sigmac Corp")
    st.markdown("### Acceso Restringido — Personal Autorizado")
    st.info("Este sistema es de uso exclusivo para auditores de Sigmac Corp. "
            "Inicia sesión con tu cuenta de Google autorizada para continuar.")
    st.button("🔐 Iniciar Sesión con Google", type="primary", on_click=st.login)
    st.stop()

# Validación por lista de correos autorizados
allowed_raw    = st.secrets.get("access", {}).get("allowed_emails", "")
allowed_emails = [e.strip() for e in allowed_raw.split(",") if e.strip()]
user_email     = st.user.email or ""

if allowed_emails and user_email not in allowed_emails:
    st.error(
        f"⛔ **Acceso denegado.** La cuenta `{user_email}` no está autorizada. "
        f"Contacta al administrador de Sigmac Corp."
    )
    st.button("Cerrar Sesión", on_click=st.logout)
    st.stop()


# ==========================================
# 4. MEMORIA DE SESIÓN
# ==========================================
if 'analisis_completado' not in st.session_state:
    st.session_state.analisis_completado = False
    st.session_state.html_ejecutivo = None
    st.session_state.html_tecnico = None
    st.session_state.objetivo_nombre = ""

if os.path.exists("logo_sigmac.jpg"):
    st.image("logo_sigmac.jpg", width=200)

st.title("🛡️ Plataforma de Auditoría CISO")
st.markdown("Motor de consolidación Multi-Escáner impulsado por IA para **Sigmac Corp**.")


# ==========================================
# 5. BARRA LATERAL
# ==========================================
with st.sidebar:
    # ── Sesión activa ─────────────────────────────────────────────
    st.success(f"✅ {st.user.name}")
    st.caption(f"📧 {st.user.email}")
    st.button("🚪 Cerrar Sesión", on_click=st.logout)
    st.divider()

    # ── Panel de Administración (solo visible para el primer correo de la lista) ──
    admin_email = allowed_emails[0] if allowed_emails else ""
    es_admin    = (user_email == admin_email)

    if es_admin:
        with st.expander("🔑 Panel de Administración", expanded=False):
            st.markdown("**Correos autorizados:**")
            for idx, correo in enumerate(allowed_emails, 1):
                icono = "👑" if idx == 1 else "👤"
                activo = " ← tú" if correo == user_email else ""
                st.markdown(f"{icono} `{correo}`{activo}")
            st.divider()
            st.caption(
                "Para agregar o eliminar usuarios, edita `allowed_emails` "
                "en `.streamlit/secrets.toml` y reinicia la app."
            )
            st.info(
                f"**Sesión actual**\n\n"
                f"👤 {st.user.name}\n\n"
                f"📧 {st.user.email}\n\n"
                f"🌐 Codespace: `{os.environ.get('CODESPACE_NAME', 'local')}`"
            )

    st.header("⚙️ Configuración del Motor")
    api_key_input = st.text_input("Ingresa tu API Key de Gemini:", type="password")
    st.info("🔒 La API Key no se guarda en ningún servidor.")
    if st.button("🔄 Nuevo Análisis"):
        st.session_state.analisis_completado = False
        st.rerun()



# ==========================================
# 6. FUNCIONES CORE Y NORMALIZACIÓN
# ==========================================
def limpiar_html(texto):
    if not texto:
        return "N/A"
    t = html.unescape(str(texto))
    t = re.sub(r'<[^>]+>', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()


def desarmar_payloads(texto):
    """Neutraliza código malicioso para que la API de Google no lo bloquee."""
    if not texto:
        return ""
    t = str(texto).replace('<', '【').replace('>', '】')
    return re.sub(r'(?i)(alert\(|prompt\(|confirm\(|eval\()', 'alerta_bloqueada(', t)


def mapear_severidad(sev_cruda):
    sev = str(sev_cruda).strip().lower()
    if sev in ['critical', 'crítico', '4', 'high', 'alto', '3']:
        return 'High'
    elif sev in ['medium', 'medio', '2']:
        return 'Medium'
    elif sev in ['low', 'bajo', '1']:
        return 'Low'
    else:
        return 'Informational'


def normalizar_objetivo(url):
    """Extrae el dominio puro, ignorando HTTP, puertos y subdominios www."""
    if not url:
        return "desconocido"
    url = url.lower().strip()
    if not url.startswith('http'):
        url = 'http://' + url
    dominio = urlparse(url).netloc.split(':')[0]
    if dominio.startswith('www.'):
        dominio = dominio[4:]
    return dominio


def limpiar_ruta(ruta_cruda, objetivo):
    if not ruta_cruda or ruta_cruda == "N/A":
        return "Global"
    ruta = str(ruta_cruda).strip()
    ruta_lower = ruta.lower()
    if any(x in ruta_lower for x in ["owasp.org", "mitre.org", "cve", "w3.org", "tools.ietf.org"]):
        return "Global"
    if ruta_lower.startswith("http"):
        try:
            dominio_ruta = urlparse(ruta).netloc.split(':')[0]
            dominio_obj  = normalizar_objetivo(objetivo)
            if dominio_ruta and dominio_obj and dominio_ruta != dominio_obj:
                return "Global"
        except ValueError:
            pass  # URL malformada: se conserva la ruta original
    return ruta


def clasificar_y_guardar(sev_norm, nombre, impacto, ruta, r_riesgos, r_tipos, hallazgos):
    r_riesgos[sev_norm] += 1
    if sev_norm in ["Critical", "High", "Medium", "Low"]:
        nombre_low = str(nombre).lower()

        if "disclosure" in nombre_low or "leak" in nombre_low or "info" in nombre_low:
            tipo_es = "Fuga de Informacion"
        elif ("ssl" in nombre_low or "tls" in nombre_low or "cipher" in nombre_low
              or "certificate" in nombre_low or "crypt" in nombre_low):
            tipo_es = "Criptografía Débil"
        elif "outdated" in nombre_low or "version" in nombre_low or "obsolete" in nombre_low:
            tipo_es = "Software Obsoleto"
        elif ("hsts" in nombre_low or "header" in nombre_low or "cookie" in nombre_low
              or "csrf" in nombre_low or "clickjacking" in nombre_low or "cors" in nombre_low):
            tipo_es = "Debilidad Perimetral"
        else:
            tipo_es = "Mala Configuracion"

        r_tipos[tipo_es] = r_tipos.get(tipo_es, 0) + 1
        hallazgos.append({
            "Riesgo":         sev_norm,
            "Vulnerabilidad": limpiar_html(nombre),
            "Impacto":        limpiar_html(impacto),
            "Ruta":           limpiar_html(ruta),
        })


# ==========================================
# 7. MOTOR DE EXTRACCIÓN XML MODULAR
# ==========================================
def extraer_ruta_dinamica(item, escaner):
    if escaner == "Acunetix":
        af = item.find('.//Affects')
        if af is not None and af.text:
            return af.text
    elif escaner == "Wapiti":
        path = item.find('.//entries/entry/path')
        if path is not None and path.text:
            return path.text
    elif escaner == "OWASP ZAP":
        uri = item.find('.//instances/instance/uri')
        if uri is not None and uri.text:
            return uri.text
    elif escaner == "Burp Suite":
        path = item.find('path')
        loc  = item.find('location')
        if path is not None and path.text:
            return path.text
        if loc is not None and loc.text:
            return loc.text

    for etiqueta in ['uri', 'url', 'path', 'location', 'Affects']:
        nodo = item.find(f'.//{etiqueta}')
        if nodo is not None and nodo.text and len(str(nodo.text).strip()) > 1:
            return str(nodo.text).strip()
    return ""


def extraer_datos_xml(xml_content):
    resumen_riesgos  = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    resumen_tipos    = {}
    hallazgos_crudos = []
    objetivo         = "Infraestructura no identificada"
    escaner          = "Desconocido"

    try:
        xml_content = re.sub(r'\bxsi:[a-zA-Z0-9_]+="[^"]*"', '', xml_content)
        root     = ET.fromstring(xml_content)
        root_tag = root.tag.lower()

        # Detección del escáner por firma XML
        wapiti_gen = root.find('.//info[@name="generatorName"]')
        if wapiti_gen is not None and 'wapiti' in str(wapiti_gen.text).lower():
            escaner = "Wapiti"
        elif 'nessus' in root_tag:
            escaner = "Nessus"
        elif 'owaspzapreport' in root_tag:
            escaner = "OWASP ZAP"
        elif 'issues' in root_tag:
            escaner = "Burp Suite"
        elif 'scangroup' in root_tag or 'scan' in root_tag:
            escaner = "Acunetix"
        else:
            escaner = "Otro Escáner"

        # Extracción del objetivo
        start_url     = root.find('.//StartURL')
        host_tag      = root.find('.//ReportHost')
        site_tag      = root.find('.//site')
        burp_host     = root.find('.//host')
        wapiti_target = root.find('.//info[@name="target"]')

        if start_url is not None and start_url.text:
            objetivo = start_url.text
        elif host_tag is not None:
            objetivo = host_tag.get('name', 'Host')
        elif site_tag is not None:
            objetivo = site_tag.get('name', 'Host')
        elif burp_host is not None and burp_host.text:
            objetivo = burp_host.text
        elif wapiti_target is not None and wapiti_target.text:
            objetivo = wapiti_target.text

        # --- Parsers por escáner ---
        if escaner == "Wapiti":
            for item in root.findall('.//vulnerability'):
                nombre    = item.get('name', 'Hallazgo Wapiti')
                level_tag = item.find('.//level')
                sev_val   = (level_tag.text if level_tag is not None and level_tag.text
                             else ('High' if any(x in nombre.lower()
                                                 for x in ['sql', 'xss', 'injection', 'exec'])
                                   else 'Medium'))
                impacto_tag = item.find('description')
                clasificar_y_guardar(
                    mapear_severidad(sev_val), nombre,
                    impacto_tag.text if impacto_tag is not None else "Sin detalles.",
                    limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo),
                    resumen_riesgos, resumen_tipos, hallazgos_crudos
                )

        elif escaner == "OWASP ZAP":
            for item in root.findall('.//alertitem'):
                sev_tag  = item.find('riskcode')
                sev_norm = ('Informational' if (sev_tag is not None and str(sev_tag.text) == '0')
                            else mapear_severidad(sev_tag.text if sev_tag is not None else '0'))
                nombre_tag  = item.find('alert')
                impacto_tag = item.find('desc')
                clasificar_y_guardar(
                    sev_norm,
                    nombre_tag.text if nombre_tag is not None else 'Hallazgo',
                    impacto_tag.text if impacto_tag is not None else "",
                    limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo),
                    resumen_riesgos, resumen_tipos, hallazgos_crudos
                )

        elif escaner == "Burp Suite":
            for item in root.findall('.//issue'):
                sev_tag    = item.find('severity')
                nombre_tag = item.find('name')
                impacto_bg = item.find('issueBackground')
                impacto_dt = item.find('issueDetail')
                impacto    = (impacto_bg.text if impacto_bg is not None
                              else (impacto_dt.text if impacto_dt is not None else ""))
                clasificar_y_guardar(
                    mapear_severidad(sev_tag.text if sev_tag is not None else 'Information'),
                    nombre_tag.text if nombre_tag is not None else 'Hallazgo',
                    impacto,
                    limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo),
                    resumen_riesgos, resumen_tipos, hallazgos_crudos
                )

        else:  # Nessus / Acunetix / Otro Escáner
            for item in root.findall('.//ReportItem'):
                sev_tag = item.find('Severity')
                sev_val = sev_tag.text if sev_tag is not None else item.get('severity')
                if sev_val is None:
                    continue
                nombre_tag  = item.find('Name')
                impacto_tag = item.find('Impact') if item.find('Impact') is not None else item.find('Description')
                clasificar_y_guardar(
                    mapear_severidad(sev_val),
                    nombre_tag.text if nombre_tag is not None else item.get('pluginName', 'Hallazgo'),
                    impacto_tag.text if impacto_tag is not None else "",
                    limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo),
                    resumen_riesgos, resumen_tipos, hallazgos_crudos
                )

        return resumen_riesgos, resumen_tipos, hallazgos_crudos, objetivo, escaner

    except ET.ParseError as e:
        st.warning(f"❌ XML mal formado, se omite este archivo: {e}")
        return None, None, None, None, None
    except Exception as e:
        st.warning(f"❌ Error inesperado al procesar un archivo XML: {e}")
        return None, None, None, None, None


def consolidar_reportes(archivos_cargados):
    total_riesgos               = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    total_tipos                 = {}
    total_hallazgos             = []
    escaneres_detectados        = set()
    objetivo_maestro            = None
    objetivo_normalizado_maestro = None

    for nombre_archivo, contenido_bytes in archivos_cargados.items():
        xml_str = contenido_bytes.decode('utf-8', errors='ignore')
        r_riesgos, r_tipos, hallazgos, obj, escaner = extraer_datos_xml(xml_str)
        if obj is None:
            continue

        obj_norm = normalizar_objetivo(obj)

        if objetivo_normalizado_maestro is None:
            objetivo_normalizado_maestro = obj_norm
            objetivo_maestro = obj
        elif objetivo_normalizado_maestro != obj_norm and obj_norm != "desconocido":
            # Escudo Relajado: permite subdominios o ligeras variaciones
            if obj_norm in objetivo_normalizado_maestro or objetivo_normalizado_maestro in obj_norm:
                pass
            else:
                st.warning(
                    f"⚠️ Nota: '{nombre_archivo}' reporta el objetivo '{obj_norm}', "
                    f"que difiere del principal '{objetivo_normalizado_maestro}'. Consolidando de todos modos."
                )

        escaneres_detectados.add(escaner)
        for k, v in r_riesgos.items():
            total_riesgos[k] += v
        for k, v in r_tipos.items():
            total_tipos[k] = total_tipos.get(k, 0) + v
        total_hallazgos.extend(hallazgos)

    madurez = {
        "Hardening":          10.0,
        "Criptografía":       10.0,
        "Protección de Datos": 10.0,
        "Gestión de Parches": 10.0,
        "Perímetro":          10.0,
    }
    for tipo, cantidad in total_tipos.items():
        if tipo == "Fuga de Informacion":
            madurez["Protección de Datos"] -= (cantidad * 0.5)
        elif tipo == "Criptografía Débil":
            madurez["Criptografía"] -= (cantidad * 0.5)
        elif tipo == "Software Obsoleto":
            madurez["Gestión de Parches"] -= (cantidad * 0.5)
        elif tipo == "Debilidad Perimetral":
            madurez["Perímetro"] -= (cantidad * 0.5)
        elif tipo == "Mala Configuracion":
            madurez["Hardening"] -= (cantidad * 0.5)

    for k in madurez:
        madurez[k] = max(0, min(10.0, madurez[k]))

    orden_severidad = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Informational": 5}
    total_hallazgos = sorted(
        total_hallazgos,
        key=lambda x: orden_severidad.get(x.get("Riesgo", "Informational"), 6)
    )
    return total_riesgos, total_tipos, madurez, total_hallazgos, objetivo_maestro, list(escaneres_detectados)


# ==========================================
# 8. ANÁLISIS IA — REINTENTOS + LOTES
# ==========================================
def llamar_ia_con_reintentos(cliente, modelo, prompt):
    """Llama a Gemini con reintentos y backoff exponencial.
    Mitiga el error 429 RESOURCE_EXHAUSTED documentado en la infraestructura Sigmac-IAOps."""
    ultimo_error = None
    for intento in range(1, REINTENTOS_IA + 1):
        try:
            return cliente.models.generate_content(model=modelo, contents=prompt).text
        except Exception as e:
            ultimo_error = e
            err_str = str(e)
            es_cuota = '429' in err_str or 'RESOURCE_EXHAUSTED' in err_str.upper()

            if intento < REINTENTOS_IA:
                espera = ESPERA_BASE_SEG * (2 ** (intento - 1))
                motivo = "cuota excedida (429)" if es_cuota else "error de API"
                st.toast(f"⚠️ Reintento {intento}/{REINTENTOS_IA} ({motivo}) — esperando {espera}s...", icon="⏳")
                time.sleep(espera)
    raise ultimo_error


def traducir_inventario_json(hallazgos, cliente):
    """Traduce TODO el inventario en lotes de LOTE_TRADUCCION hallazgos.
    La versión anterior descartaba silenciosamente todo lo que pasara del hallazgo 30.
    Si un lote falla, se conserva en su idioma original en lugar de eliminarse."""
    resultado_total = []
    total_lotes = (len(hallazgos) + LOTE_TRADUCCION - 1) // LOTE_TRADUCCION

    for i in range(0, len(hallazgos), LOTE_TRADUCCION):
        lote        = hallazgos[i:i + LOTE_TRADUCCION]
        numero_lote = i // LOTE_TRADUCCION + 1
        prompt = (
            "Traduce al español técnico SOLAMENTE los valores de 'Vulnerabilidad' e 'Impacto'. "
            "Las claves 'Riesgo' y 'Ruta' DEBEN QUEDAR EXACTAMENTE IGUAL. "
            "Devuelve JSON puro, sin texto adicional ni backticks:\n"
            + json.dumps(lote, ensure_ascii=False)
        )
        try:
            respuesta      = llamar_ia_con_reintentos(cliente, MODELO_TRADUCCION, prompt)
            respuesta      = respuesta.replace("```json", "").replace("```", "").strip()
            lote_traducido = json.loads(respuesta)
            if isinstance(lote_traducido, list) and len(lote_traducido) == len(lote):
                resultado_total.extend(lote_traducido)
            else:
                st.toast(f"⚠️ Lote {numero_lote}/{total_lotes}: respuesta inesperada, se conserva original.", icon="⚠️")
                resultado_total.extend(lote)
        except Exception as e:
            st.toast(f"⚠️ Lote {numero_lote}/{total_lotes} no se pudo traducir ({e}). Se conserva original.", icon="⚠️")
            resultado_total.extend(lote)

    return resultado_total


def analizar_ejecutivo_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    """Genera análisis ejecutivo con secciones etiquetadas y tablas para CISO."""
    datos_texto = "\n".join([
        f"- [{h.get('Riesgo', '')}] {desarmar_payloads(h.get('Vulnerabilidad', ''))}"
        for h in hallazgos[:MAX_HALLAZGOS_EJECUTIVO]
    ])
    escaneres_str = " + ".join(escaneres_lista)

    prompt = f"""Actúas como el Consultor Estratégico CISO de Sigmac Corp.
    Redacta un análisis ejecutivo de alto nivel para la Junta Directiva y el CISO.
    Objetivo auditado: {objetivo}
    Escáneres combinados: {escaneres_str}
    Hallazgos detectados:
    {datos_texto}

    INSTRUCCIONES OBLIGATORIAS:
    1. CERO jerga técnica en las secciones narrativas. Habla de riesgo de negocio, impacto financiero, reputación y cumplimiento normativo.
    2. Usa EXACTAMENTE los encabezados ##SECCION## indicados.
    3. En las secciones donde se indica TABLA, genera una tabla en formato Markdown pipe (|col1|col2|...) con una fila separadora |---|---| después del encabezado.
    4. Usa **negritas** para resaltar términos clave, niveles de riesgo y fases.
    5. Usa listas con - para los ítems de cada área de exposición.
    6. Cada sección narrativa debe tener al menos 2 párrafos sólidos.

    FORMATO OBLIGATORIO (respeta EXACTAMENTE estos encabezados):

    ##IMPACTO OPERACIONAL Y FINANCIERO##
    [2 párrafos describiendo el riesgo de negocio global. Usa **negritas** para los impactos más críticos. Menciona posibles sanciones regulatorias, pérdida de reputación y continuidad operativa.]

    ##ÁREAS DE EXPOSICIÓN CRÍTICA##
    [Lista con - de 4-5 áreas de riesgo de negocio. Para cada una usa formato: - **Nombre del Área** -- consecuencia directa para el negocio y a quién impacta.]

    ##ANÁLISIS DE IMPACTO POR ÁREA DE NEGOCIO##
    [Genera esta tabla exacta en formato pipe Markdown:]
    |Área de Negocio|Nivel de Exposición|Consecuencia Inmediata|Consecuencia si no se Remedia|
    |---|---|---|---|
    [Una fila por área: Operaciones, Clientes, Finanzas / Legal, Reputación]

    ##ROADMAP DE ACCIÓN ESTRATÉGICO##
    [Genera esta tabla exacta en formato pipe Markdown:]
    |Fase|Período|Acciones Clave|Responsables|Indicador de Éxito|
    |---|---|---|---|---|
    |**Fase 1 — Inmediata**|0-30 días|[2-3 acciones concretas]|[roles]|[métrica medible]|
    |**Fase 2 — Corto Plazo**|30-90 días|[2-3 acciones concretas]|[roles]|[métrica medible]|
    |**Fase 3 — Largo Plazo**|90-180 días|[2-3 acciones concretas]|[roles]|[métrica medible]|

    ##MÉTRICAS DE EXPOSICIÓN##
    [Genera esta tabla exacta en formato pipe Markdown:]
    |Métrica Clave|Valor Estimado|Estado|Objetivo de Remediación|
    |---|---|---|---|
    [5-7 indicadores: total hallazgos críticos, %% superficie de ataque, MTTR objetivo, activos expuestos, vectores de fraude detectados, etc.]"""

    try:
        texto = llamar_ia_con_reintentos(cliente, MODELO_EJECUTIVO, prompt)
        return texto
    except Exception as e:
        return f"##IMPACTO OPERACIONAL Y FINANCIERO##\nAnálisis ejecutivo no disponible: {e}"


def analizar_tecnico_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    """Genera análisis técnico premium con Gemini Pro: veración de positivos,
    CVSS v3.1, CVE, evidencia y plan de remediación priorizado."""
    datos_texto_lista = []
    for idx, h in enumerate(hallazgos[:MAX_HALLAZGOS_TECNICO], 1):
        impacto_str    = str(h.get('Impacto', ''))
        impacto_limpio = impacto_str[:350] + "..." if len(impacto_str) > 350 else impacto_str
        datos_texto_lista.append(
            f"[{idx}] Severidad: {h.get('Riesgo', 'Unknown')} | "
            f"Vulnerabilidad: {desarmar_payloads(h.get('Vulnerabilidad', ''))} | "
            f"Ruta: {h.get('Ruta', 'Global')} | "
            f"Descripción del escaner: {desarmar_payloads(impacto_limpio)}"
        )
    datos_texto   = "\n".join(datos_texto_lista)
    escaneres_str = " + ".join(escaneres_lista)
    total_h       = len(hallazgos[:MAX_HALLAZGOS_TECNICO])

    prompt = f"""Eres el analista líder de un equipo Red Team de elite especializado en seguridad ofensiva web.
    Tu misión es producir una Guía Técnica Maestra de máxima calidad para los ingenieros de seguridad de Sigmac Corp.
    El reporte debe ser rigurosamente preciso: distingue explícitamente entre hallazgos confirmados y probables falsos positivos.

    CONTEXTO DEL ESCANEO:
    Objetivo auditado: {objetivo}
    Motores de escaneo utilizados: {escaneres_str}
    Total de hallazgos a analizar: {total_h}

    INVENTARIO COMPLETO DE HALLAZGOS:
    {datos_texto}

    INSTRUCCIONES CRÍTICAS:
    1. Usa tu base de conocimiento de seguridad para determinar qué hallazgos son probables verdaderos positivos y cuáles son falsos positivos típicos de ese tipo de escáner.
    2. Para cada vulnerabilidad crítica, asigna un score CVSS v3.1 estimado y su vector string.
    3. Referencia CVE específicos cuando el hallazgo corresponda a una vulnerabilidad conocida.
    4. La remediación debe ser concreta, con pasos ordenados por impacto y tiempo estimado.
    5. PROHIBIDO código de explotación malicioso. El vector de ataque es siempre conceptual.
    6. Separa los párrafos con una línea en blanco. No uses Markdown (sin asteriscos, sin hashes).
    7. Usa EXACTAMENTE los encabezados ##SECCION## indicados a continuación.

    FORMATO OBLIGATORIO DE SALIDA:

    ##PANORAMA GENERAL DEL ESCANEO##
    Escribe 2 párrafos que respondan: ¿Cuántos hallazgos hay por nivel de severidad? ¿Qué categorías de vulnerabilidad predominan (inyección, configuración, criptografía, etc.)? ¿Cuál es la superficie de ataque general del objetivo? Incluye un estimado del porcentaje de confianza global en los hallazgos (ej. 70%% verdaderos positivos estimados) basado en el tipo de escáner y la naturaleza de los hallazgos.

    ##CLASIFICACIÓN: VERDADEROS POSITIVOS VS FALSOS POSITIVOS##
    Para CADA hallazgo del inventario, indica:
    HALLAZGO [Número]: [Nombre de la vulnerabilidad]
    VEREDICTO: [VERDADERO POSITIVO | PROBABLE VERDADERO POSITIVO | FALSO POSITIVO PROBABLE | REQUIERE VERIFICACIÓN MANUAL]
    JUSTIFICACIÓN: [Explica en 2-3 oraciones por qué llegas a este veredicto. Considera: el tipo de escáner que lo detectó, si la ruta reportada tiene sentido, si el tipo de vulnerabilidad es común para ese tecnología/endpoint, y patrones típicos de falsos positivos de ese escáner.]
    ---

    ##ANÁLISIS PROFUNDO DE VULNERABILIDADES CRÍTICAS##
    Para los 3-5 hallazgos con mayor riesgo real (priorizando verdaderos positivos confirmados), escribe un bloque completo para CADA UNO con exactamente estos campos:
    VULNERABILIDAD: [nombre completo + nivel de severidad]
    CVSS v3.1 SCORE: [score numérico estimado, ej. 9.1 CRITICAL]
    CVSS VECTOR: [vector string, ej. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]
    CVE RELACIONADO: [CVE-XXXX-XXXXX si aplica, o N/A]
    NIVEL DE CONFIANZA: [ALTO / MEDIO / BAJO] - [Justificación breve]
    ENDPOINT AFECTADO: [ruta o dominio exacto]
    DESCRIPCIÓN TÉCNICA: [Explicación técnica profunda del fallo: qué falla, por qué falla, qué condición lo hace explotable]
    EVIDENCIA QUE CONFIRMA EL HALLAZGO: [Indica qué elementos de la descripción del escáner o de la ruta detectada son indicios sólidos de que este hallazgo es real. Si no hay evidencia suficiente, indícalo claramente.]
    VECTOR DE ATAQUE CONCEPTUAL: [Cómo un atacante lo explotaría paso a paso, de forma puramente descriptiva, sin código]
    IMPACTO TÉCNICO: [Qué puede lograr un atacante explotando esta vulnerabilidad]
    IMPACTO EN EL NEGOCIO: [Consecuencias para la operación, datos, clientes y reputación]
    REMEDIACIÓN CONCRETA: [Pasos exactos, en orden de prioridad, para corregir la vulnerabilidad. Incluye configuración específica, actualizaciones de versión o cambios de código recomendados de forma descriptiva.]
    TIEMPO ESTIMADO DE REMEDIACIÓN: [Horas o días estimados para un equipo técnico]
    REFERENCIAS TÉCNICAS: [OWASP Top 10 categoría, CWE-ID, CVE si aplica, NIST, documentación oficial del fabricante si es relevante]
    ===

    ##HALLAZGOS DESCARTABLES - FALSOS POSITIVOS DETECTADOS##
    Lista los hallazgos que clasificaste como FALSO POSITIVO PROBABLE. Para cada uno:
    HALLAZGO [Número]: [Nombre]
    RAZÓN DEL DESCARTE: [Explicación técnica de por qué es probablemente un falso positivo]
    CÓMO VERIFICAR: [Pasos manuales concretos para confirmar si es real o no antes de descartar definitivamente]

    ##SUPERFICIE DE ATAQUE PRIORITARIA PARA PRUEBAS MANUALES##
    Enumera los endpoints, parámetros y componentes que deben ser verificados manualmente por un pentester antes de cerrar la auditoría. Para cada uno indica: qué probar, qué tipo de payload conceptual usar y qué respuesta confirmaría el hallazgo.

    ##DIAGNÓSTICO DE AUTENTICACIÓN Y GESTIÓN DE SESIONES##
    Análisis profundo de: mecanismos de autenticación observados en los hallazgos, cookies y cabeceras de sesión detectadas, configuraciones débiles de tokens, puntos ciegos de autorización, y recomendaciones de hardening de autenticación.

    ##PLAN DE REMEDIACIÓN PRIORIZADO##
    Una tabla de texto (sin formato Markdown, usa espacios para alinear) que liste TODAS las vulnerabilidades reales con:
    Prioridad | Vulnerabilidad | Esfuerzo estimado | Impacto de remediación
    Ordena de mayor a menor urgencia. Al final, escribe 2 párrafos con recomendaciones estratégicas para el equipo de desarrollo sobre cómo evitar este tipo de vulnerabilidades en el futuro."""

    try:
        texto = llamar_ia_con_reintentos(cliente, MODELO_TECNICO, prompt)
        return texto
    except Exception as e:
        return f"##PANORAMA GENERAL DEL ESCANEO##\nAnálisis técnico no disponible: {e}"



# ==========================================
# 9. RENDERIZADO DE PLANTILLA HTML PREMIUM
# ==========================================
def obtener_base64_img(ruta_img):
    if not ruta_img or not os.path.exists(ruta_img):
        return ""
    with open(ruta_img, "rb") as img_file:
        return f"data:image/png;base64,{base64.b64encode(img_file.read()).decode('utf-8')}"


def obtener_base64_jpg(ruta_img):
    """Convierte logo JPG a base64 para embeber en HTML."""
    if not ruta_img or not os.path.exists(ruta_img):
        return ""
    with open(ruta_img, "rb") as img_file:
        return f"data:image/jpeg;base64,{base64.b64encode(img_file.read()).decode('utf-8')}"


def _inline_md(texto):
    """Convierte inline markdown: **bold**, *italic*, `code`."""
    texto = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', texto)
    texto = re.sub(r'\*(?!\s)(.+?)(?<!\s)\*', r'<em>\1</em>', texto)
    texto = re.sub(r'`(.+?)`', r'<code>\1</code>', texto)
    return texto


def markdown_a_html(texto):
    """Convierte markdown básico a HTML limpio para el reporte.
    Maneja: **bold**, *italic*, `code`, - listas, 1. listas, tablas pipe, --- separadores."""
    if not texto:
        return ""
    lines   = texto.split('\n')
    partes  = []
    in_ul   = False
    in_ol   = False
    in_table = False

    for line in lines:
        s = line.strip()

        # — Tabla pipe —
        if '|' in s and s.startswith('|') and s.endswith('|'):
            cells = [c.strip() for c in s.strip('|').split('|')]
            is_sep = all(re.match(r'^[-:]+$', c) for c in cells if c)
            if is_sep:
                continue  # fila separadora de Markdown, se salta
            if not in_table:
                # cerrar listas abiertas
                if in_ul:  partes.append('</ul>');  in_ul  = False
                if in_ol:  partes.append('</ol>');  in_ol  = False
                partes.append('<table class="ai-table"><thead><tr>')
                partes.extend(f'<th>{_inline_md(c)}</th>' for c in cells)
                partes.append('</tr></thead><tbody>')
                in_table = True
            else:
                partes.append('<tr>')
                partes.extend(f'<td>{_inline_md(c)}</td>' for c in cells)
                partes.append('</tr>')
            continue

        # cerrar tabla si la línea actual no es pipe
        if in_table:
            partes.append('</tbody></table>')
            in_table = False

        # — Separador horizontal —
        if s in ('---', '===', '***', '___'):
            if in_ul: partes.append('</ul>'); in_ul = False
            if in_ol: partes.append('</ol>'); in_ol = False
            partes.append('<hr class="ai-hr">')
            continue

        # — Lista no numerada (* o -) —
        m_ul = re.match(r'^[\*\-]\s+(.*)', s)
        if m_ul:
            if in_ol: partes.append('</ol>'); in_ol = False
            if not in_ul: partes.append('<ul class="ai-ul">'); in_ul = True
            partes.append(f'<li>{_inline_md(m_ul.group(1))}</li>')
            continue

        # — Lista numerada —
        m_ol = re.match(r'^\d+[.)]\s+(.*)', s)
        if m_ol:
            if in_ul: partes.append('</ul>'); in_ul = False
            if not in_ol: partes.append('<ol class="ai-ol">'); in_ol = True
            partes.append(f'<li>{_inline_md(m_ol.group(1))}</li>')
            continue

        # — Línea vacía —
        if not s:
            if in_ul: partes.append('</ul>'); in_ul = False
            if in_ol: partes.append('</ol>'); in_ol = False
            continue

        # — Párrafo normal —
        if in_ul: partes.append('</ul>'); in_ul = False
        if in_ol: partes.append('</ol>'); in_ol = False
        partes.append(f'<p>{_inline_md(s)}</p>')

    # cerrar elementos abiertos al final
    if in_ul:    partes.append('</ul>')
    if in_ol:    partes.append('</ol>')
    if in_table: partes.append('</tbody></table>')

    return '\n'.join(partes)


def parsear_secciones_ia(texto_ia):
    """Convierte texto de IA con encabezados ##SECCION## en lista de (titulo, contenido_html).
    Aplica markdown_a_html() para que las tablas, listas y negritas se rendericen correctamente."""
    secciones = []
    bloques = re.split(r'##([^#]+)##', texto_ia)
    # bloques[0] es texto previo al primer ##, luego alterna título/contenido
    for i in range(1, len(bloques), 2):
        titulo_sec = bloques[i].strip()
        contenido  = bloques[i + 1].strip() if (i + 1) < len(bloques) else ""
        if titulo_sec and contenido:
            secciones.append({"titulo": titulo_sec, "contenido": markdown_a_html(contenido)})
    # Si no se encontraron secciones (IA no siguió el formato), devolver como sección única
    if not secciones and texto_ia.strip():
        secciones.append({"titulo": "Análisis", "contenido": markdown_a_html(texto_ia.strip())})
    return secciones


PLANTILLA_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ titulo }} — Sigmac Corp</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --navy:    #0F1B2D;
    --green:   #1A8C4E;
    --text:    #2C3E50;
    --soft:    #6B7C93;
    --border:  #E4EBF2;
    --bg:      #F5F7FA;
    --white:   #FFFFFF;
    --crit:    #8B0000;
    --high:    #D32F2F;
    --med:     #F57C00;
    --low:     #FBC02D;
    --info:    #455A64;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', 'Helvetica Neue', Arial, sans-serif;
    color: var(--text); background: var(--bg); line-height: 1.7;
    font-size: 15px;
  }
  .page-wrap { max-width: 1050px; margin: 0 auto; background: var(--white);
    box-shadow: 0 4px 40px rgba(15,27,45,0.10); }

  /* ── COVER ── */
  .cover {
    background: linear-gradient(150deg, #0F1B2D 0%, #183352 55%, #1A8C4E 100%);
    color: white; padding: 80px 60px; text-align: center;
    page-break-after: always; min-height: 520px;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
  }
  .cover img.logo { max-width: 160px; margin-bottom: 36px;
    filter: drop-shadow(0 2px 8px rgba(0,0,0,0.4)); }
  .cover-badge {
    background: rgba(26,140,78,0.25); border: 1px solid rgba(26,140,78,0.6);
    border-radius: 20px; padding: 5px 18px; font-size: 12px;
    font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase;
    color: #7DFFC0; margin-bottom: 24px;
  }
  .cover h1 { font-size: 34px; font-weight: 800; letter-spacing: -0.5px;
    line-height: 1.2; margin-bottom: 16px; }
  .cover .scanners { font-size: 14px; color: #A8C4D8; margin-bottom: 36px; }
  .cover-meta {
    background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.12);
    border-radius: 10px; padding: 20px 40px; display: inline-flex; gap: 50px;
  }
  .cover-meta-item { text-align: left; }
  .cover-meta-item .label { font-size: 11px; text-transform: uppercase;
    letter-spacing: 1px; color: #7DFFC0; font-weight: 600; }
  .cover-meta-item .value { font-size: 15px; font-weight: 500; color: white; margin-top: 4px; }

  /* ── CONTENT AREA ── */
  .content { padding: 50px 60px; }

  /* ── SECTION BANNER ── */
  .section-banner {
    background: var(--navy); color: white; padding: 12px 24px;
    font-size: 13px; font-weight: 700; letter-spacing: 1.5px;
    text-transform: uppercase; margin: 48px -60px 28px -60px;
    border-left: 5px solid var(--green);
  }

  /* ── KPI CARDS ── */
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 36px; }
  .kpi-card {
    border-radius: 10px; padding: 20px 16px; text-align: center;
    color: white; box-shadow: 0 3px 12px rgba(0,0,0,0.15);
  }
  .kpi-card .kpi-num { font-size: 38px; font-weight: 800; line-height: 1; }
  .kpi-card .kpi-lbl { font-size: 11px; font-weight: 600; letter-spacing: 1px;
    text-transform: uppercase; margin-top: 6px; opacity: 0.9; }
  .kpi-critical { background: linear-gradient(135deg, #8B0000, #B71C1C); }
  .kpi-high     { background: linear-gradient(135deg, #D32F2F, #E53935); }
  .kpi-medium   { background: linear-gradient(135deg, #E65100, #F57C00); }
  .kpi-low      { background: linear-gradient(135deg, #F57F17, #FBC02D); }

  /* ── CHARTS ── */
  .chart-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 24px;
    margin: 24px 0;
  }
  .chart-box { background: var(--bg); border-radius: 10px; padding: 16px;
    border: 1px solid var(--border); text-align: center; }
  .chart-box img { max-width: 100%; border-radius: 6px; }
  .chart-full { background: var(--bg); border-radius: 10px; padding: 16px;
    border: 1px solid var(--border); text-align: center; margin-top: 20px; }
  .chart-full img { max-width: 85%; border-radius: 6px; }

  /* ── AI ANALYSIS SECTIONS ── */
  .ai-section { margin-bottom: 36px; }
  .ai-section-title {
    font-size: 15px; font-weight: 700; color: var(--navy);
    border-left: 4px solid var(--green); padding-left: 12px;
    margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px;
  }
  .ai-section-body { font-size: 14px; line-height: 1.85; color: var(--text); }
  .ai-section-body p { margin-bottom: 10px; text-align: justify; }
  .ai-section-body strong { color: var(--navy); font-weight: 600; }
  .ai-section-body em { color: var(--soft); font-style: italic; }
  .ai-section-body code {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 4px; padding: 1px 6px; font-size: 12px;
    font-family: 'Courier New', monospace; color: #c0392b;
  }
  /* AI Tables */
  .ai-table {
    width: 100%; border-collapse: collapse; margin: 16px 0 20px 0;
    font-size: 13px; border-radius: 8px; overflow: hidden;
    box-shadow: 0 1px 6px rgba(15,27,45,0.08);
  }
  .ai-table thead th {
    background: var(--navy); color: white; padding: 10px 14px;
    text-align: left; font-size: 12px; font-weight: 600; letter-spacing: 0.5px;
  }
  .ai-table tbody td {
    padding: 9px 14px; border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  .ai-table tbody tr:nth-child(even) td { background: var(--bg); }
  .ai-table tbody tr:last-child td { border-bottom: none; }
  /* AI Lists */
  .ai-ul, .ai-ol {
    padding-left: 22px; margin: 8px 0 12px 0;
  }
  .ai-ul li, .ai-ol li {
    margin: 5px 0; font-size: 14px; line-height: 1.7; color: var(--text);
  }
  /* AI Separator */
  .ai-hr {
    border: none; border-top: 1px solid var(--border); margin: 20px 0;
  }

  /* ── VULN CARDS ── */
  .vuln-list { display: flex; flex-direction: column; gap: 20px; margin-top: 8px; }
  .vuln-card {
    border-radius: 10px; overflow: hidden;
    box-shadow: 0 2px 10px rgba(15,27,45,0.08);
    border: 1px solid var(--border);
  }
  .vuln-card-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 20px; border-bottom: 1px solid var(--border);
  }
  .vuln-card-title { font-size: 15px; font-weight: 600; color: var(--navy); flex: 1; }
  .severity-badge {
    padding: 4px 12px; border-radius: 20px; font-size: 11px;
    font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: white;
    white-space: nowrap; margin-left: 12px;
  }
  .badge-critical { background: var(--crit); }
  .badge-high     { background: var(--high); }
  .badge-medium   { background: var(--med); }
  .badge-low      { background: var(--low); color: #333; }
  .badge-informational { background: var(--info); }
  .vuln-card-stripe {
    height: 4px;
  }
  .stripe-critical { background: var(--crit); }
  .stripe-high     { background: var(--high); }
  .stripe-medium   { background: var(--med); }
  .stripe-low      { background: var(--low); }
  .stripe-informational { background: var(--info); }
  .vuln-card-body { padding: 16px 20px; background: white; }
  .vuln-endpoint {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 5px 12px; font-size: 12px;
    font-family: 'Courier New', monospace; color: var(--soft);
    margin-bottom: 12px; max-width: 100%; word-break: break-all;
  }
  .vuln-impact-text { font-size: 13px; color: var(--text); line-height: 1.7; }

  /* ── MATURITY TABLE ── */
  .maturity-table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  .maturity-table th {
    background: var(--navy); color: white; padding: 10px 16px;
    font-size: 12px; font-weight: 600; text-align: left; letter-spacing: 0.5px;
  }
  .maturity-table td { padding: 10px 16px; border-bottom: 1px solid var(--border); font-size: 13px; }
  .maturity-table tr:nth-child(even) td { background: var(--bg); }
  .score-bar-wrap { background: #eee; border-radius: 20px; height: 8px; width: 100px; display: inline-block; }
  .score-bar { height: 8px; border-radius: 20px; display: block; }

  /* ── FOOTER ── */
  .report-footer {
    background: var(--navy); color: rgba(255,255,255,0.5);
    text-align: center; padding: 18px; font-size: 11px; letter-spacing: 0.5px;
  }

  /* ── PRINT ── */
  @media print {
    body { background: white; }
    .page-wrap { box-shadow: none; }
    .cover { page-break-after: always; }
    .section-banner { page-break-before: auto; }
    .vuln-card { page-break-inside: avoid; }
    .ai-section { page-break-inside: avoid; }
    .content { padding: 30px 40px; }
    .section-banner { margin: 30px -40px 20px -40px; }
  }
</style>
</head>
<body>
<div class="page-wrap">

  <!-- PORTADA -->
  <div class="cover">
    {% if logo_sigmac %}<img src="{{ logo_sigmac }}" class="logo" alt="Sigmac Corp">{% endif %}
    <div class="cover-badge">Auditoría de Ciberseguridad</div>
    <h1>{{ titulo }}</h1>
    <p class="scanners">Motores combinados: {{ escaneres }}</p>
    <div class="cover-meta">
      <div class="cover-meta-item">
        <div class="label">Objetivo</div>
        <div class="value">{{ objetivo }}</div>
      </div>
      <div class="cover-meta-item">
        <div class="label">Fecha de emisión</div>
        <div class="value">{{ fecha }}</div>
      </div>
      <div class="cover-meta-item">
        <div class="label">Clasificación</div>
        <div class="value">Confidencial</div>
      </div>
    </div>
  </div>

  <div class="content">

    <!-- SECCIÓN 1: DASHBOARD -->
    <div class="section-banner">1. Dashboard de Postura de Riesgo</div>

    <!-- KPI Cards -->
    <div class="kpi-grid">
      <div class="kpi-card kpi-critical">
        <div class="kpi-num">{{ kpi.Critical }}</div>
        <div class="kpi-lbl">Critical</div>
      </div>
      <div class="kpi-card kpi-high">
        <div class="kpi-num">{{ kpi.High }}</div>
        <div class="kpi-lbl">High</div>
      </div>
      <div class="kpi-card kpi-medium">
        <div class="kpi-num">{{ kpi.Medium }}</div>
        <div class="kpi-lbl">Medium</div>
      </div>
      <div class="kpi-card kpi-low">
        <div class="kpi-num">{{ kpi.Low }}</div>
        <div class="kpi-lbl">Low</div>
      </div>
    </div>

    <!-- Gráficas -->
    <div class="chart-grid">
      {% if img_radar %}<div class="chart-box"><img src="{{ img_radar }}" alt="Madurez de Seguridad"></div>{% endif %}
      {% if img_sev %}<div class="chart-box"><img src="{{ img_sev }}" alt="Distribución de Riesgo"></div>{% endif %}
    </div>
    {% if img_tip %}
    <div class="chart-full"><img src="{{ img_tip }}" alt="Tipos de Vulnerabilidad"></div>
    {% endif %}

    <!-- Tabla de Madurez -->
    {% if madurez %}
    <table class="maturity-table" style="margin-top: 32px;">
      <thead>
        <tr><th>Área de Seguridad</th><th>Score</th><th>Nivel</th></tr>
      </thead>
      <tbody>
        {% for area, score in madurez.items() %}
        <tr>
          <td>{{ area }}</td>
          <td>
            <span class="score-bar-wrap">
              <span class="score-bar" style="width:{{ (score / 10 * 100)|int }}%; background: {% if score >= 7 %}#1A8C4E{% elif score >= 4 %}#F57C00{% else %}#D32F2F{% endif %};"></span>
            </span>
            &nbsp; {{ score }}/10
          </td>
          <td style="font-weight:600; color: {% if score >= 7 %}#1A8C4E{% elif score >= 4 %}#E65100{% else %}#D32F2F{% endif %}">
            {% if score >= 7 %}Aceptable{% elif score >= 4 %}Mejorable{% else %}Crítico{% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}

    <!-- SECCIÓN 2: ANÁLISIS MAESTRO IA -->
    <div class="section-banner">2. Análisis Maestro{% if es_ejecutivo %} Ejecutivo{% else %} Técnico Red Team{% endif %}</div>

    {% for sec in secciones_ia %}
    <div class="ai-section">
      <div class="ai-section-title">{{ sec.titulo }}</div>
      <div class="ai-section-body">{{ sec.contenido | safe }}</div>
    </div>
    {% endfor %}

    <!-- SECCIÓN 3: INVENTARIO (solo reporte técnico) -->
    {% if not es_ejecutivo %}
    <div class="section-banner">3. Inventario Técnico Consolidado ({{ hallazgos|length }} hallazgos)</div>
    <div class="vuln-list">
      {% for h in hallazgos %}
      <div class="vuln-card">
        <div class="vuln-card-stripe stripe-{{ h.Riesgo | lower }}"></div>
        <div class="vuln-card-header">
          <span class="vuln-card-title">{{ h.Vulnerabilidad }}</span>
          <span class="severity-badge badge-{{ h.Riesgo | lower }}">{{ h.Riesgo | upper }}</span>
        </div>
        <div class="vuln-card-body">
          <div class="vuln-endpoint">📍 {{ h.Ruta }}</div>
          <div class="vuln-impact-text">{{ h.Impacto }}</div>
        </div>
      </div>
      {% endfor %}
    </div>
    {% endif %}

  </div><!-- /content -->

  <div class="report-footer">
    CONFIDENCIAL — PROPIEDAD EXCLUSIVA DE SIGMAC CORP — Generado por OmniScanner AI · {{ fecha }}
  </div>

</div><!-- /page-wrap -->
</body>
</html>
"""


def generar_html_maestro(titulo, img_sev, img_tip, img_radar, analisis_ia,
                          hallazgos_traducidos, objetivo, escaneres_lista,
                          logo_sigmac, es_ejecutivo=True, kpi=None, madurez=None):
    """Renderiza el reporte HTML premium con secciones de IA parseadas."""
    secciones_ia = parsear_secciones_ia(analisis_ia)
    template     = Template(PLANTILLA_HTML)
    html_render  = template.render(
        titulo=titulo,
        escaneres=" + ".join(escaneres_lista),
        objetivo=objetivo,
        fecha=fecha_larga_es(),
        logo_sigmac=obtener_base64_jpg(logo_sigmac),
        img_sev=obtener_base64_img(img_sev),
        img_tip=obtener_base64_img(img_tip),
        img_radar=obtener_base64_img(img_radar),
        secciones_ia=secciones_ia,
        hallazgos=hallazgos_traducidos,
        es_ejecutivo=es_ejecutivo,
        kpi=kpi or {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        madurez=madurez or {},
    )
    return html_render


# ==========================================
# 10. INTERFAZ STREAMLIT PRINCIPAL
# ==========================================
if not st.session_state.analisis_completado:
    st.markdown("### 1. Carga de Datos Consolidada")
    archivos_xml = st.file_uploader(
        "Sube uno o MÚLTIPLES archivos XML (ZAP, Burp, Wapiti, Acunetix, Nessus, etc.)",
        type=["xml"],
        accept_multiple_files=True
    )

    if st.button("Generar Súper Reportes", type="primary"):
        if not api_key_input:
            st.error("⚠️ Ingresa tu API Key en la barra lateral.")
        elif not archivos_xml:
            st.warning("⚠️ Sube al menos un archivo XML.")
        else:
            with st.spinner("Analizando y generando reportes corporativos interactivos..."):
                archivos_cargados = {f.name: f.getvalue() for f in archivos_xml}
                r_sev, r_tip, madurez, hallazgos, obj, esc_lista = consolidar_reportes(archivos_cargados)

                if hallazgos:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        p_sev = os.path.join(tmpdir, "sev.png")
                        p_tip = os.path.join(tmpdir, "tip.png")
                        p_rad = os.path.join(tmpdir, "rad.png")

                        cliente = genai.Client(api_key=api_key_input)

                        # --- Gráfico 1: Distribución de riesgo (dona) ---
                        if sum(r_sev.values()) > 0:
                            c_sev = [k for k, v in r_sev.items() if v > 0]
                            v_sev = [v for k, v in r_sev.items() if v > 0]
                            plt.figure(figsize=(4.5, 3.5))
                            plt.pie(
                                v_sev, labels=c_sev,
                                colors=[_hex(COLORES_SEVERIDAD.get(c, (204, 204, 204))) for c in c_sev],
                                autopct='%1.1f%%',
                                textprops={'fontsize': 9, 'weight': 'bold'}
                            )
                            plt.gcf().gca().add_artist(plt.Circle((0, 0), 0.70, fc='white'))
                            plt.title('Distribución de Riesgo Global', fontweight='bold',
                                      color=_hex(COLOR_TEXTO))
                            plt.savefig(p_sev, dpi=300, transparent=True, bbox_inches='tight')
                            plt.close()

                        # --- Gráfico 2: Tipos de vulnerabilidad (barras) ---
                        if len(r_tip) > 0:
                            plt.figure(figsize=(5, 3))
                            plt.barh(list(r_tip.keys()), list(r_tip.values()),
                                     color=_hex(COLOR_VERDE))
                            plt.gca().spines['top'].set_visible(False)
                            plt.gca().spines['right'].set_visible(False)
                            plt.savefig(p_tip, dpi=300, transparent=True, bbox_inches='tight')
                            plt.close()

                        # --- Gráfico 3: Radar de madurez de seguridad ---
                        labels = np.array(list(madurez.keys()))
                        stats  = np.array(list(madurez.values()))
                        angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False)
                        stats  = np.concatenate((stats, [stats[0]]))
                        angles = np.concatenate((angles, [angles[0]]))
                        fig, ax = plt.subplots(figsize=(4.5, 4.5), subplot_kw=dict(polar=True))
                        ax.fill(angles, stats, color=_hex(COLOR_VERDE), alpha=0.25)
                        ax.plot(angles, stats, color=_hex(COLOR_VERDE), linewidth=2)
                        ax.set_yticklabels([])
                        ax.set_xticks(angles[:-1])
                        ax.set_xticklabels(labels, fontsize=9, fontweight='bold',
                                           color=_hex(COLOR_TEXTO))
                        ax.set_ylim(0, 10)
                        plt.savefig(p_rad, dpi=300, transparent=True, bbox_inches='tight')
                        plt.close()

                        # --- Análisis IA ---
                        h_trad  = traducir_inventario_json(hallazgos, cliente)
                        ia_ejec = analizar_ejecutivo_con_ia(h_trad, obj, esc_lista, cliente)
                        ia_tec  = analizar_tecnico_con_ia(h_trad, obj, esc_lista, cliente)

                        # --- Renderizado de reportes ---
                        st.session_state.html_ejecutivo = generar_html_maestro(
                            "Auditoría Estratégica Consolidada",
                            p_sev, p_tip, p_rad, ia_ejec, h_trad,
                            obj, esc_lista, "logo_sigmac.jpg",
                            es_ejecutivo=True, kpi=r_sev, madurez=madurez
                        )
                        st.session_state.html_tecnico = generar_html_maestro(
                            "Reporte Técnico Maestro",
                            p_sev, p_tip, '', ia_tec, h_trad,
                            obj, esc_lista, "logo_sigmac.jpg",
                            es_ejecutivo=False, kpi=r_sev, madurez=madurez
                        )
                        st.session_state.objetivo_nombre = normalizar_objetivo(obj)
                        st.session_state.analisis_completado = True
                        st.rerun()
                else:
                    st.error("❌ Los archivos subidos no contienen vulnerabilidades válidas o están cruzados.")

if st.session_state.analisis_completado:
    st.success("✅ ¡Consolidación exitosa! Tus reportes están listos para visualizar y descargar.")

    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📥 Descargar Reporte Ejecutivo (HTML)",
            data=st.session_state.html_ejecutivo,
            file_name=f"Ejecutivo_{st.session_state.objetivo_nombre}.html",
            mime="text/html",
            use_container_width=True
        )
    with col2:
        st.download_button(
            "📥 Descargar Reporte Técnico (HTML)",
            data=st.session_state.html_tecnico,
            file_name=f"Tecnico_{st.session_state.objetivo_nombre}.html",
            mime="text/html",
            use_container_width=True
        )

    st.markdown("---")
    st.markdown("### Vista Previa de Reportes")
    tab1, tab2 = st.tabs(["Reporte Ejecutivo", "Reporte Técnico"])

    with tab1:
        st.components.v1.html(st.session_state.html_ejecutivo, height=800, scrolling=True)
    with tab2:
        st.components.v1.html(st.session_state.html_tecnico, height=800, scrolling=True)

    if st.button("⏪ Volver al inicio"):
        st.session_state.analisis_completado = False
        st.rerun()
