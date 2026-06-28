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
MODELO_TECNICO    = 'gemini-2.5-flash'

# Tamaños y límites
MAX_HALLAZGOS_EJECUTIVO = 15   # hallazgos en el prompt ejecutivo
MAX_HALLAZGOS_TECNICO   = 20   # hallazgos en el prompt técnico
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
    Mitiga el error 429 RESOURCE_EXHAUSTED documentado en la infraestructura
    Sigmac-IAOps (ver CONTENEDORES_SIGMAC_IAOPS.md, sección 10)."""
    ultimo_error = None
    for intento in range(1, REINTENTOS_IA + 1):
        try:
            return cliente.models.generate_content(model=modelo, contents=prompt).text
        except Exception as e:
            ultimo_error = e
            es_cuota = '429' in str(e) or 'RESOURCE_EXHAUSTED' in str(e).upper()
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
    datos_texto = "\n".join([
        f"- [{h.get('Riesgo', '')}] {desarmar_payloads(h.get('Vulnerabilidad', ''))}"
        for h in hallazgos[:MAX_HALLAZGOS_EJECUTIVO]
    ])
    escaneres_str = " + ".join(escaneres_lista)
    prompt = f"""Actúa como el Consultor Estratégico CISO de Sigmac Corp. Redacta un Análisis Ejecutivo para la Junta Directiva. Objetivo: {objetivo}. Escáneres combinados: {escaneres_str}. Hallazgos: {datos_texto}.
    REGLAS ESTRICTAS:
    1. CERO JERGA TÉCNICA. Habla de riesgo de negocio, fugas de datos y reputación.
    2. PROHIBIDO Markdown. Usa saltos de línea (ENTER).
    ESTRUCTURA OBLIGATORIA:
    IMPACTO OPERACIONAL Y FINANCIERO: (Describe el riesgo de negocio global en 2 párrafos fuertes).
    VULNERABILIDADES CRITICAS IDENTIFICADAS: (Agrupa los hallazgos en conceptos de negocio, ej. 'Riesgo de robo de sesiones' en lugar de XSS).
    PLAN DE ACCION ESTRATEGICO (ROADMAP): (3 pasos gerenciales claros para mitigar el riesgo)."""
    try:
        texto = llamar_ia_con_reintentos(cliente, MODELO_EJECUTIVO, prompt)
        return texto.replace('*', '').replace('#', '').replace('$', '')
    except Exception as e:
        return f"Análisis ejecutivo maestro no disponible: {e}"


def analizar_tecnico_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    datos_texto_lista = []
    for h in hallazgos[:MAX_HALLAZGOS_TECNICO]:
        impacto_str   = str(h.get('Impacto', ''))
        impacto_limpio = impacto_str[:250] + "..." if len(impacto_str) > 250 else impacto_str
        datos_texto_lista.append(
            f"- [{h.get('Riesgo', '')}] {desarmar_payloads(h.get('Vulnerabilidad', ''))} "
            f"en la ruta {h.get('Ruta', 'Global')}: {desarmar_payloads(impacto_limpio)}"
        )
    datos_texto   = "\n".join(datos_texto_lista)
    escaneres_str = " + ".join(escaneres_lista)

    prompt = f"""Actúa como un experto en seguridad ofensiva y análisis de vulnerabilidades web (Red Team) para Sigmac Corp.
    Tu tarea es generar una Guía Técnica Maestra basada en el inventario consolidado. Objetivo: {objetivo}. Escáneres: {escaneres_str}.
    Hallazgos consolidados detectados:
    {datos_texto}

    REGLAS ESTRICTAS Y LIMITACIONES TÉCNICAS:
    1. PROHIBIDO usar formato Markdown. Usa títulos en MAYÚSCULAS y separa párrafos con saltos de línea (ENTER).
    2. PROHIBIDO generar código de explotación real (PoC). Explica el Vector de Ataque de forma puramente conceptual.
    3. Tono impersonal, estructurado y altamente técnico.

    ESTRUCTURA OBLIGATORIA:
    RESUMEN EJECUTIVO TECNICO: (2 párrafos: estadísticas generales y clasificación de riesgos principales como SQLi, XSS, CSRF, SSRF, etc.).

    ANALISIS DE VULNERABILIDADES PRINCIPALES: (Prioriza por severidad. Los 3 o 4 hallazgos más críticos, para CADA UNO):
    - VULNERABILIDAD: [Nombre y Severidad]
    - ENDPOINT AFECTADO: [Ruta]
    - DESCRIPCION TECNICA: [Descripción técnica clara]
    - VECTOR DE ATAQUE CONCEPTUAL Y EVIDENCIA: [Cómo se explotaría sin código fuente malicioso]
    - IMPACTO POTENCIAL: [En negocio y seguridad]
    - REMEDIACION CONCRETA: [Pasos de solución exactos]
    - REFERENCIAS: [OWASP, CWE aplicables]

    ANALISIS ADICIONAL:
    - ENDPOINTS SUSCEPTIBLES A FUZZING: (Parámetros o rutas inyectables detectadas).
    - PATRONES DE AUTENTICACION Y ACCESO: (Diagnóstico sobre la protección observada o puntos ciegos)."""

    try:
        texto = llamar_ia_con_reintentos(cliente, MODELO_TECNICO, prompt)
        return texto.replace('*', '').replace('#', '').replace('$', '')
    except Exception as e:
        return f"Análisis técnico maestro no disponible: {e}"


# ==========================================
# 9. RENDERIZADO DE PLANTILLA HTML
# ==========================================
def obtener_base64_img(ruta_img):
    if not ruta_img or not os.path.exists(ruta_img):
        return ""
    with open(ruta_img, "rb") as img_file:
        return f"data:image/png;base64,{base64.b64encode(img_file.read()).decode('utf-8')}"


PLANTILLA_HTML = """
<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><style>
:root { --primary: #0F1B2D; --accent: #1A8C4E; --text-dark: #2C3E50; }
body { font-family: 'Helvetica', Arial, sans-serif; color: var(--text-dark); line-height: 1.6; margin: 0; padding: 20px; background-color: #f9f9f9;}
.container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 0 20px rgba(0,0,0,0.05); }
.cover-page { display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); padding: 50px 0; margin-bottom: 40px; border-radius: 8px;}
.cover-logos img { max-width: 180px; margin-bottom: 30px; }
.cover-title { font-size: 32px; font-weight: bold; color: var(--primary); text-transform: uppercase; margin-bottom: 10px; }
.cover-subtitle { font-size: 18px; color: var(--accent); margin-bottom: 30px; }
h2 { color: var(--primary); border-bottom: 2px solid var(--accent); padding-bottom: 5px; margin-top: 40px; }
.vuln-card { background: #fff; border-left: 5px solid #ccc; padding: 15px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-radius: 0 8px 8px 0;}
.vuln-card.critical { border-left-color: #8B0000; } .vuln-card.high { border-left-color: #D32F2F; } .vuln-card.medium { border-left-color: #F57C00; } .vuln-card.low { border-left-color: #FBC02D; }
.vuln-header { display: flex; justify-content: space-between; align-items: center; font-weight: bold; font-size: 16px; margin: 0; }
.badge { padding: 4px 8px; color: white; border-radius: 4px; font-size: 12px; }
.badge-critical { background-color: #8B0000; } .badge-high { background-color: #D32F2F; } .badge-medium { background-color: #F57C00; } .badge-low { background-color: #FBC02D; } .badge-informational { background-color: #455A64; }
.vuln-route { font-size: 13px; color: #777; font-style: italic; margin-top: 5px; }
.vuln-impact { font-size: 14px; margin-top: 10px; text-align: justify; }
.dashboard-grid { display: flex; justify-content: space-around; align-items: center; margin-top: 30px; flex-wrap: wrap;}
.dashboard-img { max-width: 45%; border-radius: 8px; margin-bottom: 20px;}
@media print { body { background-color: white; } .container { box-shadow: none; padding: 0; max-width: 100%;} .cover-page { height: 100vh; page-break-after: always; margin-bottom: 0;} h2 { page-break-before: auto; } }
</style></head><body>
<div class="container">
    <div class="cover-page">
        <div class="cover-logos">{% if logo_sigmac %}<img src="{{ logo_sigmac }}">{% endif %}</div>
        <div class="cover-title">{{ titulo }}</div><div class="cover-subtitle">Motores Combinados: {{ escaneres }}</div>
        <div style="margin-top: 30px; font-size: 16px; color: #555;"><p><strong>Objetivo:</strong> {{ objetivo }}</p><p><strong>Fecha:</strong> {{ fecha }}</p></div>
    </div>
    <h2>1. Dashboard Consolidado</h2>
    <div class="dashboard-grid">{% if img_radar %}<img src="{{ img_radar }}" class="dashboard-img">{% endif %}{% if img_sev %}<img src="{{ img_sev }}" class="dashboard-img">{% endif %}</div>
    <div style="text-align: center; margin-top: 20px;">{% if img_tip %}<img src="{{ img_tip }}" style="max-width: 90%; border-radius: 8px;">{% endif %}</div>
    <h2>2. Análisis Maestro</h2>
    <div style="font-size: 15px; text-align: justify; white-space: pre-wrap; line-height: 1.8;">{{ analisis_ia }}</div>
    {% if not es_ejecutivo %}
    <h2>3. Inventario Unificado</h2>
    {% for h in hallazgos %}<div class="vuln-card {{ h.Riesgo | lower }}"><div class="vuln-header"><span>{{ h.Vulnerabilidad }}</span><span class="badge badge-{{ h.Riesgo | lower }}">{{ h.Riesgo | upper }}</span></div><p class="vuln-route">📍 Endpoint: {{ h.Ruta }}</p><div class="vuln-impact">{{ h.Impacto }}</div></div>{% endfor %}
    {% endif %}
</div>
</body></html>
"""


def generar_html_maestro(titulo, img_sev, img_tip, img_radar, analisis_ia,
                          hallazgos_traducidos, objetivo, escaneres_lista,
                          logo_sigmac, es_ejecutivo=True):
    template   = Template(PLANTILLA_HTML)
    html_render = template.render(
        titulo=titulo,
        escaneres=" + ".join(escaneres_lista),
        objetivo=objetivo,
        fecha=fecha_larga_es(),
        logo_sigmac=obtener_base64_img(logo_sigmac),
        img_sev=obtener_base64_img(img_sev),
        img_tip=obtener_base64_img(img_tip),
        img_radar=obtener_base64_img(img_radar),
        analisis_ia=analisis_ia,
        hallazgos=hallazgos_traducidos,
        es_ejecutivo=es_ejecutivo
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
                            "Auditoria Estrategica Consolidada",
                            p_sev, p_tip, p_rad, ia_ejec, h_trad,
                            obj, esc_lista, "logo_sigmac.jpg", es_ejecutivo=True
                        )
                        st.session_state.html_tecnico = generar_html_maestro(
                            "Reporte Tecnico Maestro",
                            p_sev, p_tip, '', ia_tec, h_trad,
                            obj, esc_lista, "logo_sigmac.jpg", es_ejecutivo=False
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
