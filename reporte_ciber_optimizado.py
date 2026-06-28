# ======================================================================
# SIGMAC CORP — GENERADOR DE REPORTES MAESTROS DE CIBERSEGURIDAD
# Versión optimizada — Junio 2026
# ======================================================================
# Cambios clave respecto a la versión original (ver notas al final del
# archivo / mensaje de chat para el detalle completo):
#   1. Tipografía Unicode real (DejaVu Sans/Serif, vienen con matplotlib)
#      -> ya no se pierden tildes/ñ/comillas al recodificar a latin-1.
#   2. fpdf2 2.8+ ya parte por carácter SOLO los tokens demasiado largos
#      (URLs sin espacios, etc.) en modo WORD por defecto -> se eliminó el
#      "hack" original de insertar espacios cada 30 caracteres, que rompía
#      palabras y URLs de forma fea.
#   3. Paleta alineada a la guía de marca oficial de Sigmac Corp
#      (Navy Profundo #0F1B2D / Verde Sigmac #1A8C4E / Texto #2C3E50),
#      sin tocar la paleta semántica de severidad (rojo→ámbar→amarillo),
#      que se queda como estándar de industria.
#   4. Reintentos con backoff exponencial en las llamadas a Gemini
#      (mitiga los 429 RESOURCE_EXHAUSTED ya documentados en la infra).
#   5. El inventario técnico completo ya NO se trunca silenciosamente a
#      los primeros 30 hallazgos: se traduce todo en lotes.
#   6. Ejecutable también fuera de Colab (útil para correrlo en un
#      contenedor del stack Sigmac-IAOps si algún día se automatiza).
# ======================================================================

# ==========================================
# 1. INSTALACIÓN DE DEPENDENCIAS (solo Colab)
# ==========================================
# La siguiente línea es "magic" de Jupyter/Colab y se ignora si este
# archivo se ejecuta como script .py normal (ver bloque EN_COLAB abajo).
get_ipython().system('pip install -q fpdf2 matplotlib numpy google-genai urllib3') if 'get_ipython' in dir() else None

import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import numpy as np
from fpdf import FPDF
import os
import re
import json
import time
import html
from urllib.parse import urlparse
from datetime import datetime

try:
    from google.colab import drive, files
    EN_COLAB = True
except ImportError:
    EN_COLAB = False

try:
    from google import genai
except ImportError:
    genai = None

# ==========================================
# 2. CONFIGURACIÓN GLOBAL (ajustable en un solo lugar)
# ==========================================
MODELO_TRADUCCION = 'gemini-2.5-flash'
MODELO_EJECUTIVO = 'gemini-2.5-flash'
MODELO_TECNICO = 'gemini-2.5-flash'

MAX_HALLAZGOS_PROMPT_EJECUTIVO = 15   # cuántos hallazgos se resumen en el prompt ejecutivo
MAX_HALLAZGOS_PROMPT_TECNICO = 20     # cuántos hallazgos se resumen en el prompt técnico
LOTE_TRADUCCION = 25                  # tamaño de lote para traducir el inventario COMPLETO

REINTENTOS_IA = 4
ESPERA_BASE_SEG = 6   # backoff exponencial: 6s, 12s, 24s, 48s...

# --- Paleta corporativa oficial Sigmac Corp (identidad de marca) ---
COLOR_NAVY = (15, 27, 45)        # Navy Profundo  #0F1B2D — banners y portada
COLOR_VERDE = (26, 140, 78)      # Verde Sigmac   #1A8C4E — acentos, gráficas neutras
COLOR_TEXTO = (44, 62, 80)       # Texto Principal #2C3E50 — cuerpo de texto
COLOR_SUAVE = (107, 124, 147)    # Texto Suave    #6B7C93 — metadatos, pies de página
COLOR_BORDE = (228, 235, 242)    # Borde Tarjeta  #E4EBF2 — líneas divisorias

# --- Paleta semántica de severidad (estándar de industria, NO de marca) ---
# Se deja independiente de la marca a propósito: el rojo de "Critical" no
# debe volverse verde solo por consistencia visual, perdería su función.
COLORES_SEVERIDAD = {
    "Critical": (139, 0, 0),
    "High": (211, 47, 47),
    "Medium": (245, 124, 0),
    "Low": (251, 192, 45),
    "Informational": (69, 90, 100),
}


MESES_ES = {1: 'enero', 2: 'febrero', 3: 'marzo', 4: 'abril', 5: 'mayo', 6: 'junio',
            7: 'julio', 8: 'agosto', 9: 'septiembre', 10: 'octubre', 11: 'noviembre', 12: 'diciembre'}


def fecha_larga_es(fecha=None):
    """Fecha en español ('27 de junio de 2026') sin depender del locale del
    sistema operativo: strftime('%B') dependía del locale y en Colab suele
    devolver el mes en inglés."""
    fecha = fecha or datetime.now()
    return f"{fecha.day} de {MESES_ES[fecha.month]} de {fecha.year}"


def _hex(rgb):
    return '#%02x%02x%02x' % rgb


# ==========================================
# 3. RUTAS DE ACTIVOS (Drive en Colab / locales fuera de Colab)
# ==========================================
if EN_COLAB:
    if not os.path.exists('/content/drive'):
        drive.mount('/content/drive')
    carpeta_assets = '/content/drive/MyDrive/'
else:
    carpeta_assets = os.environ.get('SIGMAC_ASSETS_DIR', './assets')

ruta_api = os.path.join(carpeta_assets, 'api.txt')
ruta_logo = os.path.join(carpeta_assets, 'logo_sigmac.jpg')


def inicializar_cliente_ia():
    """Carga la API Key desde Drive (Colab) o desde variable de entorno /
    archivo local (fuera de Colab) e inicializa el cliente de Gemini."""
    if genai is None:
        print("❌ El paquete 'google-genai' no está instalado.")
        return None

    api_key = None
    if EN_COLAB:
        try:
            with open(ruta_api, 'r') as f:
                api_key = f.read().strip()
        except Exception as e:
            print(f"❌ Error al leer la API Key desde Drive: {e}")
    else:
        api_key = os.environ.get('GEMINI_API_KEY')
        if not api_key and os.path.exists('./api.txt'):
            with open('./api.txt') as f:
                api_key = f.read().strip()

    if not api_key:
        print("❌ No se encontró la API Key de Gemini (Drive/api.txt o variable GEMINI_API_KEY).")
        return None

    try:
        cliente = genai.Client(api_key=api_key)
        print("✅ API Key cargada correctamente.")
        return cliente
    except Exception as e:
        print(f"❌ Error al inicializar el cliente de IA: {e}")
        return None


cliente_ia = inicializar_cliente_ia()

# ==========================================
# 4. FUNCIONES CORE, BLINDAJE Y DESARMADOR
# ==========================================
def limpiar_html(texto):
    if not texto:
        return "N/A"
    t = html.unescape(str(texto))
    t = re.sub(r'<[^>]+>', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()


def blindaje_fpdf(texto, truncar_log=False, unicode_ok=True):
    """Sanitiza texto para insertarlo en el PDF.

    Con fuente Unicode embebida (unicode_ok=True), fpdf2 ya maneja el
    word-wrap (incluyendo tokens largos sin espacios) sin ayuda extra, así
    que ya no es necesario insertar espacios artificiales cada 30
    caracteres ni recodificar a latin-1 (eso perdía tildes/ñ/comillas).
    Si por algún motivo la fuente Unicode no estuviera disponible, se
    conserva el respaldo a latin-1 para no romper la generación del PDF.
    """
    if not texto:
        return "N/A"
    t = html.unescape(str(texto))
    t = re.sub(r'<[^>]+>', ' ', t)
    t = str(t).replace('\r', '').replace('\t', ' ').replace('\xa0', ' ')
    t = re.sub(r'[-=_*#]{10,}', '---', t)
    if truncar_log and len(t) > 1200:
        t = t[:1197] + "...\n[DUMP TRUNCADO POR SEGURIDAD DE FORMATO]"
    lineas = t.split('\n')
    lineas_limpias = [re.sub(r' +', ' ', linea).strip() for linea in lineas]
    t = '\n'.join(lineas_limpias)
    if unicode_ok:
        return t
    return t.encode('latin-1', 'replace').decode('latin-1')


def desarmar_payloads(texto):
    """🔥 NEUTRALIZA CÓDIGO MALICIOSO PARA QUE LA API DE GOOGLE NO LO BLOQUEE"""
    if not texto:
        return ""
    t = str(texto)
    t = t.replace('<', '【').replace('>', '】')
    t = re.sub(r'(?i)(alert\(|prompt\(|confirm\(|eval\()', 'alerta_bloqueada(', t)
    return t


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
    if not url:
        return "desconocido"
    url = url.lower().strip()
    if not url.startswith('http'):
        url = 'http://' + url
    return urlparse(url).netloc.split(':')[0]


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
            dominio_obj = normalizar_objetivo(objetivo)
            if dominio_ruta and dominio_obj and dominio_ruta != dominio_obj:
                return "Global"
        except ValueError:
            pass  # URL malformada: se conserva la ruta original, no es un error crítico
    return ruta


# ==========================================
# 5. MOTOR DE EXTRACCIÓN MODULAR Y DE RUTAS
# ==========================================
def clasificar_y_guardar(sev_norm, nombre, impacto, ruta, r_riesgos, r_tipos, hallazgos):
    r_riesgos[sev_norm] += 1
    if sev_norm in ["Critical", "High", "Medium", "Low"]:
        nombre_low = str(nombre).lower()
        if "disclosure" in nombre_low or "leak" in nombre_low or "info" in nombre_low:
            tipo_es = "Fuga de Informacion"
        elif "ssl" in nombre_low or "tls" in nombre_low or "cipher" in nombre_low or "certificate" in nombre_low or "crypt" in nombre_low:
            tipo_es = "Criptografía Débil"
        elif "outdated" in nombre_low or "version" in nombre_low or "obsolete" in nombre_low:
            tipo_es = "Software Obsoleto"
        elif "hsts" in nombre_low or "header" in nombre_low or "cookie" in nombre_low or "csrf" in nombre_low or "clickjacking" in nombre_low or "cors" in nombre_low:
            tipo_es = "Debilidad Perimetral"
        else:
            tipo_es = "Mala Configuracion"
        r_tipos[tipo_es] = r_tipos.get(tipo_es, 0) + 1

        hallazgos.append({
            "Riesgo": sev_norm,
            "Vulnerabilidad": limpiar_html(nombre),
            "Impacto": limpiar_html(impacto),
            "Ruta": limpiar_html(ruta),
        })


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
        loc = item.find('location')
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
    resumen_riesgos = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    resumen_tipos = {}
    hallazgos_crudos = []
    objetivo = "Infraestructura no identificada"
    escaner = "Desconocido"

    try:
        xml_content = re.sub(r'\bxsi:[a-zA-Z0-9_]+="[^"]*"', '', xml_content)
        root = ET.fromstring(xml_content)
        root_tag = root.tag.lower()

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

        start_url = root.find('.//StartURL')
        host_tag = root.find('.//ReportHost')
        site_tag = root.find('.//site')
        burp_host = root.find('.//host')
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

        if escaner == "Wapiti":
            for item in root.findall('.//vulnerability'):
                nombre = item.get('name', 'Hallazgo Wapiti')
                level_tag = item.find('.//level')
                if level_tag is not None and level_tag.text:
                    sev_val = level_tag.text
                else:
                    sev_val = 'High' if any(x in nombre.lower() for x in ['sql', 'xss', 'injection', 'exec']) else 'Medium'
                sev_norm = mapear_severidad(sev_val)
                impacto_tag = item.find('description')
                ruta_limpia = limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo)
                clasificar_y_guardar(sev_norm, nombre, impacto_tag.text if impacto_tag is not None else "Sin detalles.", ruta_limpia, resumen_riesgos, resumen_tipos, hallazgos_crudos)

        elif escaner == "OWASP ZAP":
            for item in root.findall('.//alertitem'):
                sev_tag = item.find('riskcode')
                sev_norm = 'Informational' if (sev_tag is not None and str(sev_tag.text) == '0') else mapear_severidad(sev_tag.text if sev_tag is not None else '0')
                nombre_tag = item.find('alert')
                impacto_tag = item.find('desc')
                ruta_limpia = limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo)
                clasificar_y_guardar(sev_norm, nombre_tag.text if nombre_tag is not None else 'Hallazgo', impacto_tag.text if impacto_tag is not None else "", ruta_limpia, resumen_riesgos, resumen_tipos, hallazgos_crudos)

        elif escaner == "Burp Suite":
            for item in root.findall('.//issue'):
                sev_tag = item.find('severity')
                nombre_tag = item.find('name')
                impacto_bg = item.find('issueBackground')
                impacto_dt = item.find('issueDetail')
                impacto = impacto_bg.text if impacto_bg is not None else (impacto_dt.text if impacto_dt is not None else "")
                ruta_limpia = limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo)
                clasificar_y_guardar(mapear_severidad(sev_tag.text if sev_tag is not None else 'Information'), nombre_tag.text if nombre_tag is not None else 'Hallazgo', impacto, ruta_limpia, resumen_riesgos, resumen_tipos, hallazgos_crudos)

        else:
            for item in root.findall('.//ReportItem'):
                sev_tag = item.find('Severity')
                if sev_tag is None:
                    sev_tag = item.get('severity')
                sev_val = sev_tag.text if hasattr(sev_tag, 'text') else sev_tag
                if sev_val is None:
                    continue
                nombre_tag = item.find('Name')
                impacto_tag = item.find('Impact')
                if impacto_tag is None:
                    impacto_tag = item.find('Description')
                ruta_limpia = limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo)
                clasificar_y_guardar(mapear_severidad(sev_val), nombre_tag.text if nombre_tag is not None else item.get('pluginName', 'Hallazgo'), impacto_tag.text if impacto_tag is not None else "", ruta_limpia, resumen_riesgos, resumen_tipos, hallazgos_crudos)

        return resumen_riesgos, resumen_tipos, hallazgos_crudos, objetivo, escaner
    except ET.ParseError as e:
        print(f"❌ XML mal formado, se omite este archivo: {e}")
        return None, None, None, None, None
    except Exception as e:
        print(f"❌ Error inesperado parseando un XML: {e}")
        return None, None, None, None, None


# ==========================================
# 6. CONSOLIDADOR MULTI-ESCÁNER
# ==========================================
def consolidar_reportes(archivos_cargados):
    total_riesgos = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    total_tipos = {}
    total_hallazgos = []
    escaneres_detectados = set()
    objetivo_maestro = None
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
            print(f"⚠️ ADVERTENCIA: Conflicto detectado en {nombre_archivo}. Difiere del servidor principal. Archivo excluido.")
            continue

        escaneres_detectados.add(escaner)

        for k, v in r_riesgos.items():
            total_riesgos[k] += v
        for k, v in r_tipos.items():
            total_tipos[k] = total_tipos.get(k, 0) + v
        total_hallazgos.extend(hallazgos)

    madurez = {"Hardening": 10.0, "Criptografía": 10.0, "Protección de Datos": 10.0, "Gestión de Parches": 10.0, "Perímetro": 10.0}
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
    total_hallazgos = sorted(total_hallazgos, key=lambda x: orden_severidad.get(x.get("Riesgo", "Informational"), 6))

    return total_riesgos, total_tipos, madurez, total_hallazgos, objetivo_maestro, list(escaneres_detectados)


# ==========================================
# 7. GRÁFICAS Y TRADUCCIÓN / REDACCIÓN IA
# ==========================================
def generar_graficas_completas(datos_sev, datos_tip, madurez, r_sev, r_tip, r_radar):
    c_sev = [k for k, v in datos_sev.items() if v > 0]
    v_sev = [v for k, v in datos_sev.items() if v > 0]
    if len(v_sev) > 0:
        plt.figure(figsize=(4.5, 3.5))
        plt.pie(
            v_sev, labels=c_sev,
            colors=[_hex(COLORES_SEVERIDAD.get(c, (204, 204, 204))) for c in c_sev],
            autopct='%1.1f%%', textprops={'fontsize': 9, 'weight': 'bold'},
        )
        plt.gcf().gca().add_artist(plt.Circle((0, 0), 0.70, fc='white'))
        plt.title('Distribución de Riesgo Global', fontweight='bold', color=_hex(COLOR_TEXTO))
        plt.savefig(r_sev, dpi=300, transparent=True, bbox_inches='tight')
        plt.close()

    if len(datos_tip) > 0:
        plt.figure(figsize=(5, 3))
        plt.barh(list(datos_tip.keys()), list(datos_tip.values()), color=_hex(COLOR_VERDE))
        plt.gca().spines['top'].set_visible(False)
        plt.gca().spines['right'].set_visible(False)
        plt.savefig(r_tip, dpi=300, transparent=True, bbox_inches='tight')
        plt.close()

    labels = np.array(list(madurez.keys()))
    stats = np.array(list(madurez.values()))
    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False)
    stats = np.concatenate((stats, [stats[0]]))
    angles = np.concatenate((angles, [angles[0]]))
    fig, ax = plt.subplots(figsize=(4.5, 4.5), subplot_kw=dict(polar=True))
    ax.fill(angles, stats, color=_hex(COLOR_VERDE), alpha=0.25)
    ax.plot(angles, stats, color=_hex(COLOR_VERDE), linewidth=2)
    ax.set_yticklabels([])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=9, fontweight='bold', color=_hex(COLOR_TEXTO))
    ax.set_ylim(0, 10)
    plt.savefig(r_radar, dpi=300, transparent=True, bbox_inches='tight')
    plt.close()


def llamar_ia_con_reintentos(cliente, modelo, prompt, intentos=REINTENTOS_IA, espera_base=ESPERA_BASE_SEG):
    """Llama a Gemini con reintentos y backoff exponencial.

    Esto mitiga directamente el problema de cuota (429 RESOURCE_EXHAUSTED)
    ya documentado en la infraestructura de Sigmac-IAOps, que obligó a
    reemplazar el scheduler de IA por un cron nativo en monitor.js.
    """
    ultimo_error = None
    for intento in range(1, intentos + 1):
        try:
            respuesta = cliente.models.generate_content(model=modelo, contents=prompt)
            return respuesta.text
        except Exception as e:
            ultimo_error = e
            es_cuota = '429' in str(e) or 'RESOURCE_EXHAUSTED' in str(e).upper()
            if intento < intentos:
                espera = espera_base * (2 ** (intento - 1))
                motivo = "cuota excedida (429)" if es_cuota else "error de API"
                print(f"   ⚠️ Intento {intento}/{intentos} falló ({motivo}). Reintentando en {espera}s...")
                time.sleep(espera)
            else:
                print(f"   ❌ Se agotaron los reintentos. Último error: {e}")
    raise ultimo_error


def traducir_inventario_json(hallazgos, cliente):
    """Traduce TODO el inventario en lotes (antes se descartaba todo lo que
    pasara de los primeros 30 hallazgos; ahora cada lote que falle conserva
    su texto original en vez de desaparecer del reporte)."""
    print(f"🌐 [IA] Traduciendo {len(hallazgos)} hallazgo(s) en lotes de {LOTE_TRADUCCION}...")
    resultado_total = []
    for i in range(0, len(hallazgos), LOTE_TRADUCCION):
        lote = hallazgos[i:i + LOTE_TRADUCCION]
        numero_lote = i // LOTE_TRADUCCION + 1
        prompt = (
            "Traduce al español técnico SOLAMENTE los valores de 'Vulnerabilidad' e 'Impacto'. "
            "Las claves 'Riesgo' y 'Ruta' DEBEN QUEDAR EXACTAMENTE IGUAL. "
            "Devuelve el JSON puro, sin texto adicional ni backticks:\n"
            + json.dumps(lote, ensure_ascii=False)
        )
        try:
            respuesta = llamar_ia_con_reintentos(cliente, MODELO_TRADUCCION, prompt)
            respuesta = respuesta.replace("```json", "").replace("```", "").strip()
            lote_traducido = json.loads(respuesta)
            if isinstance(lote_traducido, list) and len(lote_traducido) == len(lote):
                resultado_total.extend(lote_traducido)
            else:
                print(f"   ⚠️ Lote {numero_lote}: forma inesperada en la respuesta, se conserva sin traducir.")
                resultado_total.extend(lote)
        except Exception as e:
            print(f"   ⚠️ Lote {numero_lote} no se pudo traducir ({e}). Se conserva en su idioma original.")
            resultado_total.extend(lote)
    return resultado_total


def analizar_ejecutivo_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    print("🧠 [1/2] Redactando reporte EJECUTIVO MAESTRO con IA...")
    datos_texto = "\n".join([f"- [{h.get('Riesgo', '')}] {desarmar_payloads(h.get('Vulnerabilidad', ''))}" for h in hallazgos[:MAX_HALLAZGOS_PROMPT_EJECUTIVO]])
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
        print(f"❌ Error en IA Ejecutiva: {e}")
        return "Análisis ejecutivo maestro no disponible."


def analizar_tecnico_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    print("🧠 [2/2] Redactando reporte TÉCNICO MAESTRO con el Prompt Ofensivo...")

    datos_texto_lista = []
    for h in hallazgos[:MAX_HALLAZGOS_PROMPT_TECNICO]:
        impacto_limpio = str(h.get('Impacto', ''))[:250] + "..." if len(str(h.get('Impacto', ''))) > 250 else str(h.get('Impacto', ''))
        impacto_desarmado = desarmar_payloads(impacto_limpio)
        vuln_desarmada = desarmar_payloads(h.get('Vulnerabilidad', ''))
        datos_texto_lista.append(f"- [{h.get('Riesgo', '')}] {vuln_desarmada} en la ruta {h.get('Ruta', 'Global')}: {impacto_desarmado}")

    datos_texto = "\n".join(datos_texto_lista)
    escaneres_str = " + ".join(escaneres_lista)

    prompt = f"""Actúa como un experto en seguridad ofensiva y análisis de vulnerabilidades web (Red Team) para Sigmac Corp.
    Tu tarea es generar una Guía Técnica Maestra basada en el inventario consolidado. Objetivo: {objetivo}. Escáneres: {escaneres_str}.
    Hallazgos consolidados detectados en el tráfico/logs:
    {datos_texto}

    REGLAS ESTRICTAS Y LIMITACIONES TÉCNICAS:
    1. PROHIBIDO usar formato Markdown (no uses asteriscos, ni hashes, ni tablas). El reporte se imprimirá en un PDF estricto que no soporta tablas. Usa títulos en MAYÚSCULAS y separa los párrafos con saltos de línea (ENTER).
    2. PROHIBIDO generar código de explotación real (PoC en Python o Curl). Explica el "Vector de Ataque o PoC" de forma puramente conceptual en texto descriptivo para evitar bloqueos de seguridad anti-malware.
    3. Tono impersonal, estructurado y altamente técnico.

    ESTRUCTURA OBLIGATORIA:
    RESUMEN EJECUTIVO TECNICO: (En 2 párrafos, resume las estadísticas generales y clasifica los riesgos principales identificados como SQLi, XSS, CSRF, SSRF, Autenticación, Exposición de Info, etc., según aplique a los datos proporcionados).

    ANALISIS DE VULNERABILIDADES PRINCIPALES: (Prioriza por severidad descendente. Selecciona los 3 o 4 hallazgos más críticos y para CADA UNO redacta un bloque con esta información exacta):
    - VULNERABILIDAD: [Nombre y Severidad]
    - ENDPOINT AFECTADO: [Ruta]
    - DESCRIPCION TECNICA: [Descripción técnica clara]
    - VECTOR DE ATAQUE CONCEPTUAL Y EVIDENCIA: [Explica cómo se explotaría y la confirmación en el tráfico sin escribir código fuente malicioso]
    - IMPACTO POTENCIAL: [En negocio y seguridad]
    - REMEDIACION CONCRETA: [Pasos de solución exactos]
    - REFERENCIAS: [OWASP, CWE aplicables]

    ANALISIS ADICIONAL:
    - ENDPOINTS SUSCEPTIBLES A FUZZING: (Menciona parámetros o rutas detectadas que podrían ser inyectables).
    - PATRONES DE AUTENTICACION Y ACCESO: (Diagnóstico sobre la protección observada o puntos ciegos)."""

    try:
        texto = llamar_ia_con_reintentos(cliente, MODELO_TECNICO, prompt)
        return texto.replace('*', '').replace('#', '').replace('$', '')
    except Exception as e:
        print(f"❌ Error en IA Técnica: {e}")
        return "Análisis técnico maestro no disponible."


# ==========================================
# 8. CLASE PDF Y DISEÑO CORPORATIVO
# ==========================================
def localizar_fuentes_dejavu():
    """Ubica DejaVu Sans/Serif, que vienen incluidas con matplotlib.
    Da soporte Unicode completo (tildes, ñ, comillas) sin depender de
    descargas externas ni de conexión a internet."""
    base = os.path.join(matplotlib_get_data_path(), 'fonts', 'ttf')
    rutas = {
        'sans_regular': os.path.join(base, 'DejaVuSans.ttf'),
        'sans_bold': os.path.join(base, 'DejaVuSans-Bold.ttf'),
        'sans_italic': os.path.join(base, 'DejaVuSans-Oblique.ttf'),
        'serif_bold': os.path.join(base, 'DejaVuSerif-Bold.ttf'),
    }
    faltantes = [k for k, v in rutas.items() if not os.path.exists(v)]
    if faltantes:
        print(f"⚠️ No se encontraron fuentes empaquetadas con matplotlib ({faltantes}). Se usará 'helvetica' (sin Unicode completo).")
        return None
    return rutas


def matplotlib_get_data_path():
    import matplotlib
    return matplotlib.get_data_path()


class ReporteSigmac(FPDF):
    def __init__(self, logo_path, titulo_doc, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logo_path = logo_path
        self.titulo_doc = titulo_doc

        self.fuentes_unicode = localizar_fuentes_dejavu()
        if self.fuentes_unicode:
            self.add_font('Body', '', self.fuentes_unicode['sans_regular'])
            self.add_font('Body', 'B', self.fuentes_unicode['sans_bold'])
            self.add_font('Body', 'I', self.fuentes_unicode['sans_italic'])
            self.add_font('Titulo', 'B', self.fuentes_unicode['serif_bold'])
            self.fuente_cuerpo = 'Body'
            self.fuente_titulo = 'Titulo'
        else:
            self.fuente_cuerpo = 'helvetica'
            self.fuente_titulo = 'helvetica'

    def texto_multilinea(self, w, h, texto, align='J', truncar_log=False, **kwargs):
        """multi_cell ya blindado. Nota: fpdf2 >= 2.8 maneja en modo WORD
        (el default) los tokens demasiado largos (URLs sin espacios, etc.)
        partiéndolos solo a ellos sin desbordar la página, así que ya no
        hace falta forzar wrapmode='CHAR' en todo el texto (eso partía
        palabras normales como 'Ñandú' a la mitad)."""
        contenido = blindaje_fpdf(texto, truncar_log=truncar_log, unicode_ok=bool(self.fuentes_unicode))
        self.multi_cell(w, h, text=contenido, align=align, **kwargs)

    def header(self):
        if self.page_no() > 1:
            if os.path.exists(self.logo_path):
                self.image(self.logo_path, x=160, y=10, w=40)
            self.set_font(self.fuente_cuerpo, 'B', 10)
            self.set_text_color(*COLOR_TEXTO)
            self.cell(0, 10, text=f'{self.titulo_doc} - Sigmac Corp', border=False, align='L')
            self.set_draw_color(*COLOR_VERDE)
            self.set_line_width(0.5)
            self.line(10, 25, 200, 25)
            self.ln(15)

    def footer(self):
        if self.page_no() > 1:
            self.set_y(-15)
            self.set_draw_color(*COLOR_BORDE)
            self.line(10, 282, 200, 282)
            self.set_font(self.fuente_cuerpo, 'I', 8)
            self.set_text_color(*COLOR_SUAVE)
            self.cell(0, 10, text='CONFIDENCIAL - PROPIEDAD DE SIGMAC CORP.', align='L')
            self.set_x(0)
            self.cell(0, 10, text=f'Pagina {self.page_no()}', align='R')


def crear_banner_seccion(pdf, texto):
    """Título de sección con fondo Navy Profundo (marca oficial Sigmac)."""
    pdf.set_fill_color(*COLOR_NAVY)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(pdf.fuente_titulo, 'B', 14)
    pdf.cell(0, 12, text=f"  {texto}", fill=True, align='L', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)


def tamano_fuente_ajustado(pdf, texto, familia, estilo, tam_inicial, ancho_max, tam_min=14):
    """Reduce el tamaño de fuente hasta que el texto entre en una sola línea
    dentro de ancho_max. Necesario porque DejaVu Serif es más ancha que
    Helvetica: a tamaño fijo, títulos largos se salían de la página."""
    tam = tam_inicial
    pdf.set_font(familia, estilo, tam)
    while pdf.get_string_width(texto) > ancho_max and tam > tam_min:
        tam -= 1
        pdf.set_font(familia, estilo, tam)
    return tam


def caja_kpi(pdf, x, y, w, h, valor, etiqueta, color_rgb):
    """KPI con esquinas redondeadas (con respaldo automático a rectángulo
    recto si la versión de fpdf2 instalada no soporta round_corners)."""
    pdf.set_fill_color(*color_rgb)
    try:
        pdf.rect(x, y, w, h, style='F', round_corners=True, corner_radius=2)
    except TypeError:
        pdf.rect(x, y, w, h, style='F')

    pdf.set_text_color(255, 255, 255)
    pdf.set_font(pdf.fuente_cuerpo, 'B', 20)
    pdf.set_xy(x, y + 3)
    pdf.cell(w, 10, text=str(valor), align='C')

    pdf.set_font(pdf.fuente_cuerpo, '', 10)
    pdf.set_xy(x, y + 13)
    pdf.cell(w, 10, text=etiqueta.upper(), align='C')


def generar_pdf_maestro(titulo, img_sev, img_tip, img_radar, analisis_ia, hallazgos_traducidos, objetivo, escaneres_lista, logo, ruta_out, es_ejecutivo, total_riesgos):
    pdf = ReporteSigmac(logo_path=logo, titulo_doc=titulo)
    escaneres_str = " + ".join(escaneres_lista)

    # ---------------------------------------------------------
    # PAGINA 1: PORTADA
    # ---------------------------------------------------------
    pdf.add_page()
    pdf.ln(50)
    if os.path.exists(logo):
        pdf.image(logo, x=65, y=50, w=80)

    ancho_util = pdf.w - pdf.l_margin - pdf.r_margin

    pdf.ln(70)
    titulo_txt = titulo.upper()
    tamano_fuente_ajustado(pdf, titulo_txt, pdf.fuente_titulo, 'B', 28, ancho_util - 10, tam_min=16)
    pdf.set_text_color(*COLOR_NAVY)
    pdf.cell(0, 15, text=titulo_txt, align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    subtitulo_txt = f"Auditoría Consolidada: {escaneres_str}"
    tamano_fuente_ajustado(pdf, subtitulo_txt, pdf.fuente_cuerpo, '', 14, ancho_util - 10, tam_min=10)
    pdf.set_text_color(*COLOR_VERDE)
    pdf.cell(0, 10, text=subtitulo_txt, align='C', new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(*COLOR_BORDE)
    pdf.line(40, pdf.get_y() + 5, 170, pdf.get_y() + 5)
    pdf.ln(15)

    pdf.set_font(pdf.fuente_cuerpo, 'B', 14)
    pdf.set_text_color(*COLOR_NAVY)
    pdf.cell(0, 8, text="OBJETIVO EVALUADO:", align='C', new_x="LMARGIN", new_y="NEXT")
    tamano_fuente_ajustado(pdf, str(objetivo), pdf.fuente_cuerpo, '', 14, ancho_util - 10, tam_min=9)
    pdf.set_text_color(*COLOR_SUAVE)
    pdf.cell(0, 8, text=objetivo, align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(15)

    pdf.set_font(pdf.fuente_cuerpo, 'I', 12)
    pdf.set_text_color(*COLOR_SUAVE)
    pdf.cell(0, 6, text=f"Fecha de Emisión: {fecha_larga_es()}", align='C', new_x="LMARGIN", new_y="NEXT")

    # ---------------------------------------------------------
    # PAGINA 2: DASHBOARD Y KPIs
    # ---------------------------------------------------------
    pdf.add_page()
    crear_banner_seccion(pdf, "1. DASHBOARD DE POSTURA DE RIESGO")
    y_actual = pdf.get_y()

    if es_ejecutivo and total_riesgos:
        x_offset = 15
        for nivel in ["Critical", "High", "Medium", "Low"]:
            caja_kpi(pdf, x_offset, y_actual, 40, 25, total_riesgos.get(nivel, 0), nivel, COLORES_SEVERIDAD[nivel])
            x_offset += 45
        pdf.set_y(y_actual + 35)
        y_actual = pdf.get_y()

    if es_ejecutivo and os.path.exists(img_radar):
        pdf.image(img_radar, x=10, y=y_actual, w=90)
        if os.path.exists(img_sev):
            pdf.image(img_sev, x=110, y=y_actual + 5, w=85)
        pdf.set_y(y_actual + 90)
        if os.path.exists(img_tip):
            pdf.image(img_tip, x=35, y=pdf.get_y(), w=140)
        pdf.ln(80)
    else:
        if os.path.exists(img_sev):
            pdf.image(img_sev, x=10, y=y_actual, w=90)
        if os.path.exists(img_tip):
            pdf.image(img_tip, x=110, y=y_actual + 5, w=90)
        pdf.set_y(y_actual + 95)

    # ---------------------------------------------------------
    # PAGINA 3: ANÁLISIS MAESTRO IA
    # ---------------------------------------------------------
    pdf.add_page()
    if es_ejecutivo:
        crear_banner_seccion(pdf, "2. DIAGNÓSTICO ESTRATÉGICO (SIGMAC CORP)")
    else:
        crear_banner_seccion(pdf, "2. ANÁLISIS RED TEAM & VECTORES DE ATAQUE")

    pdf.set_font(pdf.fuente_cuerpo, '', 11)
    pdf.set_text_color(*COLOR_TEXTO)
    pdf.set_x(10)
    pdf.texto_multilinea(0, 6, analisis_ia, align='J')

    # ---------------------------------------------------------
    # PAGINA 4+: INVENTARIO TÉCNICO COMPLETO (solo reporte técnico)
    # ---------------------------------------------------------
    if not es_ejecutivo:
        pdf.add_page()
        crear_banner_seccion(pdf, f"3. INVENTARIO TÉCNICO DETALLADO ({len(hallazgos_traducidos)} hallazgos)")
        for h in hallazgos_traducidos:
            riesgo_str = h.get('Riesgo', 'Informational')
            pdf.set_font(pdf.fuente_cuerpo, 'B', 11)
            pdf.set_text_color(*COLORES_SEVERIDAD.get(riesgo_str, COLOR_SUAVE))

            titulo_h = f"[{riesgo_str.upper()}] {h.get('Vulnerabilidad', 'Desconocida')}"
            pdf.set_x(10)
            pdf.texto_multilinea(0, 6, titulo_h, align='L', truncar_log=True)

            ruta_h = h.get('Ruta', 'N/A')
            if ruta_h and ruta_h != "N/A":
                pdf.set_font(pdf.fuente_cuerpo, 'I', 9)
                pdf.set_text_color(*COLOR_SUAVE)
                pdf.set_x(10)
                if "Global" in ruta_h:
                    pdf.texto_multilinea(0, 5, "Alcance: Nivel Global / Servidor Completo", align='L', truncar_log=True)
                else:
                    pdf.texto_multilinea(0, 5, f"Endpoint detectado: {ruta_h}", align='L', truncar_log=True)

            pdf.set_font(pdf.fuente_cuerpo, '', 10)
            pdf.set_text_color(*COLOR_TEXTO)
            pdf.set_x(10)
            pdf.texto_multilinea(0, 5, h.get('Impacto', 'N/A'), align='J', truncar_log=True)
            pdf.ln(5)

    pdf.output(ruta_out)


# ==========================================
# 9. ENTRADA / SALIDA DE ARCHIVOS (Colab o local)
# ==========================================
def cargar_archivos_entrada():
    if EN_COLAB:
        print("Sube MÚLTIPLES archivos XML para consolidarlos por dominio (ZAP, Burp, Wapiti, Acunetix):")
        return files.upload()

    carpeta = os.environ.get('SIGMAC_INPUT_DIR', './input_xml')
    if not os.path.isdir(carpeta):
        print(f"❌ No existe la carpeta de entrada local: {carpeta}")
        return {}
    nombres = [f for f in os.listdir(carpeta) if f.lower().endswith('.xml')]
    if not nombres:
        print(f"❌ No se encontraron archivos .xml en {carpeta}")
        return {}
    print(f"📂 Cargando {len(nombres)} archivo(s) desde {carpeta}...")
    salida = {}
    for nombre in nombres:
        with open(os.path.join(carpeta, nombre), 'rb') as fh:
            salida[nombre] = fh.read()
    return salida


def entregar_archivo(ruta):
    if EN_COLAB:
        files.download(ruta)
    else:
        print(f"📄 Reporte generado en: {os.path.abspath(ruta)}")


# ==========================================
# 10. ORQUESTACIÓN PRINCIPAL
# ==========================================
def main():
    if not cliente_ia:
        print("❌ Asegúrate de tener tu API Key configurada.")
        return

    print("\n" + "=" * 50)
    print("🛡️ OMNISCANNER FASE 2: CONSOLIDACIÓN MULTI-MOTOR 🛡️")
    print("=" * 50)

    archivos_subidos = cargar_archivos_entrada()
    if not archivos_subidos:
        return

    print(f"\n🚀 Procesando y consolidando {len(archivos_subidos)} archivo(s)...")
    resultado_consolidado = consolidar_reportes(archivos_subidos)
    if not resultado_consolidado:
        return

    r_sev, r_tip, madurez, hallazgos, obj, esc_lista = resultado_consolidado
    if not hallazgos:
        print("❌ No se encontraron vulnerabilidades válidas en los archivos.")
        return

    print(f"✅ Validación de objetivo exitosa: {obj}")
    print(f"📊 Generando Dashboards Unificados (Motores: {', '.join(esc_lista)})...")
    generar_graficas_completas(r_sev, r_tip, madurez, 'sigmac_severidad.png', 'sigmac_tipos.png', 'sigmac_radar.png')

    print(f"⏳ Traduciendo {len(hallazgos)} hallazgo(s) (ya no se descarta nada por encima de 30)...")
    hallazgos_traducidos = traducir_inventario_json(hallazgos, cliente_ia)

    print("⏳ Redactando Reportes Inteligentes...")
    ia_ejecutiva = analizar_ejecutivo_con_ia(hallazgos_traducidos, obj, esc_lista, cliente_ia)
    ia_tecnica = analizar_tecnico_con_ia(hallazgos_traducidos, obj, esc_lista, cliente_ia)

    fecha_str = datetime.now().strftime("%Y%m%d")
    pdf_ejec = f'Reporte_Ejecutivo_Maestro_{fecha_str}.pdf'
    pdf_tec = f'Reporte_Tecnico_Maestro_{fecha_str}.pdf'

    print("📑 Ensamblando Súper Reporte Ejecutivo...")
    generar_pdf_maestro("Reporte Ejecutivo de Ciberseguridad", 'sigmac_severidad.png', 'sigmac_tipos.png', 'sigmac_radar.png', ia_ejecutiva, hallazgos_traducidos, obj, esc_lista, ruta_logo, pdf_ejec, es_ejecutivo=True, total_riesgos=r_sev)

    print("📑 Ensamblando Súper Reporte Técnico...")
    generar_pdf_maestro("Reporte Técnico de Ciberseguridad", 'sigmac_severidad.png', 'sigmac_tipos.png', '', ia_tecnica, hallazgos_traducidos, obj, esc_lista, ruta_logo, pdf_tec, es_ejecutivo=False, total_riesgos=r_sev)

    print("\n📥 Entregando ambos reportes maestros...")
    entregar_archivo(pdf_ejec)
    entregar_archivo(pdf_tec)
    print("✅ ¡Consolidación exitosa!")


if __name__ == "__main__":
    main()
