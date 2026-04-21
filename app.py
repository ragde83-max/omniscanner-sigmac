import streamlit as st
import xml.etree.ElementTree as ET
import matplotlib
matplotlib.use('Agg') # Vital para la nube
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
# 1. CONFIGURACIÓN Y MEMORIA DE SESIÓN
# ==========================================
st.set_page_config(page_title="OmniScanner | Sigmac Corp", page_icon="🛡️", layout="wide")

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
# 2. BARRA LATERAL (SEGURIDAD)
# ==========================================
with st.sidebar:
    st.header("⚙️ Configuración del Motor")
    api_key_input = st.text_input("Ingresa tu API Key de Gemini:", type="password")
    st.info("🔒 La API Key no se guarda en ningún servidor.")
    if st.button("🔄 Nuevo Análisis"):
        st.session_state.analisis_completado = False
        st.rerun()

# ==========================================
# 3. FUNCIONES CORE
# ==========================================
def limpiar_html(texto):
    if not texto: return "N/A"
    t = html.unescape(str(texto))
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', t)).strip()

def desarmar_payloads(texto):
    if not texto: return ""
    t = str(texto).replace('<', '【').replace('>', '】')
    return re.sub(r'(?i)(alert\(|prompt\(|confirm\(|eval\()', 'alerta_bloqueada(', t)

def mapear_severidad(sev_cruda):
    sev = str(sev_cruda).strip().lower()
    if sev in ['critical', 'crítico', '4', 'high', 'alto', '3']: return 'High'
    elif sev in ['medium', 'medio', '2']: return 'Medium'
    elif sev in ['low', 'bajo', '1']: return 'Low'
    else: return 'Informational'

def normalizar_objetivo(url):
    if not url: return "desconocido"
    url = url.lower().strip()
    if not url.startswith('http'): url = 'http://' + url
    return urlparse(url).netloc.split(':')[0] 

def limpiar_ruta(ruta_cruda, objetivo):
    if not ruta_cruda or ruta_cruda == "N/A": return "Global"
    ruta = str(ruta_cruda).strip().lower()
    if any(x in ruta for x in ["owasp.org", "mitre.org", "cve", "w3.org", "tools.ietf.org"]): return "Global"
    if ruta.startswith("http"):
        try:
            if urlparse(ruta).netloc.split(':')[0] != normalizar_objetivo(objetivo): return "Global" 
        except: pass
    return str(ruta_cruda).strip()

def clasificar_y_guardar(sev_norm, nombre, impacto, ruta, r_riesgos, r_tipos, hallazgos):
    r_riesgos[sev_norm] += 1
    if sev_norm in ["Critical", "High", "Medium", "Low"]:
        nombre_low = str(nombre).lower()
        if "disclosure" in nombre_low or "leak" in nombre_low or "info" in nombre_low: tipo_es = "Fuga de Informacion"
        elif any(x in nombre_low for x in ["ssl", "tls", "cipher", "certificate", "crypt"]): tipo_es = "Criptografía Débil"
        elif any(x in nombre_low for x in ["outdated", "version", "obsolete"]): tipo_es = "Software Obsoleto"
        elif any(x in nombre_low for x in ["hsts", "header", "cookie", "csrf", "clickjacking", "cors"]): tipo_es = "Debilidad Perimetral"
        else: tipo_es = "Mala Configuracion"
        r_tipos[tipo_es] = r_tipos.get(tipo_es, 0) + 1
        hallazgos.append({"Riesgo": sev_norm, "Vulnerabilidad": limpiar_html(nombre), "Impacto": limpiar_html(impacto), "Ruta": limpiar_html(ruta)})

def extraer_ruta_dinamica(item, escaner):
    if escaner == "Acunetix": return getattr(item.find('.//Affects'), 'text', "")
    elif escaner == "Wapiti": return getattr(item.find('.//entries/entry/path'), 'text', "")
    elif escaner == "OWASP ZAP": return getattr(item.find('.//instances/instance/uri'), 'text', "")
    elif escaner == "Burp Suite": return getattr(item.find('path'), 'text', getattr(item.find('location'), 'text', ""))
    for etiqueta in ['uri', 'url', 'path', 'location', 'Affects']:
        nodo = item.find(f'.//{etiqueta}')
        if nodo is not None and nodo.text and len(str(nodo.text).strip()) > 1: return str(nodo.text).strip()
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

        if root.find('.//info[@name="generatorName"]') is not None and 'wapiti' in str(root.find('.//info[@name="generatorName"]').text).lower(): escaner = "Wapiti"
        elif 'nessus' in root_tag: escaner = "Nessus"
        elif 'owaspzapreport' in root_tag: escaner = "OWASP ZAP"
        elif 'issues' in root_tag: escaner = "Burp Suite"
        elif 'scangroup' in root_tag or 'scan' in root_tag: escaner = "Acunetix"

        if root.find('.//StartURL') is not None and root.find('.//StartURL').text: objetivo = root.find('.//StartURL').text
        elif root.find('.//ReportHost') is not None: objetivo = root.find('.//ReportHost').get('name', 'Host')
        elif root.find('.//host') is not None and root.find('.//host').text: objetivo = root.find('.//host').text

        if escaner == "Wapiti":
            for item in root.findall('.//vulnerability'):
                nombre = item.get('name', 'Hallazgo Wapiti')
                sev_val = getattr(item.find('.//level'), 'text', 'High' if any(x in nombre.lower() for x in ['sql', 'xss', 'injection']) else 'Medium')
                clasificar_y_guardar(mapear_severidad(sev_val), nombre, getattr(item.find('description'), 'text', ""), limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo), resumen_riesgos, resumen_tipos, hallazgos_crudos)

        elif escaner == "OWASP ZAP":
            for item in root.findall('.//alertitem'):
                sev_tag = item.find('riskcode')
                sev_norm = 'Informational' if (sev_tag is not None and str(sev_tag.text) == '0') else mapear_severidad(sev_tag.text if sev_tag is not None else '0')
                clasificar_y_guardar(sev_norm, getattr(item.find('alert'), 'text', 'Hallazgo'), getattr(item.find('desc'), 'text', ""), limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo), resumen_riesgos, resumen_tipos, hallazgos_crudos)

        elif escaner == "Burp Suite":
            for item in root.findall('.//issue'):
                clasificar_y_guardar(mapear_severidad(getattr(item.find('severity'), 'text', 'Information')), getattr(item.find('name'), 'text', 'Hallazgo'), getattr(item.find('issueBackground'), 'text', getattr(item.find('issueDetail'), 'text', "")), limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo), resumen_riesgos, resumen_tipos, hallazgos_crudos)

        else: 
            for item in root.findall('.//ReportItem'):
                sev_val = getattr(item.find('Severity'), 'text', item.get('severity'))
                if sev_val is None: continue
                clasificar_y_guardar(mapear_severidad(sev_val), getattr(item.find('Name'), 'text', item.get('pluginName', 'Hallazgo')), getattr(item.find('Impact'), 'text', getattr(item.find('Description'), 'text', "")), limpiar_ruta(extraer_ruta_dinamica(item, escaner), objetivo), resumen_riesgos, resumen_tipos, hallazgos_crudos)

        return resumen_riesgos, resumen_tipos, hallazgos_crudos, objetivo, escaner
    except Exception as e: return None, None, None, None, None

def consolidar_reportes(archivos_cargados):
    total_riesgos = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}; total_tipos = {}; total_hallazgos = []; escaneres_detectados = set(); objetivo_maestro = None; objetivo_normalizado_maestro = None

    for nombre_archivo, contenido_bytes in archivos_cargados.items():
        xml_str = contenido_bytes.decode('utf-8', errors='ignore')
        r_riesgos, r_tipos, hallazgos, obj, escaner = extraer_datos_xml(xml_str)
        if obj is None: continue 
        obj_norm = normalizar_objetivo(obj)
        if objetivo_normalizado_maestro is None:
            objetivo_normalizado_maestro = obj_norm
            objetivo_maestro = obj
        elif objetivo_normalizado_maestro != obj_norm and obj_norm != "desconocido":
            st.warning(f"⚠️ Conflicto en {nombre_archivo}. Archivo excluido.")
            continue

        escaneres_detectados.add(escaner)
        for k, v in r_riesgos.items(): total_riesgos[k] += v
        for k, v in r_tipos.items(): total_tipos[k] = total_tipos.get(k, 0) + v
        total_hallazgos.extend(hallazgos)

    madurez = {"Hardening": 10.0, "Criptografía": 10.0, "Protección de Datos": 10.0, "Gestión de Parches": 10.0, "Perímetro": 10.0}
    for tipo, cantidad in total_tipos.items():
        if tipo == "Fuga de Informacion": madurez["Protección de Datos"] -= (cantidad * 0.5)
        elif tipo == "Criptografía Débil": madurez["Criptografía"] -= (cantidad * 0.5)
        elif tipo == "Software Obsoleto": madurez["Gestión de Parches"] -= (cantidad * 0.5)
        elif tipo == "Debilidad Perimetral": madurez["Perímetro"] -= (cantidad * 0.5)
        elif tipo == "Mala Configuracion": madurez["Hardening"] -= (cantidad * 0.5)
    
    for k in madurez: madurez[k] = max(0, min(10.0, madurez[k]))
    orden_severidad = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Informational": 5}
    total_hallazgos = sorted(total_hallazgos, key=lambda x: orden_severidad.get(x.get("Riesgo", "Informational"), 6))
    return total_riesgos, total_tipos, madurez, total_hallazgos, objetivo_maestro, list(escaneres_detectados)

# ==========================================
# 4. ANÁLISIS IA
# ==========================================
def traducir_inventario_json(hallazgos, cliente):
    hallazgos_top = hallazgos[:30] 
    prompt = f"Traduce al español técnico SOLAMENTE 'Vulnerabilidad' e 'Impacto'. 'Riesgo' y 'Ruta' QUEDAN IGUAL. Devuelve JSON puro:\n{json.dumps(hallazgos_top)}"
    try:
        respuesta = cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text.replace("```json", "").replace("```", "").strip()
        resultado = json.loads(respuesta)
        return resultado if isinstance(resultado, list) and len(resultado) > 0 else hallazgos_top
    except: return hallazgos_top

def analizar_ejecutivo_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    datos_texto = "\n".join([f"- [{h.get('Riesgo', '')}] {desarmar_payloads(h.get('Vulnerabilidad', ''))}" for h in hallazgos[:15]])
    prompt = f"""Actúa como CISO de Sigmac Corp. Redacta análisis ejecutivo para: {objetivo}. Escáneres: {" + ".join(escaneres_lista)}. Hallazgos: {datos_texto}.
    REGLAS: NO uses Markdown. Usa múltiples saltos de línea (ENTER) para separar párrafos.
    ESTRUCTURA: RESUMEN EJECUTIVO / CAUSA RAIZ OPERATIVA / PLAN DE ACCION ESTRATEGICO."""
    try: return cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text.replace('*', '').replace('#', '').replace('$', '')
    except Exception as e: return f"Error IA: {e}"

def analizar_tecnico_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    datos_texto = "\n".join([f"- [{h.get('Riesgo', '')}] {desarmar_payloads(h.get('Vulnerabilidad', ''))} en {h.get('Ruta', 'Global')}: {desarmar_payloads(str(h.get('Impacto', ''))[:250])}" for h in hallazgos[:15]])
    prompt = f"""Actúa como Arquitecto DevSecOps de Sigmac Corp. Guía técnica para: {objetivo}. Escáneres: {" + ".join(escaneres_lista)}. Detalles: {datos_texto}.
    REGLAS: NO uses Markdown. Usa múltiples saltos de línea (ENTER) para separar párrafos.
    ESTRUCTURA: EVALUACION TECNICA CONSOLIDADA / VECTORES DE ATAQUE COMBINADOS / GUIA DE REMEDIACION MAESTRA."""
    try: return cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text.replace('*', '').replace('#', '').replace('$', '')
    except Exception as e: return f"Error IA: {e}"

# ==========================================
# 5. RENDERIZADO DE PLANTILLA HTML
# ==========================================
def obtener_base64_img(ruta_img):
    if not ruta_img or not os.path.exists(ruta_img): return ""
    with open(ruta_img, "rb") as img_file: return f"data:image/png;base64,{base64.b64encode(img_file.read()).decode('utf-8')}"

PLANTILLA_HTML = """
<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><style>
:root { --primary: #1B263B; --accent: #388E3C; --text-dark: #333; }
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

def generar_html_maestro(titulo, img_sev, img_tip, img_radar, analisis_ia, hallazgos_traducidos, objetivo, escaneres_lista, logo_sigmac, es_ejecutivo=True):
    template = Template(PLANTILLA_HTML)
    html_render = template.render(titulo=titulo, escaneres=" + ".join(escaneres_lista), objetivo=objetivo, fecha=datetime.now().strftime('%d de %B, %Y'), logo_sigmac=obtener_base64_img(logo_sigmac), img_sev=obtener_base64_img(img_sev), img_tip=obtener_base64_img(img_tip), img_radar=obtener_base64_img(img_radar), analisis_ia=analisis_ia, hallazgos=hallazgos_traducidos, es_ejecutivo=es_ejecutivo)
    return html_render

# ==========================================
# 6. INTERFAZ STREAMLIT
# ==========================================
if not st.session_state.analisis_completado:
    st.markdown("### 1. Carga de Datos Consolidada")
    archivos_xml = st.file_uploader("Sube uno o MÚLTIPLES archivos XML (ZAP, Burp, Wapiti, Acunetix, etc.)", type=["xml"], accept_multiple_files=True)

    if st.button("Generar Súper Reportes", type="primary"):
        if not api_key_input: st.error("⚠️ Ingresa tu API Key en la barra lateral.")
        elif not archivos_xml: st.warning("⚠️ Sube al menos un archivo XML.")
        else:
            with st.spinner("Analizando y generando reportes corporativos interactivos..."):
                archivos_cargados = {f.name: f.getvalue() for f in archivos_xml}
                r_sev, r_tip, madurez, hallazgos, obj, esc_lista = consolidar_reportes(archivos_cargados)
                
                if hallazgos:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        p_sev = os.path.join(tmpdir, "sev.png"); p_tip = os.path.join(tmpdir, "tip.png"); p_rad = os.path.join(tmpdir, "rad.png")
                        cliente = genai.Client(api_key=api_key_input)
                        
                        colores = {"Critical": '#8B0000', "High": '#D32F2F', "Medium": '#F57C00', "Low": '#FBC02D', "Informational": '#455A64'}
                        if sum(r_sev.values()) > 0:
                            plt.figure(figsize=(4.5, 3.5)); plt.pie([v for v in r_sev.values() if v>0], labels=[k for k,v in r_sev.items() if v>0], colors=[colores.get(c, '#CCCCCC') for c in [k for k,v in r_sev.items() if v>0]], autopct='%1.1f%%', textprops={'weight':'bold'}); plt.gcf().gca().add_artist(plt.Circle((0,0),0.70,fc='white')); plt.savefig(p_sev, transparent=True, bbox_inches='tight'); plt.close()
                        if len(r_tip) > 0:
                            plt.figure(figsize=(5, 3)); plt.barh(list(r_tip.keys()), list(r_tip.values()), color='#388E3C'); plt.gca().spines['top'].set_visible(False); plt.gca().spines['right'].set_visible(False); plt.savefig(p_tip, transparent=True, bbox_inches='tight'); plt.close()
                        
                        labels = np.array(list(madurez.keys())); stats = np.array(list(madurez.values()))
                        angles = np.linspace(0, 2*np.pi, len(labels), endpoint=False); stats = np.concatenate((stats, [stats[0]])); angles = np.concatenate((angles, [angles[0]]))
                        fig, ax = plt.subplots(figsize=(4.5, 4.5), subplot_kw=dict(polar=True)); ax.fill(angles, stats, color='#388E3C', alpha=0.25); ax.plot(angles, stats, color='#388E3C', linewidth=2); ax.set_yticklabels([]); ax.set_xticks(angles[:-1]); ax.set_xticklabels(labels, fontsize=9, fontweight='bold'); ax.set_ylim(0, 10); plt.savefig(p_rad, transparent=True, bbox_inches='tight'); plt.close()

                        h_trad = traducir_inventario_json(hallazgos, cliente)
                        time.sleep(2)
                        ia_ejec = analizar_ejecutivo_con_ia(h_trad, obj, esc_lista, cliente)
                        time.sleep(2)
                        ia_tec = analizar_tecnico_con_ia(h_trad, obj, esc_lista, cliente)
                        
                        st.session_state.html_ejecutivo = generar_html_maestro("Auditoria Estrategica Consolidada", p_sev, p_tip, p_rad, ia_ejec, h_trad, obj, esc_lista, "logo_sigmac.jpg", es_ejecutivo=True)
                        st.session_state.html_tecnico = generar_html_maestro("Reporte Tecnico Maestro", p_sev, p_tip, '', ia_tec, h_trad, obj, esc_lista, "logo_sigmac.jpg", es_ejecutivo=False)
                        st.session_state.objetivo_nombre = normalizar_objetivo(obj)
                        st.session_state.analisis_completado = True
                        st.rerun()
                else: st.error("❌ Los archivos subidos no contienen vulnerabilidades válidas o están cruzados.")

if st.session_state.analisis_completado:
    st.success("✅ ¡Consolidación exitosa! Tus reportes están listos para visualizar y descargar.")
    
    col1, col2 = st.columns(2)
    with col1: 
        st.download_button("📥 Descargar Reporte Ejecutivo (HTML)", data=st.session_state.html_ejecutivo, file_name=f"Ejecutivo_{st.session_state.objetivo_nombre}.html", mime="text/html", use_container_width=True)
    with col2: 
        st.download_button("📥 Descargar Reporte Técnico (HTML)", data=st.session_state.html_tecnico, file_name=f"Tecnico_{st.session_state.objetivo_nombre}.html", mime="text/html", use_container_width=True)
    
    st.markdown("---")
    st.markdown("### Vista Previa de Reportes")
    tab1, tab2 = st.tabs(["Reporte Ejecutivo", "Reporte Técnico"])
    
    with tab1:
        st.components.v1.html(st.session_state.html_ejecutivo, height=800, scrolling=True)
    with tab2:
        st.components.v1.html(st.session_state.html_tecnico, height=800, scrolling=True)
