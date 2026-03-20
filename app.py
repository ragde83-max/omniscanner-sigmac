import streamlit as st
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import numpy as np
from fpdf import FPDF
import os
import re
import json
import html
from urllib.parse import urlparse
from datetime import datetime
from google import genai
import tempfile

# ==========================================
# 1. CONFIGURACIÓN Y MEMORIA DE SESIÓN
# ==========================================
st.set_page_config(page_title="OmniScanner | Sigmac Corp", page_icon="🛡️", layout="centered")

if 'analisis_completado' not in st.session_state:
    st.session_state.analisis_completado = False
    st.session_state.pdf_ejecutivo = None
    st.session_state.pdf_tecnico = None
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
    st.info("🔒 La API Key no se guarda en ningún servidor. Se utiliza temporalmente durante esta sesión.")
    
    if st.button("🔄 Nuevo Análisis"):
        st.session_state.analisis_completado = False
        st.rerun()

# ==========================================
# 3. FUNCIONES CORE Y BLINDAJE
# ==========================================
def limpiar_html(texto):
    if not texto: return "N/A"
    t = html.unescape(str(texto))
    t = re.sub(r'<[^>]+>', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()

def blindaje_fpdf(texto, truncar_log=False):
    if not texto: return "N/A"
    t = html.unescape(str(texto))
    t = re.sub(r'<[^>]+>', ' ', t)
    t = str(t).replace('\r', '').replace('\t', ' ').replace('\xa0', ' ')
    t = re.sub(r'[-=_*#]{10,}', '---', t) 
    if truncar_log and len(t) > 1200: 
        t = t[:1197] + "...\n[DUMP TRUNCADO POR SEGURIDAD DE FORMATO]"
    t = re.sub(r'([^\s\n]{30})', r'\1 ', t) 
    lineas = t.split('\n')
    lineas_limpias = [re.sub(r' +', ' ', linea).strip() for linea in lineas]
    return '\n'.join(lineas_limpias).encode('latin-1', 'replace').decode('latin-1')

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

# ==========================================
# 4. MOTOR DE EXTRACCIÓN MODULAR
# ==========================================
def clasificar_y_guardar(sev_norm, nombre, impacto, r_riesgos, r_tipos, hallazgos):
    r_riesgos[sev_norm] += 1
    if sev_norm in ["Critical", "High", "Medium", "Low"]:
        nombre_low = str(nombre).lower()
        if "disclosure" in nombre_low or "leak" in nombre_low or "info" in nombre_low: tipo_es = "Fuga de Informacion"
        elif "ssl" in nombre_low or "tls" in nombre_low or "cipher" in nombre_low or "certificate" in nombre_low or "crypt" in nombre_low: tipo_es = "Criptografía Débil"
        elif "outdated" in nombre_low or "version" in nombre_low or "obsolete" in nombre_low: tipo_es = "Software Obsoleto"
        elif "hsts" in nombre_low or "header" in nombre_low or "cookie" in nombre_low or "csrf" in nombre_low or "clickjacking" in nombre_low or "cors" in nombre_low: tipo_es = "Debilidad Perimetral"
        else: tipo_es = "Mala Configuracion"
        
        r_tipos[tipo_es] = r_tipos.get(tipo_es, 0) + 1
        hallazgos.append({"Riesgo": sev_norm, "Vulnerabilidad": limpiar_html(nombre), "Impacto": limpiar_html(impacto)})

def extraer_datos_xml(xml_content):
    resumen_riesgos = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    resumen_tipos = {}
    hallazgos_crudos = []
    objetivo = "Infraestructura no identificada"
    escaner = "Desconocido"
    
    try:
        # Sanitización estricta contra atributos fantasma (Ej. Wapiti)
        xml_content = re.sub(r'\bxsi:[a-zA-Z0-9_]+="[^"]*"', '', xml_content)
        
        root = ET.fromstring(xml_content)
        root_tag = root.tag.lower()

        wapiti_gen = root.find('.//info[@name="generatorName"]')
        if wapiti_gen is not None and 'wapiti' in str(wapiti_gen.text).lower(): escaner = "Wapiti"
        elif 'nessus' in root_tag: escaner = "Nessus"
        elif 'owaspzapreport' in root_tag: escaner = "OWASP ZAP"
        elif 'issues' in root_tag: escaner = "Burp Suite"
        elif 'report' in root_tag and root.find('.//result') is not None: escaner = "OpenVAS"
        elif 'scangroup' in root_tag or 'scan' in root_tag: escaner = "Invicti/Acunetix"
        elif 'xmlreport' in root_tag: escaner = "HCL AppScan"
        elif 'cxxmlresults' in root_tag: escaner = "Checkmarx"

        start_url = root.find('.//StartURL')
        host_tag = root.find('.//ReportHost')
        site_tag = root.find('.//site')
        burp_host = root.find('.//host')
        wapiti_target = root.find('.//info[@name="target"]')

        if start_url is not None and start_url.text: objetivo = start_url.text
        elif host_tag is not None: objetivo = host_tag.get('name', 'Host')
        elif site_tag is not None: objetivo = site_tag.get('name', 'Host')
        elif burp_host is not None and burp_host.text: objetivo = burp_host.text
        elif wapiti_target is not None and wapiti_target.text: objetivo = wapiti_target.text

        if escaner == "Wapiti":
            for item in root.findall('.//vulnerability'):
                nombre = item.get('name', 'Hallazgo Wapiti')
                level_tag = item.find('.//level')
                if level_tag is not None and level_tag.text:
                    sev_val = level_tag.text
                else:
                    n_lower = nombre.lower()
                    if 'sql' in n_lower or 'xss' in n_lower or 'injection' in n_lower or 'exec' in n_lower: sev_val = 'High'
                    elif 'backup' in n_lower or 'disclosure' in n_lower or 'info' in n_lower: sev_val = 'Medium'
                    else: sev_val = 'Low'
                sev_norm = mapear_severidad(sev_val)
                impacto_tag = item.find('description')
                clasificar_y_guardar(sev_norm, nombre, impacto_tag.text if impacto_tag is not None else "Sin detalles.", resumen_riesgos, resumen_tipos, hallazgos_crudos)

        elif escaner == "OWASP ZAP":
            for item in root.findall('.//alertitem'):
                sev_tag = item.find('riskcode')
                sev_val = sev_tag.text if sev_tag is not None else '0'
                sev_norm = 'Informational' if str(sev_val) == '0' else mapear_severidad(sev_val)
                nombre_tag = item.find('alert')
                clasificar_y_guardar(sev_norm, nombre_tag.text if nombre_tag is not None else 'Hallazgo', (item.find('desc').text if item.find('desc') is not None else ""), resumen_riesgos, resumen_tipos, hallazgos_crudos)

        elif escaner == "Burp Suite":
            for item in root.findall('.//issue'):
                sev_tag = item.find('severity')
                sev_val = sev_tag.text if sev_tag is not None else 'Information'
                nombre_tag = item.find('name')
                impacto_bg = item.find('issueBackground')
                impacto_dt = item.find('issueDetail')
                impacto = impacto_bg.text if impacto_bg is not None else (impacto_dt.text if impacto_dt is not None else "")
                clasificar_y_guardar(mapear_severidad(sev_val), nombre_tag.text if nombre_tag is not None else 'Hallazgo', impacto, resumen_riesgos, resumen_tipos, hallazgos_crudos)

        else: 
            for item in root.findall('.//ReportItem'):
                sev_tag = item.find('Severity')
                if sev_tag is None: sev_tag = item.get('severity')
                sev_val = sev_tag.text if hasattr(sev_tag, 'text') else sev_tag
                if sev_val is None: continue
                nombre_tag = item.find('Name')
                clasificar_y_guardar(mapear_severidad(sev_val), nombre_tag.text if nombre_tag is not None else item.get('pluginName', 'Hallazgo'), (item.find('Impact').text if item.find('Impact') is not None else ""), resumen_riesgos, resumen_tipos, hallazgos_crudos)

        return resumen_riesgos, resumen_tipos, hallazgos_crudos, objetivo, escaner
    except Exception as e:
        return None, None, None, None, None

# ==========================================
# 5. CONSOLIDADOR MULTI-ESCÁNER
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
        
        if obj is None: continue 
        
        obj_norm = normalizar_objetivo(obj)
        
        if objetivo_normalizado_maestro is None:
            objetivo_normalizado_maestro = obj_norm
            objetivo_maestro = obj
        elif objetivo_normalizado_maestro != obj_norm and obj_norm != "desconocido":
            st.warning(f"⚠️ Conflicto de objetivos: {nombre_archivo} escaneó '{obj_norm}', difiere de '{objetivo_normalizado_maestro}'. Se omitirá.")
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
# 6. ANÁLISIS IA
# ==========================================
def traducir_inventario_json(hallazgos, cliente):
    hallazgos_top = hallazgos[:30] 
    prompt = f"Traduce los campos 'Vulnerabilidad' e 'Impacto' de esta lista JSON del ingles al espanol tecnico. MANTEN INTACTO el campo 'Riesgo'. Retorna UNICAMENTE el JSON valido, sin formato markdown:\n{json.dumps(hallazgos_top)}"
    try:
        respuesta = cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text
        respuesta = respuesta.replace("```json", "").replace("```", "").strip()
        resultado = json.loads(respuesta)
        if isinstance(resultado, list) and len(resultado) > 0: return resultado
        return hallazgos_top
    except: return hallazgos_top

def analizar_ejecutivo_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    datos_texto = "\n".join([f"- [{h.get('Riesgo', '')}] {h.get('Vulnerabilidad', '')}" for h in hallazgos[:15]])
    escaneres_str = " + ".join(escaneres_lista)
    
    prompt = f"""Actúa como el CISO de Sigmac Corp. Redacta un análisis ejecutivo maestro, combinando resultados de múltiples herramientas. Objetivo: {objetivo}. Escáneres combinados: {escaneres_str}. Principales vulnerabilidades detectadas: {datos_texto}.
    REGLAS ESTRICTAS: 
    1. NO uses formato de carta, saludos o despedidas.
    2. Documento extenso (mínimo 450 palabras), tono impersonal y directivo.
    3. NO uses Markdown. Usa múltiples saltos de línea (ENTER) para separar párrafos.
    ESTRUCTURA OBLIGATORIA (Separa cada sección con doble salto de línea):
    RESUMEN EJECUTIVO: (Desarrolla el impacto global consolidado de los múltiples escaneos en 2 o 3 párrafos).
    CAUSA RAIZ OPERATIVA: (Analiza fallas estructurales en TI en 2 párrafos).
    PLAN DE ACCION ESTRATEGICO: (Desarrolla 3 pasos gerenciales enumerados)."""
    try: return cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text.replace('*', '').replace('#', '').replace('$', '')
    except: return "Análisis maestro no disponible."

def analizar_tecnico_con_ia(hallazgos, objetivo, escaneres_lista, cliente):
    datos_texto = "\n".join([f"- [{h.get('Riesgo', '')}] {h.get('Vulnerabilidad', '')}: {h.get('Impacto', '')}" for h in hallazgos[:15]])
    escaneres_str = " + ".join(escaneres_lista)
    
    prompt = f"""Actúa como Arquitecto DevSecOps de Sigmac Corp. Escribe una guía técnica maestra de remediación. Objetivo: {objetivo}. Escáneres de origen: {escaneres_str}. Detalles combinados: {datos_texto}.
    REGLAS ESTRICTAS: 
    1. NO uses formato de carta. Impersonal.
    2. NO uses Markdown. Usa múltiples saltos de línea (ENTER) para separar párrafos.
    ESTRUCTURA OBLIGATORIA:
    EVALUACION TECNICA CONSOLIDADA: (Diagnóstico técnico directo integrando la visión de múltiples motores en 2 párrafos).
    VECTORES DE ATAQUE COMBINADOS: (Riesgos técnicos).
    GUIA DE REMEDIACION MAESTRA: (3 pasos técnicos detallados)."""
    try: return cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text.replace('*', '').replace('#', '').replace('$', '')
    except: return "Análisis técnico maestro no disponible."

# ==========================================
# 7. CLASE PDF
# ==========================================
class ReporteSigmac(FPDF):
    def __init__(self, logo_path, titulo_doc, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logo_path = logo_path
        self.titulo_doc = titulo_doc

    def header(self):
        if self.page_no() > 1:
            if os.path.exists(self.logo_path): self.image(self.logo_path, x=160, y=10, w=40)
            self.set_font('helvetica', 'B', 10); self.set_text_color(44, 62, 80)
            self.cell(0, 10, text=f'{self.titulo_doc} - Sigmac Corp', border=False, align='L')
            self.set_draw_color(56, 142, 60); self.set_line_width(0.5); self.line(10, 25, 200, 25); self.ln(15)

    def footer(self):
        if self.page_no() > 1:
            self.set_y(-15); self.set_draw_color(200, 200, 200); self.line(10, 282, 200, 282)
            self.set_font('helvetica', 'I', 8); self.set_text_color(120, 120, 120)
            self.cell(0, 10, text='CONFIDENCIAL - PROPIEDAD DE SIGMAC CORP.', align='L')
            self.set_x(0); self.cell(0, 10, text=f'Pagina {self.page_no()}', align='R')

def generar_pdf_maestro(titulo, img_sev, img_tip, img_radar, analisis_ia, hallazgos_traducidos, objetivo, escaneres_lista, logo, ruta_out, es_ejecutivo=True):
    pdf = ReporteSigmac(logo_path=logo, titulo_doc=titulo)
    escaneres_str = " + ".join(escaneres_lista)
    
    pdf.add_page(); pdf.ln(40)
    if os.path.exists(logo): pdf.image(logo, x=55, y=50, w=100)
    pdf.ln(60)
    pdf.set_font("helvetica", 'B', 24); pdf.set_text_color(44, 62, 80); pdf.cell(0, 15, text=titulo.upper(), align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", '', 14); pdf.set_text_color(56, 142, 60); pdf.cell(0, 10, text=f"Motores Combinados: {escaneres_str}", align='C', new_x="LMARGIN", new_y="NEXT"); pdf.ln(30)
    pdf.set_font("helvetica", 'B', 12); pdf.set_text_color(44, 62, 80); pdf.cell(0, 6, text=f"Objetivo Consolidado: {objetivo}", align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", '', 12); pdf.cell(0, 6, text=f"Fecha: {datetime.now().strftime('%d de %B, %Y')}", align='C', new_x="LMARGIN", new_y="NEXT")

    pdf.add_page()
    pdf.set_font("helvetica", 'B', 16); pdf.set_text_color(44, 62, 80); pdf.cell(0, 10, text="1. Dashboard de Postura Consolidada", new_x="LMARGIN", new_y="NEXT")
    y_actual = pdf.get_y()
    
    if es_ejecutivo and os.path.exists(img_radar): 
        pdf.image(img_radar, x=10, y=y_actual, w=90)
        if os.path.exists(img_sev): pdf.image(img_sev, x=110, y=y_actual+5, w=85)
        pdf.set_y(y_actual + 90)
        if os.path.exists(img_tip): pdf.image(img_tip, x=35, y=pdf.get_y(), w=140)
        pdf.ln(80)
    else:
        if os.path.exists(img_sev): pdf.image(img_sev, x=10, y=y_actual, w=90)
        if os.path.exists(img_tip): pdf.image(img_tip, x=110, y=y_actual+5, w=90)
        pdf.set_y(y_actual + 95)
    
    pdf.add_page()
    pdf.set_font("helvetica", 'B', 16); pdf.set_text_color(44, 62, 80); pdf.cell(0, 10, text="2. Analisis Maestro (IA)", new_x="LMARGIN", new_y="NEXT"); pdf.ln(5)
    pdf.set_font("helvetica", '', 11); pdf.set_text_color(50, 50, 50); pdf.set_x(10)
    pdf.multi_cell(0, 6, text=blindaje_fpdf(analisis_ia, truncar_log=False), align='J') 
    
    if not es_ejecutivo:
        pdf.add_page()
        pdf.set_font("helvetica", 'B', 16); pdf.set_text_color(44, 62, 80); pdf.cell(0, 10, text="3. Inventario Unificado de Vulnerabilidades", new_x="LMARGIN", new_y="NEXT"); pdf.ln(5)
        for h in hallazgos_traducidos:
            pdf.set_font("helvetica", 'B', 11)
            riesgo_str = h.get('Riesgo', 'Informational')
            if riesgo_str == 'Critical': pdf.set_text_color(139, 0, 0)
            elif riesgo_str == 'High': pdf.set_text_color(211, 47, 47)
            elif riesgo_str == 'Medium': pdf.set_text_color(245, 124, 0)
            elif riesgo_str == 'Low': pdf.set_text_color(251, 192, 45)
            else: pdf.set_text_color(69, 90, 100)
            
            titulo_h = f"[{riesgo_str.upper()}] {h.get('Vulnerabilidad', 'Desconocida')}"
            pdf.set_x(10)
            pdf.multi_cell(0, 6, text=blindaje_fpdf(titulo_h, truncar_log=True), align='L') 
            
            pdf.set_font("helvetica", '', 10); pdf.set_text_color(50, 50, 50); pdf.set_x(10)
            pdf.multi_cell(0, 5, text=blindaje_fpdf(h.get('Impacto', 'N/A'), truncar_log=True), align='J')
            pdf.ln(5)
            
    pdf.output(ruta_out)

# ==========================================
# 8. INTERFAZ STREAMLIT (SOPORTE MULTI-ARCHIVO)
# ==========================================
if not st.session_state.analisis_completado:
    st.markdown("### 1. Carga de Datos Consolidada")
    archivos_xml = st.file_uploader("Sube uno o MÚLTIPLES archivos XML del mismo servidor (Nessus, ZAP, Burp, Wapiti, etc.)", type=["xml"], accept_multiple_files=True)

    if st.button("Generar Súper Reportes", type="primary"):
        if not api_key_input:
            st.error("⚠️ Por favor ingresa tu API Key en la barra lateral para continuar.")
        elif not archivos_xml:
            st.warning("⚠️ Sube al menos un archivo XML válido primero.")
        else:
            with st.spinner(f"Analizando {len(archivos_xml)} archivo(s) y consolidando reportes maestros. Esto tomará un par de minutos..."):
                archivos_cargados = {f.name: f.getvalue() for f in archivos_xml}
                
                resultado_consolidado = consolidar_reportes(archivos_cargados)
                
                if resultado_consolidado:
                    r_sev, r_tip, madurez, hallazgos, obj, esc_lista = resultado_consolidado
                    
                    if hallazgos:
                        with tempfile.TemporaryDirectory() as tmpdir:
                            p_sev = os.path.join(tmpdir, "sev.png")
                            p_tip = os.path.join(tmpdir, "tip.png")
                            p_rad = os.path.join(tmpdir, "rad.png")
                            p_pdf_ejecutivo = os.path.join(tmpdir, "Ejecutivo.pdf")
                            p_pdf_tecnico = os.path.join(tmpdir, "Tecnico.pdf")
                            
                            cliente = genai.Client(api_key=api_key_input)
                            colores = {"Critical": '#8B0000', "High": '#D32F2F', "Medium": '#F57C00', "Low": '#FBC02D', "Informational": '#455A64'}
                            
                            if len([v for v in r_sev.values() if v>0]) > 0:
                                plt.figure(figsize=(4.5, 3.5))
                                plt.pie([v for v in r_sev.values() if v>0], labels=[k for k,v in r_sev.items() if v>0], colors=[colores.get(c, '#CCCCCC') for c in [k for k,v in r_sev.items() if v>0]], autopct='%1.1f%%', textprops={'fontsize':9, 'weight':'bold'})
                                plt.gcf().gca().add_artist(plt.Circle((0,0),0.70,fc='white'))
                                plt.savefig(p_sev, dpi=300, transparent=True, bbox_inches='tight'); plt.close()
                            
                            if len(r_tip) > 0:
                                plt.figure(figsize=(5, 3))
                                plt.barh(list(r_tip.keys()), list(r_tip.values()), color='#388E3C')
                                plt.gca().spines['top'].set_visible(False); plt.gca().spines['right'].set_visible(False)
                                plt.savefig(p_tip, dpi=300, transparent=True, bbox_inches='tight'); plt.close()

                            labels = np.array(list(madurez.keys())); stats = np.array(list(madurez.values()))
                            angles = np.linspace(0, 2*np.pi, len(labels), endpoint=False)
                            stats = np.concatenate((stats, [stats[0]])); angles = np.concatenate((angles, [angles[0]]))
                            fig, ax = plt.subplots(figsize=(4.5, 4.5), subplot_kw=dict(polar=True))
                            ax.fill(angles, stats, color='#388E3C', alpha=0.25); ax.plot(angles, stats, color='#388E3C', linewidth=2)
                            ax.set_yticklabels([]); ax.set_xticks(angles[:-1]); ax.set_xticklabels(labels, fontsize=9, fontweight='bold', color='#2C3E50'); ax.set_ylim(0, 10)
                            plt.savefig(p_rad, dpi=300, transparent=True, bbox_inches='tight'); plt.close()

                            # IA Pipeline Master
                            hallazgos_traducidos = traducir_inventario_json(hallazgos, cliente)
                            ia_ejecutiva = analizar_ejecutivo_con_ia(hallazgos_traducidos, obj, esc_lista, cliente)
                            ia_tecnica = analizar_tecnico_con_ia(hallazgos_traducidos, obj, esc_lista, cliente)
                            
                            # Ensamblaje
                            generar_pdf_maestro("Auditoria Estrategica Consolidada", p_sev, p_tip, p_rad, ia_ejecutiva, hallazgos_traducidos, obj, esc_lista, "logo_sigmac.jpg", p_pdf_ejecutivo, es_ejecutivo=True)
                            generar_pdf_maestro("Reporte Tecnico Maestro", p_sev, p_tip, '', ia_tecnica, hallazgos_traducidos, obj, esc_lista, "logo_sigmac.jpg", p_pdf_tecnico, es_ejecutivo=False)

                            with open(p_pdf_ejecutivo, "rb") as f_ejec:
                                st.session_state.pdf_ejecutivo = f_ejec.read()
                            with open(p_pdf_tecnico, "rb") as f_tec:
                                st.session_state.pdf_tecnico = f_tec.read()
                            
                            st.session_state.objetivo_nombre = normalizar_objetivo(obj)
                            st.session_state.analisis_completado = True
                            st.rerun()
                    else:
                        st.error("❌ Los archivos subidos no contienen vulnerabilidades válidas o su formato no es compatible.")
                else:
                    st.error("❌ Ocurrió un problema durante la consolidación. Asegúrate de que todos los XML pertenezcan a la misma infraestructura.")

if st.session_state.analisis_completado:
    st.success("✅ ¡Consolidación exitosa! Tus reportes maestros están listos.")
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(label="📥 Descargar Reporte Ejecutivo Maestro", data=st.session_state.pdf_ejecutivo, file_name=f"Ejecutivo_Maestro_{st.session_state.objetivo_nombre}.pdf", mime="application/pdf", use_container_width=True)
    with col2:
        st.download_button(label="📥 Descargar Reporte Técnico Maestro", data=st.session_state.pdf_tecnico, file_name=f"Tecnico_Maestro_{st.session_state.objetivo_nombre}.pdf", mime="application/pdf", use_container_width=True)
