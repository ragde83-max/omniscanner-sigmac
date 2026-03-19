import streamlit as st
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import numpy as np
from fpdf import FPDF
import os
import re
import json
import html
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
st.markdown("Motor de análisis de vulnerabilidades impulsado por Inteligencia Artificial para **Sigmac Corp**.")

# ==========================================
# 2. BARRA LATERAL (SEGURIDAD)
# ==========================================
with st.sidebar:
    st.header("⚙️ Configuración del Motor")
    api_key_input = st.text_input("Ingresa tu API Key de Gemini:", type="password")
    st.info("🔒 La API Key no se guarda en ningún servidor. Se utiliza de forma temporal en la memoria durante esta sesión.")
    
    if st.button("🔄 Nuevo Análisis"):
        st.session_state.analisis_completado = False
        st.rerun()

# ==========================================
# 3. FUNCIONES CORE Y BLINDAJE INTELIGENTE
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

def extraer_datos_universales(xml_content):
    resumen_riesgos = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    resumen_tipos = {}
    hallazgos_crudos = []
    madurez = {"Hardening": 10.0, "Criptografía": 10.0, "Protección de Datos": 10.0, "Gestión de Parches": 10.0, "Perímetro": 10.0}
    objetivo = "Infraestructura no identificada"
    escaner = "Desconocido"
    
    try:
        root = ET.fromstring(xml_content)
        root_tag = root.tag.lower()

        if 'nessus' in root_tag: escaner = "Nessus"
        elif 'owaspzapreport' in root_tag: escaner = "OWASP ZAP"
        elif 'report' in root_tag and root.find('.//result') is not None: escaner = "OpenVAS"
        elif 'scangroup' in root_tag or 'scan' in root_tag: escaner = "Invicti/Acunetix"
        elif 'xmlreport' in root_tag: escaner = "HCL AppScan"
        elif 'cxxmlresults' in root_tag: escaner = "Checkmarx"

        start_url = root.find('.//StartURL')
        host_tag = root.find('.//ReportHost')
        site_tag = root.find('.//site')

        if start_url is not None and start_url.text: objetivo = start_url.text
        elif host_tag is not None: objetivo = host_tag.get('name', 'Host')
        elif site_tag is not None: objetivo = site_tag.get('name', 'Host')

        items = root.findall('.//ReportItem') + root.findall('.//alertitem')

        for item in items:
            sev_tag = item.find('Severity')
            if sev_tag is None: sev_tag = item.find('riskcode')
            if sev_tag is None: sev_tag = item.get('severity')
            
            if sev_tag is None: continue
            
            sev_val = sev_tag.text if hasattr(sev_tag, 'text') else sev_tag
            
            if str(sev_val) == '0': 
                sev_norm = 'Informational'
            else: 
                sev_norm = mapear_severidad(sev_val)
                
            resumen_riesgos[sev_norm] += 1
            
            if sev_norm in ["Critical", "High", "Medium", "Low"]:
                nombre_tag = item.find('Name')
                if nombre_tag is None: nombre_tag = item.find('name')
                if nombre_tag is None: nombre_tag = item.find('alert')
                
                nombre = nombre_tag.text if nombre_tag is not None else item.get('pluginName', 'Hallazgo')
                
                impacto_tag = item.find('Impact')
                if impacto_tag is None: impacto_tag = item.find('desc')
                
                impacto = impacto_tag.text if impacto_tag is not None else "Detalles técnicos no especificados."
                
                tipo_tag = item.find('Type')
                tipo_raw = (tipo_tag.text if tipo_tag is not None else '').lower()
                nombre_low = str(nombre).lower()
                
                if "disclosure" in tipo_raw or "leak" in nombre_low or "info" in nombre_low or "disclosure" in nombre_low:
                    tipo_es = "Fuga de Informacion"; madurez["Protección de Datos"] -= 1.5
                elif "ssl" in nombre_low or "tls" in nombre_low or "cipher" in nombre_low or "certificate" in nombre_low or "crypt" in nombre_low:
                    tipo_es = "Criptografía Débil"; madurez["Criptografía"] -= 1.5
                elif "outdated" in nombre_low or "version" in nombre_low or "obsolete" in nombre_low:
                    tipo_es = "Software Obsoleto"; madurez["Gestión de Parches"] -= 1.5
                elif "hsts" in nombre_low or "header" in nombre_low or "cookie" in nombre_low or "csrf" in nombre_low or "clickjacking" in nombre_low or "cors" in nombre_low:
                    tipo_es = "Debilidad Perimetral"; madurez["Perímetro"] -= 1.0
                else:
                    tipo_es = "Mala Configuracion"; madurez["Hardening"] -= 1.0
                
                resumen_tipos[tipo_es] = resumen_tipos.get(tipo_es, 0) + 1
                hallazgos_crudos.append({"Riesgo": sev_norm, "Vulnerabilidad": limpiar_html(nombre), "Impacto": limpiar_html(impacto)})
        
        for k in madurez: madurez[k] = max(0, madurez[k])
        return resumen_riesgos, resumen_tipos, madurez, hallazgos_crudos, objetivo, escaner
    except Exception as e:
        return None, None, None, None, None, None

# ==========================================
# 4. ANÁLISIS IA Y TRADUCCIÓN
# ==========================================
def traducir_inventario_json(hallazgos, cliente):
    hallazgos_top = hallazgos[:25]
    prompt = f"Traduce los campos 'Vulnerabilidad' e 'Impacto' de esta lista JSON del ingles al espanol tecnico. MANTEN INTACTO el campo 'Riesgo'. Retorna UNICAMENTE el JSON valido, sin formato markdown:\n{json.dumps(hallazgos_top)}"
    try:
        respuesta = cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text
        respuesta = respuesta.replace("```json", "").replace("```", "").strip()
        resultado = json.loads(respuesta)
        if isinstance(resultado, list) and len(resultado) > 0: return resultado
        return hallazgos_top
    except:
        return hallazgos_top

def analizar_ejecutivo_con_ia(hallazgos, objetivo, escaner, cliente):
    datos_texto = "\n".join([f"- [{h.get('Riesgo', '')}] {h.get('Vulnerabilidad', '')}" for h in hallazgos[:15]])
    prompt = f"""Actúa como el CISO de Sigmac Corp. Redacta un análisis ejecutivo profundo, objetivo y de nivel corporativo sobre: {objetivo}. Escáner: {escaner}. Vulnerabilidades: {datos_texto}.
    REGLAS ESTRICTAS: 
    1. NO uses formato de carta. PROHIBIDO usar saludos (ej. "Estimados") o despedidas (ej. "Atentamente"). Es un informe oficial.
    2. Debe ser un documento detallado, analítico y extenso (mínimo 450 palabras), pero manteniendo un tono impersonal de consultoría.
    3. NO uses Markdown (ni asteriscos, ni negritas, ni #).
    4. Usa múltiples saltos de línea (ENTER) para separar los párrafos y evitar bloques de texto saturados.
    ESTRUCTURA OBLIGATORIA (Separa cada sección con doble salto de línea):
    RESUMEN EJECUTIVO: (Desarrolla el impacto de negocio y el nivel de riesgo de forma exhaustiva en 2 o 3 párrafos).
    CAUSA RAIZ OPERATIVA: (Analiza detalladamente las fallas estructurales en los procesos de TI en 2 párrafos).
    PLAN DE ACCION ESTRATEGICO: (Desarrolla 3 pasos gerenciales enumerados, explicando a profundidad el 'cómo' y el 'por qué' de cada acción para justificar la inversión)."""
    try: return cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text.replace('*', '').replace('#', '').replace('$', '')
    except: return "Análisis ejecutivo no disponible."

def analizar_tecnico_con_ia(hallazgos, objetivo, escaner, cliente):
    datos_texto = "\n".join([f"- [{h.get('Riesgo', '')}] {h.get('Vulnerabilidad', '')}: {h.get('Impacto', '')}" for h in hallazgos[:15]])
    prompt = f"""Actúa como Arquitecto DevSecOps de Sigmac Corp. Escribe una guía técnica de remediación directa sobre: {objetivo}. Escáner: {escaner}. Detalles: {datos_texto}.
    REGLAS ESTRICTAS: 
    1. NO uses formato de carta, correo o mensaje. PROHIBIDO usar saludos o despedidas. Debe ser impersonal.
    2. NO uses Markdown (ni asteriscos, ni negritas).
    3. Usa múltiples saltos de línea (ENTER) para separar los párrafos. Lenguaje puramente técnico y conciso.
    ESTRUCTURA OBLIGATORIA:
    EVALUACION TECNICA: (Diagnóstico técnico directo en 1 o 2 párrafos).
    VECTORES DE ATAQUE: (Explica los riesgos técnicos concretos).
    GUIA DE REMEDIACION: (3 pasos técnicos detallados)."""
    try: return cliente.models.generate_content(model='gemini-2.5-flash', contents=prompt).text.replace('*', '').replace('#', '').replace('$', '')
    except: return "Análisis técnico no disponible."

# ==========================================
# 5. CLASE PDF
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

# ==========================================
# 6. INTERFAZ STREAMLIT PRINCIPAL
# ==========================================
if not st.session_state.analisis_completado:
    st.markdown("### 1. Carga de Datos")
    archivo_xml = st.file_uploader("Sube el archivo XML del escáner (Nessus, Invicti, OpenVAS, ZAP, Checkmarx)", type=["xml"])

    if st.button("Generar Reportes (Ejecutivo y Técnico)", type="primary"):
        if not api_key_input:
            st.error("⚠️ Por favor ingresa tu API Key en la barra lateral para continuar.")
        elif not archivo_xml:
            st.warning("⚠️ Sube un archivo XML válido primero.")
        else:
            with st.spinner("Analizando infraestructura y redactando reportes con Inteligencia Artificial. Esto tomará un minuto..."):
                contenido_xml = archivo_xml.read().decode('utf-8', errors='ignore')
                r_sev, r_tip, madurez, hallazgos, obj, escaner = extraer_datos_universales(contenido_xml)
                
                if hallazgos:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        p_sev = os.path.join(tmpdir, "sev.png")
                        p_tip = os.path.join(tmpdir, "tip.png")
                        p_rad = os.path.join(tmpdir, "rad.png")
                        p_pdf_ejecutivo = os.path.join(tmpdir, "Ejecutivo.pdf")
                        p_pdf_tecnico = os.path.join(tmpdir, "Tecnico.pdf")
                        
                        cliente = genai.Client(api_key=api_key_input)
                        colores = {"Critical": '#8B0000', "High": '#D32F2F', "Medium": '#F57C00', "Low": '#FBC02D', "Informational": '#455A64'}
                        
                        plt.figure(figsize=(4.5, 3.5))
                        plt.pie([v for v in r_sev.values() if v>0], labels=[k for k,v in r_sev.items() if v>0], colors=[colores.get(c, '#CCCCCC') for c in [k for k,v in r_sev.items() if v>0]], autopct='%1.1f%%', textprops={'fontsize':9, 'weight':'bold'})
                        plt.gcf().gca().add_artist(plt.Circle((0,0),0.70,fc='white'))
                        plt.savefig(p_sev, dpi=300, transparent=True, bbox_inches='tight'); plt.close()
                        
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

                        # IA Pipeline
                        hallazgos_traducidos = traducir_inventario_json(hallazgos, cliente)
                        ia_ejecutiva = analizar_ejecutivo_con_ia(hallazgos_traducidos, obj, escaner, cliente)
                        ia_tecnica = analizar_tecnico_con_ia(hallazgos_traducidos, obj, escaner, cliente)
                        
                        # --- ENSAMBLAR EJECUTIVO ---
                        pdf_ejec = ReporteSigmac("logo_sigmac.jpg", "Auditoria Estrategica")
                        pdf_ejec.add_page(); pdf_ejec.ln(40)
                        if os.path.exists("logo_sigmac.jpg"): pdf_ejec.image("logo_sigmac.jpg", x=55, y=50, w=100)
                        pdf_ejec.ln(60); pdf_ejec.set_font("helvetica", 'B', 24); pdf_ejec.set_text_color(44, 62, 80); pdf_ejec.cell(0, 15, text="AUDITORIA ESTRATEGICA 360", align='C', new_x="LMARGIN", new_y="NEXT")
                        pdf_ejec.set_font("helvetica", '', 14); pdf_ejec.set_text_color(56, 142, 60); pdf_ejec.cell(0, 10, text=f"Motor de Análisis: {escaner}", align='C', new_x="LMARGIN", new_y="NEXT"); pdf_ejec.ln(30)
                        pdf_ejec.set_font("helvetica", 'B', 12); pdf_ejec.set_text_color(44, 62, 80); pdf_ejec.cell(0, 6, text=f"Objetivo: {obj}", align='C', new_x="LMARGIN", new_y="NEXT")
                        pdf_ejec.set_font("helvetica", '', 12); pdf_ejec.cell(0, 6, text=f"Fecha: {datetime.now().strftime('%d de %B, %Y')}", align='C', new_x="LMARGIN", new_y="NEXT")

                        pdf_ejec.add_page(); pdf_ejec.set_font("helvetica", 'B', 16); pdf_ejec.set_text_color(44, 62, 80); pdf_ejec.cell(0, 10, text="1. Dashboard de Madurez y Postura", new_x="LMARGIN", new_y="NEXT")
                        y_actual = pdf_ejec.get_y()
                        pdf_ejec.image(p_rad, x=10, y=y_actual, w=90) 
                        pdf_ejec.image(p_sev, x=110, y=y_actual+5, w=85) 
                        pdf_ejec.set_y(y_actual + 90) 
                        pdf_ejec.image(p_tip, x=35, y=pdf_ejec.get_y(), w=140) 
                        pdf_ejec.ln(80)
                        
                        pdf_ejec.add_page(); pdf_ejec.set_font("helvetica", 'B', 16); pdf_ejec.set_text_color(44, 62, 80); pdf_ejec.cell(0, 10, text="2. Analisis Directivo", new_x="LMARGIN", new_y="NEXT"); pdf_ejec.ln(5)
                        pdf_ejec.set_font("helvetica", '', 11); pdf_ejec.set_text_color(50, 50, 50); pdf_ejec.set_x(10)
                        pdf_ejec.multi_cell(0, 6, text=blindaje_fpdf(ia_ejecutiva, truncar_log=False), align='J') 
                        pdf_ejec.output(p_pdf_ejecutivo)

                        # --- ENSAMBLAR TÉCNICO ---
                        pdf_tec = ReporteSigmac("logo_sigmac.jpg", "Reporte Tecnico Detallado")
                        pdf_tec.add_page(); pdf_tec.ln(40)
                        if os.path.exists("logo_sigmac.jpg"): pdf_tec.image("logo_sigmac.jpg", x=55, y=50, w=100)
                        pdf_tec.ln(60); pdf_tec.set_font("helvetica", 'B', 24); pdf_tec.set_text_color(44, 62, 80); pdf_tec.cell(0, 15, text="REPORTE TÉCNICO DE REMEDIACIÓN", align='C', new_x="LMARGIN", new_y="NEXT")
                        pdf_tec.set_font("helvetica", '', 14); pdf_tec.set_text_color(56, 142, 60); pdf_tec.cell(0, 10, text=f"Guía de Bastionado y Hardening", align='C', new_x="LMARGIN", new_y="NEXT"); pdf_tec.ln(30)
                        pdf_tec.set_font("helvetica", 'B', 12); pdf_tec.set_text_color(44, 62, 80); pdf_tec.cell(0, 6, text=f"Objetivo: {obj}", align='C', new_x="LMARGIN", new_y="NEXT")

                        pdf_tec.add_page(); pdf_tec.set_font("helvetica", 'B', 16); pdf_tec.set_text_color(44, 62, 80); pdf_tec.cell(0, 10, text="1. Metricas Tecnicas y Distribucion", new_x="LMARGIN", new_y="NEXT"); pdf_tec.ln(5)
                        y_actual = pdf_tec.get_y()
                        pdf_tec.image(p_sev, x=10, y=y_actual, w=90)
                        pdf_tec.image(p_tip, x=110, y=y_actual+5, w=90)
                        pdf_tec.set_y(y_actual + 95)

                        pdf_tec.add_page(); pdf_tec.set_font("helvetica", 'B', 16); pdf_tec.set_text_color(44, 62, 80); pdf_tec.cell(0, 10, text="2. Estrategia de Remediacion (IA)", new_x="LMARGIN", new_y="NEXT"); pdf_tec.ln(5)
                        pdf_tec.set_font("helvetica", '', 11); pdf_tec.set_text_color(50, 50, 50); pdf_tec.set_x(10)
                        pdf_tec.multi_cell(0, 6, text=blindaje_fpdf(ia_tecnica, truncar_log=False), align='J')
                        
                        pdf_tec.add_page(); pdf_tec.set_font("helvetica", 'B', 16); pdf_tec.set_text_color(44, 62, 80); pdf_tec.cell(0, 10, text="3. Inventario Detallado de Vulnerabilidades", new_x="LMARGIN", new_y="NEXT"); pdf_tec.ln(5)
                        
                        orden_severidad = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Informational": 5}
                        hallazgos_ordenados = sorted(hallazgos_traducidos, key=lambda x: orden_severidad.get(x.get("Riesgo", "Informational"), 6))
                        
                        for h in hallazgos_ordenados:
                            pdf_tec.set_font("helvetica", 'B', 11)
                            riesgo_str = h.get('Riesgo', 'Informational')
                            if riesgo_str == 'Critical': pdf_tec.set_text_color(139, 0, 0)
                            elif riesgo_str == 'High': pdf_tec.set_text_color(211, 47, 47)
                            elif riesgo_str == 'Medium': pdf_tec.set_text_color(245, 124, 0)
                            elif riesgo_str == 'Low': pdf_tec.set_text_color(251, 192, 45)
                            else: pdf_tec.set_text_color(69, 90, 100)
                            
                            titulo = f"[{riesgo_str.upper()}] {h.get('Vulnerabilidad', 'Desconocida')}"
                            pdf_tec.set_x(10)
                            pdf_tec.multi_cell(0, 6, text=blindaje_fpdf(titulo, truncar_log=True), align='L') 
                            
                            pdf_tec.set_font("helvetica", '', 10); pdf_tec.set_text_color(50, 50, 50)
                            impacto = h.get('Impacto', 'N/A')
                            pdf_tec.set_x(10)
                            pdf_tec.multi_cell(0, 5, text=blindaje_fpdf(impacto, truncar_log=True), align='J')
                            pdf_tec.ln(5)
                            
                        pdf_tec.output(p_pdf_tecnico)

                        # Guardar en sesión
                        with open(p_pdf_ejecutivo, "rb") as f_ejec:
                            st.session_state.pdf_ejecutivo = f_ejec.read()
                        with open(p_pdf_tecnico, "rb") as f_tec:
                            st.session_state.pdf_tecnico = f_tec.read()
                        
                        st.session_state.objetivo_nombre = obj
                        st.session_state.analisis_completado = True
                        st.rerun()

                else:
                    st.error("❌ No se encontraron vulnerabilidades válidas o el formato del XML no es compatible.")

if st.session_state.analisis_completado:
    st.success("✅ ¡Análisis completado! Tus reportes están listos.")
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(label="📥 Descargar Reporte Ejecutivo", data=st.session_state.pdf_ejecutivo, file_name=f"Ejecutivo_{st.session_state.objetivo_nombre}.pdf", mime="application/pdf", use_container_width=True)
    with col2:
        st.download_button(label="📥 Descargar Reporte Técnico", data=st.session_state.pdf_tecnico, file_name=f"Tecnico_{st.session_state.objetivo_nombre}.pdf", mime="application/pdf", use_container_width=True)
