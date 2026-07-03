# Memoria Técnica - OmniScanner AI (Sigmac Corp)

## 1. Introducción
El presente documento detalla las implementaciones y cambios recientes realizados en la plataforma **OmniScanner AI**, orientados a mejorar la generación de reportes de ciberseguridad, integración con modelos de inteligencia artificial avanzados (Gemini), mejoras en la interfaz de usuario y robustecimiento de la seguridad de acceso.

## 2. Resumen de Actualizaciones (Changelog Reciente)
- **Mejoras de desempeño IA y autenticación Google OAuth**: Implementación de inicio de sesión seguro para entornos de Streamlit Community Cloud.
- **Reportes Premium (Plantilla HTML Corporativa)**: Rediseño completo de los reportes exportables, incluyendo dashboard de KPI, gráficas integradas y estilos CSS mejorados.
- **Reporte Técnico con Gemini 2.5 Pro**: Enriquecimiento de los reportes técnicos con análisis de verdaderos positivos, puntuaciones CVSS v3.1, identificadores CVE y planes de remediación estructurados.
- **Conversor Markdown a HTML y Tablas CISO**: Implementación de un conversor nativo para procesar la salida de la IA (negritas, listas, tablas pipe) en el reporte ejecutivo, facilitando la lectura de métricas clave.
- **Gestión de Cuotas de API (Fallback de Modelos)**: Ajustes en la lógica de selección de modelos, implementando fallback dinámico de Gemini 2.5 Pro a Flash cuando se agota la cuota del *free tier*, y posterior reversión parcial para forzar el uso de Pro exclusivamente en los reportes técnicos (garantizando máxima calidad analítica).

## 3. Detalles de Implementación Técnica

### 3.1. Autenticación Google OAuth
Se integró autenticación mediante Google OAuth en el entorno de Streamlit Community Cloud, asegurando que solo usuarios autorizados puedan ejecutar escaneos y acceder a los reportes confidenciales.

### 3.2. Motor de Reportes HTML (Plantilla Corporativa Premium)
Se rediseñó la función `generar_html_maestro()` y la constante `PLANTILLA_HTML` para incluir:
- **Dashboard de Postura de Riesgo (KPI Cards)**: Visualización inmediata de hallazgos clasificados por criticidad (Critical, High, Medium, Low).
- **Gráficas de Madurez**: Inserción de imágenes en base64 para gráficos de radar y distribución de riesgos, incluyendo una tabla de áreas de seguridad con barras de progreso de madurez.
- **Inventario Técnico Consolidado**: Listado de vulnerabilidades con diseño tipo tarjeta (vuln-card), indicando la ruta/endpoint impactado y el impacto directo.
- **Estilos CSS Embebidos**: Variables de color, tipografía corporativa y diseño responsivo para impresión y visualización.

### 3.3. Integración con Gemini 2.5 Pro y Prompts Estructurados
Se actualizaron los prompts enviados al modelo (`MODELO_EJECUTIVO` y modelo técnico) para requerir respuestas altamente estructuradas con secciones delimitadas (`##SECCION##`):
- **Reporte Ejecutivo**: Enfoque en riesgo de negocio, métricas de exposición (tablas pipe Markdown), MTTR y porcentaje de superficie de ataque.
- **Reporte Técnico**: Enfoque técnico (Red Team) forzando el uso de **Gemini 2.5 Pro**. Incluye análisis profundo de falsos positivos, vectores de ataque, severidad (CVSS v3.1) y mitigación detallada.

A continuación, se documentan los prompts base exactos inyectados en la aplicación:

<details>
<summary><b>1. Prompt - Traducción de Inventario</b></summary>

```text
Traduce al español técnico SOLAMENTE los valores de 'Vulnerabilidad' e 'Impacto'. 
Las claves 'Riesgo' y 'Ruta' DEBEN QUEDAR EXACTAMENTE IGUAL. 
Devuelve JSON puro, sin texto adicional ni backticks:
[LOTE_DE_HALLAZGOS_EN_JSON]
```
</details>

<details>
<summary><b>2. Prompt - Reporte Ejecutivo (CISO)</b></summary>

```text
Actúas como el Consultor Estratégico CISO de Sigmac Corp.
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
[2 párrafos describiendo el riesgo de negocio global...]

##ÁREAS DE EXPOSICIÓN CRÍTICA##
[Lista con - de 4-5 áreas de riesgo de negocio...]

##ANÁLISIS DE IMPACTO POR ÁREA DE NEGOCIO##
[Tabla con Área de Negocio, Nivel de Exposición, Consecuencia Inmediata, etc.]

##ROADMAP DE ACCIÓN ESTRATÉGICO##
[Tabla con Fase, Período, Acciones Clave, Responsables, Indicador]

##MÉTRICAS DE EXPOSICIÓN##
[Tabla con Métrica Clave, Valor Estimado, Estado, Objetivo de Remediación]
```
</details>

<details>
<summary><b>3. Prompt - Reporte Técnico (Red Team)</b></summary>

```text
Eres el analista líder de un equipo Red Team de elite especializado en seguridad ofensiva web.
Tu misión es producir una Guía Técnica Maestra de máxima calidad para los ingenieros de seguridad de Sigmac Corp.
El reporte debe ser rigurosamente preciso: distingue explícitamente entre hallazgos confirmados y probables falsos positivos.

CONTEXTO DEL ESCANEO:
Objetivo auditado: {objetivo}
Motores de escaneo utilizados: {escaneres_str}
Total de hallazgos a analizar: {total_h}

INVENTARIO COMPLETO DE HALLAZGOS:
{datos_texto}

INSTRUCCIONES CRÍTICAS:
1. Usa tu base de conocimiento de seguridad para determinar qué hallazgos son probables verdaderos positivos y cuáles son falsos positivos...
2. Para cada vulnerabilidad crítica, asigna un score CVSS v3.1 estimado y su vector string.
3. Referencia CVE específicos cuando el hallazgo corresponda a una vulnerabilidad conocida.
4. La remediación debe ser concreta, con pasos ordenados por impacto y tiempo estimado.
5. PROHIBIDO código de explotación malicioso. El vector de ataque es siempre conceptual.
6. Separa los párrafos con una línea en blanco. No uses Markdown (sin asteriscos, sin hashes).
7. Usa EXACTAMENTE los encabezados ##SECCION## indicados a continuación.

FORMATO OBLIGATORIO DE SALIDA:

##PANORAMA GENERAL DEL ESCANEO##
##CLASIFICACIÓN: VERDADEROS POSITIVOS VS FALSOS POSITIVOS##
##ANÁLISIS PROFUNDO DE VULNERABILIDADES CRÍTICAS##
##HALLAZGOS DESCARTABLES - FALSOS POSITIVOS DETECTADOS##
##SUPERFICIE DE ATAQUE PRIORITARIA PARA PRUEBAS MANUALES##
##DIAGNÓSTICO DE AUTENTICACIÓN Y GESTIÓN DE SESIONES##
##PLAN DE REMEDIACIÓN PRIORIZADO##
```
</details>

### 3.4. Parseo de Markdown a HTML (Custom Parser)
Dado que los reportes PDF/HTML no renderizaban el Markdown generado por la IA por defecto, se implementó la función `markdown_a_html(texto)` y su auxiliar `_inline_md(texto)`.
- **Soporte Inline**: Negritas (`**`), cursivas (`*`) y código en línea (`` ` ``).
- **Soporte de Bloque**: Tablas estilo pipe (`| Col | Col |`), listas desordenadas (`*`, `-`), listas ordenadas (`1.`) y separadores (`---`).
- Estas funciones convierten el texto generado por Gemini en etiquetas HTML limpias (`<table>`, `<ul>`, `<strong>`, etc.) con clases CSS predefinidas (`ai-table`, `ai-ul`), que luego se inyectan en el HTML del reporte de forma segura.

### 3.5. Fallback de Modelos de IA
Se implementó un sistema de control de errores al llamar a la API de Gemini:
- Se añadió un mecanismo automático que cambia de `gemini-2.5-pro` a `gemini-2.5-flash` en caso de errores `429 Too Many Requests` (agotamiento de cuota de la capa gratuita).
- **Reversión selectiva**: Para garantizar la calidad del "Reporte Técnico Maestro", se eliminó el fallback automático en dicho flujo, obligando a usar la versión Pro debido a la necesidad de máxima capacidad analítica.

## 4. Archivos Clave Modificados
- **`app.py`**: Contiene la lógica principal del frontend interactivo (Streamlit), renderizado HTML (Jinja2), procesamiento de prompts estructurados hacia Gemini y manejo de plantillas/gráficos base64.
- **`requirements.txt`**: Modificado para ajustar las dependencias actuales del entorno (se eliminó además el archivo redundante `packages.txt`).

## 5. Conclusión
Las actualizaciones transforman el aplicativo en una herramienta Enterprise-ready. La sinergia entre Gemini 2.5 Pro, una interfaz rediseñada y un motor de reportes HTML avanzado permite entregar resultados de auditoría técnica precisos y comprensibles a nivel ejecutivo, todo dentro del ecosistema de Streamlit y Google Cloud.
