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
