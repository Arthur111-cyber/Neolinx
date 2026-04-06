# NeoLinx v3.1 - Reconnaissance & OSINT Suite

NeoLinx es una suite de auditoría perimetral y recolección de inteligencia de fuentes abiertas (OSINT). Esta herramienta ha sido desarrollada bajo estándares de optimización de procesos para permitir a los administradores de sistemas y analistas de seguridad mapear la infraestructura de red de manera eficiente, rápida y estructurada.

## Descripción Técnica

La versión 3.1 representa una reingeniería completa del núcleo original, migrando la lógica a un entorno moderno y escalable. Se han implementado mejoras críticas en la gestión de recursos y en la persistencia de datos para garantizar resultados precisos en entornos de auditoría corporativa.

## Características Principales

* **Procesamiento Concurrente (Threading):** Implementación de hilos para el escaneo de puertos, permitiendo la evaluación simultánea de múltiples vectores y reduciendo drásticamente los tiempos de espera.
* **Gestión Automatizada de Reportes:** Generación automática de registros detallados en formato de texto plano dentro de un directorio estructurado para su posterior análisis.
* **Sanitización de Entradas:** Módulo de validación inteligente de URLs y protocolos para prevenir fallos durante la fase de comunicación con los servicios externos.
* **Arquitectura Modular:** Diseño basado en funciones independientes que facilitan el mantenimiento y la escalabilidad del código.

## Módulos de Auditoría

1. **DNS Lookup:** Análisis de registros A, MX, NS y TXT para determinar la arquitectura de servicios de nombres.
2. **Whois Lookup:** Obtención de información administrativa, legal y de contacto asociada al dominio.
3. **GeoIP Locator:** Identificación de la ubicación física del servidor y resolución del proveedor de servicios de internet (ISP).
4. **HTTP Header Analyzer:** Evaluación de políticas de seguridad en la capa de aplicación (HSTS, CORS, protección XSS).
5. **Port Scanner:** Verificación del estado de puertos críticos mediante escaneo TCP de alto rendimiento.
6. **Robots.txt Scraper:** Extracción de directivas de exclusión y rutas de directorios no indexados.
7. **Subdomain Finder:** Identificación de activos secundarios y paneles de administración mediante reconocimiento pasivo.

## Requisitos del Sistema

* Sistema Operativo: Distribuciones basadas en Linux.
* Intérprete: Python 3.8 o superior.
* Librerías requeridas:
    * requests
    * dnspython
    * python-whois

## Instalación y Configuración

1. Clonar o descargar el script principal `neolinx.py`.
2. Instalar las dependencias necesarias a través del gestor de paquetes de Python:
   ```bash
   pip install requests dnspython python-whois

3.   Otorgar permisos de ejecución al archivo principal para permitir su uso como binario:
    Bash
    chmod +x neolinx.py
4. Guía de Uso
Para iniciar la suite de auditoría, ejecute el siguiente comando desde la terminal dentro del directorio del proyecto:
    Bash
    python neolinx.py

Al finalizar cada operación, NeoLinx almacenará automáticamente los resultados en la carpeta .neolinx_reports/. Los archivos se nombran siguiendo el patrón objetivo_herramienta_fecha.txt para mantener un orden cronológico en la auditoría.

## Aviso Legal

NeoLinx es una herramienta diseñada exclusivamente para fines educativos y de auditoría ética. El uso de esta suite contra infraestructuras de red sin autorización previa y por escrito es responsabilidad única del usuario. El autor no asume responsabilidad por el uso indebido de la información recolectada ni por posibles daños derivados de la ejecución de escaneos activos en redes de terceros.

Desarrollador: Linx
Versión: 3.1 (Estable)
Estado del Proyecto: Mantenimiento y Auditoría Perimetral