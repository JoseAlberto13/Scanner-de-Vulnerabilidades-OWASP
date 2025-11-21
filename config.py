"""
config.py - Configuración de la aplicación
"""
import os

class Config:
    # Configuración del servidor
    HOST = '0.0.0.0'
    PORT = 5000
    DEBUG = False
    
    # Rutas
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
    STATIC_DIR = os.path.join(BASE_DIR, 'static')
    
    # Configuración de escaneo
    SCAN_TIMEOUT = 10
    VERIFY_SSL = False
    
    # Datos OWASP Top 10
    OWASP_TOP_10 = [
        {
            "title": "A01:2021 – Broken Access Control",
            "description": "El control de acceso roto permite a los atacantes acceder a datos o funciones no autorizadas. Las violaciones comunes incluyen la falta de verificación de privilegios y la manipulación de URLs.",
            "severity": "high"
        },
        {
            "title": "A02:2021 – Cryptographic Failures",
            "description": "Fallas relacionadas con la criptografía que pueden resultar en exposición de datos sensibles. Incluye uso de algoritmos débiles, falta de cifrado o implementación incorrecta.",
            "severity": "high"
        },
        {
            "title": "A03:2021 – Injection",
            "description": "Las vulnerabilidades de inyección (SQL, NoSQL, OS, LDAP) ocurren cuando datos no confiables se envían a un intérprete como parte de un comando o consulta.",
            "severity": "high"
        },
        {
            "title": "A04:2021 – Insecure Design",
            "description": "Fallas en el diseño de seguridad y defectos arquitectónicos. Se refiere a riesgos inherentes al diseño, no a una implementación defectuosa.",
            "severity": "high"
        },
        {
            "title": "A05:2021 – Security Misconfiguration",
            "description": "Configuraciones de seguridad inadecuadas, permisos incorrectos, servicios innecesarios habilitados o configuraciones predeterminadas inseguras.",
            "severity": "medium"
        },
        {
            "title": "A06:2021 – Vulnerable and Outdated Components",
            "description": "Uso de componentes con vulnerabilidades conocidas, bibliotecas desactualizadas o sin parches de seguridad aplicados.",
            "severity": "medium"
        },
        {
            "title": "A07:2021 – Identification and Authentication Failures",
            "description": "Fallas en la confirmación de la identidad del usuario, autenticación o gestión de sesiones que pueden permitir comprometer contraseñas o tokens.",
            "severity": "high"
        },
        {
            "title": "A08:2021 – Software and Data Integrity Failures",
            "description": "Fallas relacionadas con la integridad del software y datos, incluyendo actualizaciones inseguras y deserialización de datos no confiables.",
            "severity": "medium"
        },
        {
            "title": "A09:2021 – Security Logging and Monitoring Failures",
            "description": "Falta de registro, detección, monitoreo y respuesta activa a incidentes de seguridad, lo que permite que los ataques pasen desapercibidos.",
            "severity": "low"
        },
        {
            "title": "A10:2021 – Server-Side Request Forgery (SSRF)",
            "description": "SSRF ocurre cuando una aplicación web obtiene un recurso remoto sin validar la URL proporcionada por el usuario, permitiendo acceso a recursos internos.",
            "severity": "medium"
        }
    ]
    
    @staticmethod
    def init_app():
        """Inicializa directorios necesarios"""
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        print(f"✓ Directorio de reportes: {Config.REPORTS_DIR}")