"""
scanner.py - Módulo de escaneo de vulnerabilidades
"""
import requests
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
import urllib3
import nmap

# Suprimir advertencias SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnerabilityScanner:
    """Escáner de vulnerabilidades web"""
    
    def __init__(self, timeout=10, verify_ssl=False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
    def scan(self, url):
        """
        Realiza un escaneo completo de vulnerabilidades
        
        Args:
            url (str): URL del sitio a escanear
            
        Returns:
            dict: Resultados del escaneo
        """
        results = {
            'url': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': [],
            'summary': {
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        try:
            # Realizar todas las verificaciones web
            self._check_security_headers(url, results)
            self._check_ssl_tls(url, results)
            self._check_cookies(url, results)
            self._check_http_methods(url, results)

            # Escaneo de puertos y servicios con Nmap
            self._scan_ports_nmap(url, results)
            
            # Calcular resumen
            for finding in results['findings']:
                severity = finding['severity'].lower()
                if severity in results['summary']:
                    results['summary'][severity] += 1
                    
        except Exception as e:
            results['findings'].append({
                'severity': 'ERROR',
                'category': 'Escaneo',
                'issue': 'Error general',
                'description': f'Error durante el escaneo: {str(e)}',
                'recommendation': 'Verificar la URL e intentar nuevamente.'
            })
        
        return results

    def _scan_ports_nmap(self, url, results):
        """Realiza un escaneo básico de puertos/servicios usando Nmap

        Se centra en los puertos más comunes y en la detección de versión (-sV),
        similar a un escaneo de reconocimiento inicial típico.
        """
        try:
            parsed = urlparse(url)
            # Extraer host (sin puerto)
            host = parsed.netloc.split(':')[0] if parsed.netloc else parsed.path.split('/')[0]
            if not host:
                return

            nm = nmap.PortScanner()

            # Escaneo rápido de los puertos más comunes con detección de versión
            # -sV: Detectar versión de servicio
            # -T4: Velocidad agresiva pero razonable
            # --top-ports 100: Top 100 puertos más frecuentes
            nm.scan(hosts=host, arguments='-sV -T4 --top-ports 100')

            if host not in nm.all_hosts():
                return

            host_data = nm[host]

            # Estado general del host
            host_state = host_data.state()
            if host_state != 'up':
                results['findings'].append({
                    'severity': 'INFO',
                    'category': 'Nmap',
                    'issue': 'Host no accesible',
                    'description': f'El host {host} aparece como "{host_state}" según Nmap.',
                    'recommendation': 'Verificar conectividad de red o reglas de firewall.'
                })
                return

            # Severidades heurísticas según servicio/puerto
            high_risk_services = {'ms-wbt-server', 'rdp', 'telnet', 'vnc'}
            medium_risk_services = {'ftp', 'ssh', 'mysql', 'postgresql', 'mssql', 'mongodb'}

            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in sorted(ports):
                    port_info = host_data[proto][port]
                    state = port_info.get('state', 'unknown')
                    name = port_info.get('name', 'desconocido')
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')

                    if state != 'open':
                        continue

                    service_str = f"{name} {product} {version}".strip()

                    # Determinar severidad base
                    service_lower = name.lower()
                    if service_lower in high_risk_services:
                        severity = 'HIGH'
                    elif service_lower in medium_risk_services:
                        severity = 'MEDIUM'
                    elif port in (21, 23):  # FTP/Telnet por puerto
                        severity = 'HIGH'
                    else:
                        severity = 'INFO'

                    description = (
                        f"Puerto {port}/{proto} abierto ejecutando servicio '{service_str or 'desconocido'}'. "
                        "Los servicios expuestos aumentan la superficie de ataque y deben estar justificados."
                    )

                    if severity == 'HIGH':
                        recommendation = (
                            "Restringir el acceso al servicio a través de firewall, usar VPN cuando sea posible, "
                            "y deshabilitarlo si no es estrictamente necesario."
                        )
                    elif severity == 'MEDIUM':
                        recommendation = (
                            "Asegurar que el servicio esté actualizado, correctamente configurado y protegido con "
                            "autenticación robusta y cifrado fuerte."
                        )
                    else:
                        recommendation = (
                            "Mantener este servicio actualizado y documentado. Verificar periódicamente si sigue siendo necesario."
                        )

                    results['findings'].append({
                        'severity': severity,
                        'category': 'Network Services',
                        'issue': f'Servicio expuesto: {name} (puerto {port}/{proto})',
                        'description': description,
                        'recommendation': recommendation
                    })
        except Exception as e:
            results['findings'].append({
                'severity': 'ERROR',
                'category': 'Nmap',
                'issue': 'Error al escanear puertos',
                'description': f'Error: {str(e)}',
                'recommendation': 'Verificar la configuración de Nmap y la conectividad de red.'
            })
    
    def _check_security_headers(self, url, results):
        """Verifica headers de seguridad"""
        try:
            response = requests.get(url, timeout=self.timeout, verify=self.verify_ssl)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Protección contra Clickjacking',
                'X-Content-Type-Options': 'Protección MIME-Type Sniffing',
                'Strict-Transport-Security': 'HTTPS obligatorio (HSTS)',
                'Content-Security-Policy': 'Política de seguridad de contenido',
                'X-XSS-Protection': 'Protección XSS del navegador',
                'Referrer-Policy': 'Control de información del referrer',
                'Permissions-Policy': 'Control de permisos del navegador'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    results['findings'].append({
                        'severity': 'MEDIUM',
                        'category': 'Security Headers',
                        'issue': f'Header faltante: {header}',
                        'description': f'{description}. Este header no está configurado.',
                        'recommendation': f'Agregar el header {header} en la configuración del servidor.'
                    })
            
            # Verificar si el servidor expone información sensible
            if 'Server' in headers:
                results['findings'].append({
                    'severity': 'LOW',
                    'category': 'Information Disclosure',
                    'issue': 'Banner del servidor visible',
                    'description': f'El servidor expone su versión: {headers["Server"]}',
                    'recommendation': 'Ocultar o modificar el banner del servidor para no revelar información.'
                })
                
            if 'X-Powered-By' in headers:
                results['findings'].append({
                    'severity': 'LOW',
                    'category': 'Information Disclosure',
                    'issue': 'Tecnología expuesta',
                    'description': f'El servidor expone la tecnología utilizada: {headers["X-Powered-By"]}',
                    'recommendation': 'Remover el header X-Powered-By.'
                })
                
        except requests.exceptions.RequestException as e:
            results['findings'].append({
                'severity': 'ERROR',
                'category': 'Conexión',
                'issue': 'Error al verificar headers',
                'description': f'No se pudo conectar: {str(e)}',
                'recommendation': 'Verificar que la URL sea correcta y el sitio esté accesible.'
            })
    
    def _check_ssl_tls(self, url, results):
        """Verifica configuración SSL/TLS"""
        if url.startswith('https://'):
            domain = urlparse(url).netloc
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        protocol = ssock.version()
                        
                        results['findings'].append({
                            'severity': 'INFO',
                            'category': 'SSL/TLS',
                            'issue': 'Certificado SSL válido',
                            'description': f'Protocolo: {protocol}. Válido hasta: {cert.get("notAfter", "desconocido")}',
                            'recommendation': 'Mantener el certificado actualizado y renovar antes del vencimiento.'
                        })
                        
                        # Verificar protocolo TLS
                        if protocol in ['TLSv1', 'TLSv1.1']:
                            results['findings'].append({
                                'severity': 'HIGH',
                                'category': 'SSL/TLS',
                                'issue': 'Protocolo TLS obsoleto',
                                'description': f'El servidor usa {protocol} que es inseguro.',
                                'recommendation': 'Actualizar a TLS 1.2 o superior.'
                            })
                            
            except ssl.SSLError as e:
                results['findings'].append({
                    'severity': 'HIGH',
                    'category': 'SSL/TLS',
                    'issue': 'Error en certificado SSL',
                    'description': f'Problema SSL detectado: {str(e)}',
                    'recommendation': 'Revisar y corregir la configuración del certificado SSL/TLS.'
                })
            except Exception as e:
                results['findings'].append({
                    'severity': 'MEDIUM',
                    'category': 'SSL/TLS',
                    'issue': 'No se pudo verificar SSL',
                    'description': f'Error: {str(e)}',
                    'recommendation': 'Verificar la configuración SSL del servidor.'
                })
        else:
            results['findings'].append({
                'severity': 'HIGH',
                'category': 'Transport Security',
                'issue': 'No usa HTTPS',
                'description': 'El sitio no utiliza conexión segura HTTPS. Los datos se transmiten sin cifrar.',
                'recommendation': 'Implementar certificado SSL/TLS y forzar HTTPS en todo el sitio.'
            })
    
    def _check_cookies(self, url, results):
        """Verifica configuración de cookies"""
        try:
            response = requests.get(url, timeout=self.timeout, verify=self.verify_ssl)
            
            if 'Set-Cookie' in response.headers:
                cookies_str = response.headers['Set-Cookie']
                
                if 'Secure' not in cookies_str:
                    results['findings'].append({
                        'severity': 'MEDIUM',
                        'category': 'Cookies',
                        'issue': 'Cookies sin atributo Secure',
                        'description': 'Las cookies no tienen el flag Secure, pueden ser interceptadas en conexiones no HTTPS.',
                        'recommendation': 'Agregar el atributo Secure a todas las cookies sensibles.'
                    })
                    
                if 'HttpOnly' not in cookies_str:
                    results['findings'].append({
                        'severity': 'MEDIUM',
                        'category': 'Cookies',
                        'issue': 'Cookies sin atributo HttpOnly',
                        'description': 'Las cookies son accesibles desde JavaScript, aumentando el riesgo de XSS.',
                        'recommendation': 'Agregar el atributo HttpOnly para prevenir acceso via JavaScript.'
                    })
                    
                if 'SameSite' not in cookies_str:
                    results['findings'].append({
                        'severity': 'LOW',
                        'category': 'Cookies',
                        'issue': 'Cookies sin atributo SameSite',
                        'description': 'Las cookies no tienen protección contra CSRF mediante SameSite.',
                        'recommendation': 'Agregar el atributo SameSite=Strict o SameSite=Lax.'
                    })
                    
        except Exception:
            pass
    
    def _check_http_methods(self, url, results):
        """Verifica métodos HTTP permitidos"""
        try:
            options_response = requests.options(url, timeout=5, verify=self.verify_ssl)
            
            if 'Allow' in options_response.headers:
                methods = options_response.headers['Allow']
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in dangerous_methods if m in methods]
                
                if found_dangerous:
                    results['findings'].append({
                        'severity': 'MEDIUM',
                        'category': 'HTTP Methods',
                        'issue': 'Métodos HTTP peligrosos habilitados',
                        'description': f'Métodos detectados: {", ".join(found_dangerous)}. Pueden ser explotados por atacantes.',
                        'recommendation': 'Deshabilitar métodos HTTP innecesarios en la configuración del servidor.'
                    })
                    
                if 'TRACE' in methods:
                    results['findings'].append({
                        'severity': 'LOW',
                        'category': 'HTTP Methods',
                        'issue': 'Método TRACE habilitado',
                        'description': 'El método TRACE puede ser usado en ataques XST (Cross-Site Tracing).',
                        'recommendation': 'Deshabilitar el método TRACE en el servidor.'
                    })
                    
        except Exception:
            pass