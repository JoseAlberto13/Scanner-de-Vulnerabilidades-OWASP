"""
app.py - Servidor Flask principal
"""
from flask import Flask, render_template, request, send_file, jsonify
import os
from datetime import datetime

# Importar módulos propios
from config import Config
from scanner import VulnerabilityScanner
from pdf_generator import PDFReportGenerator

# Inicializar Flask
app = Flask(__name__)

# Inicializar configuración
Config.init_app()

# Inicializar módulos
scanner = VulnerabilityScanner(
    timeout=Config.SCAN_TIMEOUT,
    verify_ssl=Config.VERIFY_SSL
)
pdf_generator = PDFReportGenerator(Config.REPORTS_DIR)

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html', owasp_data=Config.OWASP_TOP_10)

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    """Endpoint para iniciar escaneo"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL no proporcionada'
            }), 400
        
        # Validar URL básica
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"\n{'='*60}")
        print(f"Iniciando escaneo de: {url}")
        print(f"{'='*60}\n")
        
        # Realizar escaneo
        scan_results = scanner.scan(url)
        
        print(f"✓ Escaneo completado")
        print(f"  - Hallazgos totales: {len(scan_results['findings'])}")
        print(f"  - Alta: {scan_results['summary']['high']}")
        print(f"  - Media: {scan_results['summary']['medium']}")
        print(f"  - Baja: {scan_results['summary']['low']}")
        
        # Generar PDF
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"reporte_{timestamp}.pdf"
        pdf_path = pdf_generator.generate(scan_results, filename)
        
        # Verificar que el PDF se creó correctamente
        if not os.path.exists(pdf_path):
            raise Exception("El archivo PDF no se generó correctamente")
        
        return jsonify({
            'success': True,
            'filename': filename,
            'summary': scan_results['summary'],
            'total_findings': len(scan_results['findings'])
        })
        
    except Exception as e:
        print(f"❌ Error en escaneo: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/report/<filename>')
def get_report(filename):
    """Endpoint para descargar reporte PDF"""
    try:
        pdf_path = os.path.join(Config.REPORTS_DIR, filename)
        
        if not os.path.exists(pdf_path):
            print(f"❌ Archivo no encontrado: {pdf_path}")
            return jsonify({
                'error': 'Reporte no encontrado'
            }), 404
        
        print(f"✓ Enviando reporte: {filename}")
        return send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=False,
            download_name=filename
        )
        
    except Exception as e:
        print(f"❌ Error al enviar reporte: {str(e)}")
        return jsonify({
            'error': f'Error al cargar el reporte: {str(e)}'
        }), 500

@app.route('/api/reports')
def list_reports():
    """Endpoint para listar reportes disponibles"""
    try:
        reports = []
        for filename in os.listdir(Config.REPORTS_DIR):
            if filename.endswith('.pdf'):
                filepath = os.path.join(Config.REPORTS_DIR, filename)
                stats = os.stat(filepath)
                reports.append({
                    'filename': filename,
                    'size': stats.st_size,
                    'created': datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                })
        
        # Ordenar por fecha de creación (más reciente primero)
        reports.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({
            'success': True,
            'reports': reports
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    """Manejo de errores 404"""
    return jsonify({'error': 'Endpoint no encontrado'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores 500"""
    return jsonify({'error': 'Error interno del servidor'}), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  SCANNER DE VULNERABILIDADES OWASP")
    print("="*60)
    print(f"\n✓ Servidor Flask inicializado")
    print(f"✓ Modo Debug: {'Activado' if Config.DEBUG else 'Desactivado'}")
    print(f"✓ Directorio de reportes: {Config.REPORTS_DIR}")
    print(f"\n🌐 Accede a la aplicación en:")
    print(f"   → http://localhost:{Config.PORT}")
    print(f"   → http://127.0.0.1:{Config.PORT}")
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )