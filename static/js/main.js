// main.js - Lógica del frontend

// Variables globales
let currentReportFilename = null;

// Elementos del DOM
const scanForm = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const btnText = document.getElementById('btnText');
const loading = document.getElementById('loading');
const scanResult = document.getElementById('scanResult');
const btnDownload = document.getElementById('btnDownload');

// Event Listeners
document.addEventListener('DOMContentLoaded', function () {
    console.log('✓ Aplicación cargada correctamente');

    // Formulario de escaneo
    scanForm.addEventListener('submit', handleScan);

    // Botón de descarga
    btnDownload.addEventListener('click', openReport);

    // Auto-focus en el input
    urlInput.focus();
});

/**
 * Maneja el envío del formulario de escaneo
 */
async function handleScan(e) {
    e.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        showError('Por favor ingresa una URL válida');
        return;
    }

    console.log(`🔍 Iniciando escaneo de: ${url}`);

    // Mostrar loading
    showLoading();
    hideResult();

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (data.success) {
            console.log('✓ Escaneo completado exitosamente');
            console.log(`  - Total de hallazgos: ${data.total_findings}`);
            console.log(`  - Reporte: ${data.filename}`);

            // Guardar nombre del archivo
            currentReportFilename = data.filename;

            // Mostrar resultados
            displayResults(data);

            // Pequeño delay para mejor UX
            setTimeout(() => {
                hideLoading();
                showResult();
            }, 500);

        } else {
            throw new Error(data.error || 'Error desconocido en el escaneo');
        }

    } catch (error) {
        console.error('❌ Error:', error);
        hideLoading();
        showError(`Error al realizar el escaneo: ${error.message}`);
    }
}

/**
 * Muestra los resultados del escaneo
 */
function displayResults(data) {
    const summary = data.summary || {};

    // Actualizar contadores
    document.getElementById('statHigh').textContent = summary.high || 0;
    document.getElementById('statMedium').textContent = summary.medium || 0;
    document.getElementById('statLow').textContent = summary.low || 0;
    document.getElementById('statInfo').textContent = summary.info || 0;

    // Animar contadores
    animateCounters();
}

/**
 * Anima los contadores de estadísticas
 */
function animateCounters() {
    const counters = document.querySelectorAll('.stat-number');

    counters.forEach(counter => {
        const target = parseInt(counter.textContent);
        let current = 0;
        const increment = Math.ceil(target / 20);

        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                counter.textContent = target;
                clearInterval(timer);
            } else {
                counter.textContent = current;
            }
        }, 30);
    });
}

/**
 * Abre el reporte PDF en una nueva ventana
 */
function openReport() {
    if (!currentReportFilename) {
        showError('No hay reporte disponible');
        return;
    }

    console.log(`📄 Abriendo reporte: ${currentReportFilename}`);

    const reportUrl = `/api/report/${currentReportFilename}`;
    window.open(reportUrl, '_blank');
}

/**
 * Muestra el indicador de carga
 */
function showLoading() {
    loading.classList.add('active');
    scanBtn.disabled = true;
    btnText.textContent = 'Escaneando...';
}

/**
 * Oculta el indicador de carga
 */
function hideLoading() {
    loading.classList.remove('active');
    scanBtn.disabled = false;
    btnText.textContent = 'Iniciar Análisis';
}

/**
 * Muestra el panel de resultados
 */
function showResult() {
    scanResult.classList.add('active');

    // Scroll suave hacia los resultados
    scanResult.scrollIntoView({
        behavior: 'smooth',
        block: 'nearest'
    });
}

/**
 * Oculta el panel de resultados
 */
function hideResult() {
    scanResult.classList.remove('active');
}

/**
 * Muestra un mensaje de error
 */
function showError(message) {
    // Remover errores anteriores
    const existingError = document.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }

    // Crear nuevo mensaje de error
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.textContent = message;

    // Insertar después del formulario
    scanForm.parentNode.insertBefore(errorDiv, scanForm.nextSibling);

    // Auto-remover después de 5 segundos
    setTimeout(() => {
        errorDiv.style.animation = 'fadeOut 0.3s';
        setTimeout(() => errorDiv.remove(), 300);
    }, 5000);
}

/**
 * Formatea el tamaño de archivo
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Valida una URL
 */
function isValidUrl(string) {
    try {
        const url = new URL(string.startsWith('http') ? string : 'https://' + string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

// Agregar animación fadeOut si no existe
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeOut {
        from { opacity: 1; }
        to { opacity: 0; }
    }
`;
document.head.appendChild(style);

console.log('✓ JavaScript cargado y listo');