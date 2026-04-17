/**
 * UI Notification Engine - Spanish Version
 */
function showToast(message, type = 'danger') {
    const container = document.getElementById('toastPlacement');
    if (!container) return;

    let icon = 'bi-info-circle';
    const msgLower = message.toLowerCase();
    const typeLower = type.toLowerCase();

    // Map types to icons
    if (typeLower.includes('success') || typeLower.includes('exito')) icon = 'bi-check-circle-fill';
    else if (typeLower.includes('warning') || typeLower.includes('advertencia')) icon = 'bi-exclamation-triangle-fill';
    else if (typeLower.includes('danger') || typeLower.includes('error')) icon = 'bi-exclamation-octagon-fill';

    // Security specific icons (Recognizing Spanish keywords)
    if (msgLower.includes('robot') || msgLower.includes('bot') || msgLower.includes('trampa')) icon = 'bi-robot';
    if (msgLower.includes('captcha') || msgLower.includes('seguridad')) icon = 'bi-shield-lock-fill';

    const toastHtml = `
        <div class="toast align-items-center text-white bg-${typeLower} border-0 shadow-lg mb-2" 
             role="alert" aria-live="assertive" aria-atomic="true" style="min-width: 250px; max-width: 350px;">
            <div class="d-flex">
                <div class="toast-body d-flex align-items-start">
                    <i class="bi ${icon} me-2 mt-1 fs-5"></i>
                    <div style="word-break: break-word;">${message}</div>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Cerrar"></button>
            </div>
        </div>`;

    container.insertAdjacentHTML('beforeend', toastHtml);
    const element = container.lastElementChild;
    const bsToast = new bootstrap.Toast(element, {delay: 5000});
    bsToast.show();
    element.addEventListener('hidden.bs.toast', () => element.remove());
}

// Auto-scanner for base.html data attributes
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.js-toast-source').forEach(el => {
        const message = el.getAttribute('data-message');
        const type = el.getAttribute('data-type') || 'info';
        if (message) showToast(message, type);
        el.remove();
    });
});