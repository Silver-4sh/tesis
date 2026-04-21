/**
 * Validaciones combinadas de Autenticación, Perfil y Recuperación de Contraseña
 * Incluye soporte para reCAPTCHA v3 y estilos de validación Bootstrap 5.
 */
document.addEventListener('DOMContentLoaded', function () {

    // --- 1. TOGGLE PASSWORD EYE (Lógica de Autenticación) ---
    const toggleButtons = document.querySelectorAll('.toggle-password');
    toggleButtons.forEach(button => {
        button.addEventListener('click', function (e) {
            e.preventDefault();
            const group = this.closest('.input-group');
            const input = group ? group.querySelector('input') : null;
            const icon = this.querySelector('i');
            if (input && icon) {
                input.type = input.type === 'password' ? 'text' : 'password';
                icon.classList.toggle('bi-eye');
                icon.classList.toggle('bi-eye-slash');
            }
        });
    });

    // --- 2. LÓGICA DE VALIDACIÓN Y ENVÍO (Login, Registro y Reset) ---
    const authForm = document.querySelector('.needs-validation');

    // Buscamos tanto el botón manual del login como el botón submit de pass_reset
    const submitBtnManual = document.getElementById('btn-submit-manual');
    const submitBtnDefault = authForm ? authForm.querySelector('button[type="submit"]') : null;

    /**
     * Función unificada para validar campos y disparar el envío
     * Se usa requestSubmit() para que los scripts de reCAPTCHA intercepten el evento.
     */
    const validateAndSubmit = function (e) {
        // Seleccionamos todos los inputs relevantes (excluyendo técnicos de Django y Captcha)
        const inputs = authForm.querySelectorAll('input:not([type="hidden"]):not([name="full_name_field"]):not([name*="captcha"])');
        let isFormComplete = true;

        inputs.forEach(input => {
            // Si el campo está vacío, marcamos error visual de Bootstrap
            if (input.value.trim() === "") {
                isFormComplete = false;
                input.classList.add('is-invalid');
            } else {
                input.classList.remove('is-invalid');
                input.classList.add('is-valid');
            }
        });

        // Activamos los feedback visuales de Bootstrap
        authForm.classList.add('was-validated');

        // Si el formulario está incompleto, detenemos cualquier proceso de envío
        if (!isFormComplete) {
            e.preventDefault();
            return;
        }

        /**
         * LÓGICA DE ENVÍO PARA RECAPTCHA V3:
         * Si el botón es manual (como en login/registro), usamos requestSubmit().
         * Esto dispara el evento 'submit' nativo, permitiendo que el JS de Google
         * genere el token antes de que la petición llegue al servidor.
         */
        if (this.id === 'btn-submit-manual') {
            e.preventDefault(); // Detenemos el click inicial

            if (typeof authForm.requestSubmit === "function") {
                // Esto permite que los scripts de terceros se ejecuten
                console.log("Disparando requestSubmit para reCAPTCHA...");
                authForm.requestSubmit();
            } else {
                authForm.submit();
            }
        }
    };

    // Aplicar el evento al botón de login/registro (que son type="button")
    if (submitBtnManual && authForm) {
        submitBtnManual.addEventListener('click', validateAndSubmit);
    }

    // Aplicar el evento al formulario de recuperación (que usa botón type="submit")
    if (authForm && !submitBtnManual) {
        authForm.addEventListener('submit', validateAndSubmit);
    }
});