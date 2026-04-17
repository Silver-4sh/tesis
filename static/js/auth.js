/**
 * Bloqueo de envío inteligente: Ignora Honeypot y Captcha
 */
document.addEventListener('DOMContentLoaded', function () {

    // Lógica del ojo (Toggle Password) - Sin cambios
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

    const form = document.querySelector('.needs-validation');
    const submitBtn = document.getElementById('btn-submit-manual');

    if (submitBtn && form) {
        submitBtn.addEventListener('click', function (e) {
            // Evitamos cualquier comportamiento por defecto del click
            e.preventDefault();

            // Seleccionamos solo inputs reales (excluyendo honeypot y captcha de la validación de vacíos)
            const inputs = form.querySelectorAll('input:not([type="hidden"]):not([name="full_name_field"]):not([name*="captcha"])');
            let isFormComplete = true;

            inputs.forEach(input => {
                if (input.value.trim() === "") {
                    isFormComplete = false;
                }
            });

            // Agregamos la clase visual de Bootstrap
            form.classList.add('was-validated');

            if (!isFormComplete) {
                console.log("Error: Campos incompletos.");
                return; // Bloqueamos aquí
            }

            // SI ESTÁ COMPLETO: Enviamos el formulario de forma que Django lo reconozca
            console.log("Formulario válido. Enviando a Django...");

            // Usamos requestSubmit para que se disparen todos los validadores y se adjunten los datos
            if (typeof form.requestSubmit === "function") {
                form.requestSubmit();
            } else {
                form.submit();
            }
        });
    }
});