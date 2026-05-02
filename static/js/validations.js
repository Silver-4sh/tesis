document.addEventListener('DOMContentLoaded', function () {

    // 1. TOGGLE PASSWORD EYE
    const toggleButtons = document.querySelectorAll('.toggle-password');
    toggleButtons.forEach(button => {
        button.addEventListener('click', function (e) {
            e.preventDefault();
            const group = this.closest('.input-group');
            const input = group?.querySelector('input');
            const icon = this.querySelector('i');
            if (input && icon) {
                input.type = input.type === 'password' ? 'text' : 'password';
                icon.classList.toggle('bi-eye');
                icon.classList.toggle('bi-eye-slash');
            }
        });
    });

    // 2. VALIDATION AND SUBMISSION LOGIC
    const authForm = document.querySelector('.needs-validation');
    const submitBtnManual = document.getElementById('btn-submit');

    if (authForm) {
        const validateAndSubmit = function (e) {
            // Check HTML5 validity (required attributes, types, etc.)
            if (!authForm.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
            }

            // Apply Bootstrap visual styles
            authForm.classList.add('was-validated');

            // --- RECAPTCHA V3 HANDLING ---
            // If triggered by the manual button (Login/Register), use requestSubmit
            if (this.id === 'btn-submit' && authForm.checkValidity()) {
                e.preventDefault();
                if (typeof authForm.requestSubmit === "function") {
                    authForm.requestSubmit();
                } else {
                    authForm.submit();
                }
            }
        };

        // Case A: Manual button (usually type="button" in Login/Register)
        if (submitBtnManual) {
            submitBtnManual.addEventListener('click', validateAndSubmit);
        }

        // Case B: Native submit (usually type="submit" in Password Reset)
        authForm.addEventListener('submit', validateAndSubmit);
    }
});