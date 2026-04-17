/**
 * theme.js
 * Gestión del modo oscuro/claro para la aplicación de Economía Circular.
 * Utiliza las capacidades nativas de Bootstrap 5 y localStorage.
 */

document.addEventListener('DOMContentLoaded', function () {
    // Selección de elementos del DOM
    const themeToggle = document.getElementById('themeToggle');
    if (!themeToggle) return; // Verificación de seguridad si el botón no existe en la página

    const themeIcon = themeToggle.querySelector('.bi');
    const htmlElement = document.documentElement;

    /**
     * Función para actualizar el icono del botón según el tema activo.
     * @param {string} theme - El tema actual ('dark' o 'light').
     */
    const updateIcon = (theme) => {
        themeIcon.classList.remove('bi-sun', 'bi-moon');
        if (theme === 'dark') {
            themeIcon.classList.add('bi-sun'); // Muestra sol para volver a luz
        } else {
            themeIcon.classList.add('bi-moon'); // Muestra luna para volver a oscuridad
        }
    };

    /**
     * Inicialización del tema al cargar la página.
     * Prioriza la selección guardada en localStorage, luego la preferencia del sistema.
     */
    const initTheme = () => {
        const savedTheme = localStorage.getItem('bsTheme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

        let activeTheme = 'light'; // Por defecto

        if (savedTheme) {
            activeTheme = savedTheme;
        } else if (prefersDark) {
            activeTheme = 'dark';
        }

        htmlElement.setAttribute('data-bs-theme', activeTheme);
        updateIcon(activeTheme);
    };

    // Ejecutar inicialización
    initTheme();

    /**
     * Evento Click: Cambia entre los modos 'light' y 'dark'.
     */
    themeToggle.addEventListener('click', function () {
        const currentTheme = htmlElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        // Aplicar el nuevo tema al atributo de datos de Bootstrap 5
        htmlElement.setAttribute('data-bs-theme', newTheme);

        // Persistir la elección en el navegador
        localStorage.setItem('bsTheme', newTheme);

        // Actualizar la interfaz visual
        updateIcon(newTheme);
    });
});