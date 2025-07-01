document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('login-form');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await response.json();
            if (response.ok && result.success) {
                window.location.href = result.redirectUrl;
            } else {
                throw new Error(result.message || 'Erro desconhecido.');
            }
        } catch (error) {
            showNotification(error.message, 'error');
        }
    });
});