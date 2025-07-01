document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('recruitment-form');
    const successModal = document.getElementById('success-modal');
    const modalOkButton = document.getElementById('modal-ok-button');
    if (!form || !successModal || !modalOkButton) return;

    modalOkButton.addEventListener('click', () => {
        successModal.classList.remove('visible');
        window.location.href = '/';
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const submitButton = form.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.textContent = 'Enviando...';
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        try {
            const response = await fetch('/recrutar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await response.json();
            if (response.ok) {
                form.reset();
                successModal.classList.add('visible');
            } else {
                throw new Error(result.message || 'Erro desconhecido.');
            }
        } catch (error) {
            showNotification(error.message, 'error');
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = 'Enviar para Análise';
        }
    });
});