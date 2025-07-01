document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('pending-recruits-container');

    async function fetchPendingRecruits() {
        try {
            const response = await fetch('/api/admin/recrutas-pendentes');
            if (!response.ok) throw new Error('Falha ao buscar recrutas.');
            
            const recruits = await response.json();
            
            if (recruits.length === 0) {
                container.innerHTML = '<p>Nenhum recrutamento pendente no momento.</p>';
                return;
            }

            container.innerHTML = recruits.map(recruta => `
                <div class="aviso-card" style="border-left-color: #e50914;">
                    <h4>${recruta.nickname}</h4>
                    <p><strong>Email:</strong> ${recruta.email}</p>
                    <p><strong>ID no Jogo:</strong> ${recruta.game_id}</p>
                    <p><strong>Data do Pedido:</strong> ${new Date(recruta.data_registro).toLocaleString()}</p>
                    <div style="margin-top: 15px;">
                        <button class="btn-cta" onclick="handleRecruitment(${recruta.id}, 'aprovar')">Aprovar</button>
                        <button style="background-color: #555;" class="btn-cta" onclick="handleRecruitment(${recruta.id}, 'rejeitar')">Rejeitar</button>
                    </div>
                </div>
            `).join('');

        } catch (error) {
            container.innerHTML = `<p style="color: red;">${error.message}</p>`;
        }
    }

    window.handleRecruitment = async (id, action) => {
        if (!confirm(`Tem certeza que deseja ${action} este recruta?`)) return;

        try {
            const response = await fetch(`/api/admin/${action}/${id}`, { method: 'POST' });
            if (!response.ok) throw new Error(`Falha ao ${action} o recruta.`);
            
            alert(`Recruta #${id} foi atualizado com sucesso!`);
            fetchPendingRecruits(); // Recarrega a lista
        } catch (error) {
            alert(error.message);
        }
    };

    fetchPendingRecruits();
});