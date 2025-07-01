document.addEventListener('DOMContentLoaded', () => {
    // LÓGICA DE NAVEGAÇÃO DAS ABAS
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('data-target');
            if (!targetId) return;
            document.querySelectorAll('.nav-link').forEach(navLink => navLink.classList.remove('active'));
            document.querySelectorAll('.content-panel').forEach(panel => panel.classList.remove('active'));
            link.classList.add('active');
            const targetPanel = document.getElementById(targetId + '-section');
            if (targetPanel) targetPanel.classList.add('active');
        });
    });

    // FUNÇÃO PARA LIDAR COM AÇÕES DE ADMIN
    async function handleAdminAction(id, action) {
        if (!confirm(`Tem certeza que deseja ${action} este recruta?`)) return;
        try {
            const response = await fetch(`/api/admin/${action}/${id}`, { method: 'POST' });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message || 'Falha na operação.');
            showNotification(result.message, 'success');
            await carregarRecrutasPendentes();
        } catch (error) {
            showNotification(error.message, 'error');
        }
    }

    // FUNÇÃO PARA CARREGAR O PAINEL DE ADMIN
    async function carregarRecrutasPendentes() {
        const container = document.getElementById('pending-recruits-container');
        if (!container) return;
        container.innerHTML = '<p>Carregando...</p>';
        try {
            const response = await fetch('/api/admin/recrutas-pendentes');
            if (!response.ok) throw new Error('Falha ao buscar recrutas.');
            const recruits = await response.json();
            if (recruits.length === 0) {
                container.innerHTML = '<p>Nenhum recrutamento pendente.</p>';
                return;
            }
            container.innerHTML = ''; 
            recruits.forEach(recruta => {
                const card = document.createElement('div');
                card.className = 'aviso-card';
                card.innerHTML = `<h4>${recruta.nickname}</h4><p><strong>Email:</strong> ${recruta.email}</p><p><strong>ID:</strong> ${recruta.game_id}</p><div style="margin-top:15px;"><button class="btn-aprovar">Aprovar</button><button class="btn-rejeitar">Rejeitar</button></div>`;
                card.querySelector('.btn-aprovar').addEventListener('click', () => handleAdminAction(recruta.id, 'aprovar'));
                card.querySelector('.btn-rejeitar').addEventListener('click', () => handleAdminAction(recruta.id, 'rejeitar'));
                container.appendChild(card);
            });
        } catch (error) {
            container.innerHTML = `<p style="color:red;">${error.message}</p>`;
        }
    }
    
    // FUNÇÃO PRINCIPAL PARA CARREGAR DADOS
    async function carregarDadosIniciais() {
        try {
            const userResponse = await fetch('/api/user/me');
            if (!userResponse.ok) throw new Error('Falha ao verificar sessão.');
            const userData = await userResponse.json();
            const memberNameEl = document.getElementById('member-name');
            if (memberNameEl && userData.nickname) memberNameEl.textContent = userData.nickname;

            if (userData.isAdmin) {
                document.querySelectorAll('.admin-only').forEach(el => el.classList.add('visible'));
                await carregarRecrutasPendentes();
            }

            const membrosResponse = await fetch('/api/membros');
            const membros = await membrosResponse.json();
            const membrosListEl = document.getElementById('membros-list');
            if (membrosListEl) {
                membrosListEl.innerHTML = membros.length > 0 ? membros.map(m => `<li>${m.nickname}</li>`).join('') : '<li>Nenhum membro encontrado.</li>';
            }
        } catch (error) {
            showNotification('Sessão expirada. Redirecionando...', 'error');
            setTimeout(() => window.location.href = '/login.html', 2000);
        }
    }

    carregarDadosIniciais();
});