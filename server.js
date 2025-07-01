// =================================================================
// 1. IMPORTAÇÃO DAS DEPENDÊNCIAS (VERSÃO POSTGRESQL)
// =================================================================
const express = require('express');
const path = require('path');
const { Pool } = require('pg'); // MUDANÇA: Usando 'pg' para PostgreSQL
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session); // MUDANÇA: Usando o conector de sessão do PostgreSQL

// =================================================================
// 2. CONFIGURAÇÕES INICIAIS
// =================================================================
const app = express();
// O Render define a porta através de uma variável de ambiente, por isso usamos process.env.PORT
const port = process.env.PORT || 3000;
const saltRounds = 10;

// =================================================================
// 3. MIDDLEWARES
// =================================================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// =================================================================
// 4. BANCO DE DADOS E SESSÃO (CONFIGURADO PARA RENDER)
// =================================================================
// MUDANÇA: O 'Pool' se conecta usando a DATABASE_URL que o Render fornece automaticamente
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Essencial para a conexão com o banco de dados do Render
  }
});

// MUDANÇA: Configura o armazenamento da sessão no PostgreSQL
const sessionStore = new pgSession({
    pool: db,                // Usa a mesma conexão do banco
    tableName: 'session'     // Nome da tabela de sessões
});

app.use(session({
    store: sessionStore,
    // IMPORTANTE: Crie esta variável de ambiente no painel do seu Web Service no Render!
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true, // Em produção (Render), o cookie deve ser seguro (HTTPS)
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000 // Duração do login: 30 dias
    }
}));

// =================================================================
// 5. MIDDLEWARES DE AUTENTICAÇÃO
// =================================================================
const isLoggedIn = (req, res, next) => {
    if (!req.session.userId) { return res.redirect('/login.html'); }
    next();
};
const isAdmin = (req, res, next) => {
    if (!req.session.isAdmin) { return res.status(403).json({ error: 'Acesso negado.' }); }
    next();
};

// =================================================================
// 6. ROTAS (SINTAXE DAS QUERIES ATUALIZADA PARA POSTGRESQL)
// =================================================================
// MUDANÇA EM TODAS AS ROTAS: os placeholders agora são $1, $2, etc. em vez de ?

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
// Adicione outras rotas públicas aqui

app.post('/recrutar', async (req, res) => {
    const { nickname, gameid, email, password } = req.body;
    if (!nickname || !gameid || !email || !password) {
        return res.status(400).json({ success: false, message: 'Todos os campos são obrigatórios.' });
    }
    try {
        const passwordHash = await bcrypt.hash(password, saltRounds);
        await db.query("INSERT INTO recrutas (nickname, game_id, email, password_hash) VALUES ($1, $2, $3, $4)", [nickname, gameid, email, passwordHash]);
        res.status(201).json({ success: true, message: 'Recrutamento enviado com sucesso!' });
    } catch (error) {
        // MUDANÇA: Código de erro para 'duplicado' no PostgreSQL é '23505'
        if (error.code === '23505') { return res.status(409).json({ success: false, message: 'Este email já foi cadastrado.' }); }
        console.error("Erro no /recrutar:", error);
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await db.query("SELECT id, nickname, password_hash FROM recrutas WHERE email = $1 AND status = 'aprovado'", [email]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (await bcrypt.compare(password, user.password_hash)) {
                const adminResult = await db.query("SELECT id FROM admins WHERE username = $1", [user.nickname]);
                req.session.userId = user.id;
                req.session.nickname = user.nickname;
                req.session.isAdmin = adminResult.rows.length > 0;
                return res.json({ success: true, redirectUrl: '/dashboard.html' });
            }
        }
        res.status(401).json({ success: false, message: 'Credenciais inválidas ou recrutamento não aprovado.' });
    } catch (error) {
        console.error("Erro no /login:", error);
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) { console.error('Erro ao fazer logout:', err); }
        res.clearCookie('connect.sid'); // Nome padrão do cookie de sessão
        res.redirect('/');
    });
});

// 7. ROTAS PROTEGIDAS E APIs DO DASHBOARD
app.get('/dashboard.html', isLoggedIn, (req, res) => { res.sendFile(path.join(__dirname, 'dashboard.html')); });

app.get('/api/user/me', isLoggedIn, (req, res) => {
    res.json({
        nickname: req.session.nickname,
        isAdmin: req.session.isAdmin || false
    });
});

app.get('/api/membros', isLoggedIn, async (req, res) => {
    const { rows } = await db.query("SELECT nickname FROM recrutas WHERE status = 'aprovado' ORDER BY nickname ASC");
    res.json(rows);
});

// ... (Mantenha as outras rotas de API como /api/chat, /api/admin/..., elas usarão a sintaxe $1, $2, etc. também)

// 8. INICIAR O SERVIDOR
app.listen(port, () => {
    console.log(`Servidor da Facção China rodando na porta ${port}`);
});
