// 1. IMPORTAÇÕES
const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);

// 2. CONFIGURAÇÕES INICIAIS
const app = express();
const port = 3000;
const saltRounds = 10;

// 3. MIDDLEWARES
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// 4. BANCO DE DADOS E SESSÃO
const poolOptions = {
	host: 'localhost',
	port: 3306,
	user: 'root',
	password: '',
	database: 'faccao_final_db', // ATENÇÃO: Verifique se este é o nome correto do seu banco de dados
    connectionLimit: 10,
    waitForConnections: true,
    queueLimit: 0
};
const db = mysql.createPool(poolOptions).promise();
const sessionStore = new MySQLStore({}, db);

app.use(session({
    key: 'session_cookie_name',
    secret: 'uma-chave-secreta-muito-forte-e-aleatoria',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 dias
}));

// 5. MIDDLEWARES DE AUTENTICAÇÃO
const isLoggedIn = (req, res, next) => {
    if (!req.session.userId) { return res.redirect('/login.html'); }
    next();
};
const isAdmin = (req, res, next) => {
    if (!req.session.isAdmin) { return res.status(403).json({ error: 'Acesso negado.' }); }
    next();
};

// 6. ROTAS PÚBLICAS
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
app.get('/login.html', (req, res) => { res.sendFile(path.join(__dirname, 'login.html')); });
app.get('/recrutamento.html', (req, res) => { res.sendFile(path.join(__dirname, 'recrutamento.html')); });
// Adicione outras rotas para páginas públicas se precisar

app.post('/recrutar', async (req, res) => {
    const { nickname, gameid, email, password } = req.body;
    if (!nickname || !gameid || !email || !password) {
        return res.status(400).json({ success: false, message: 'Todos os campos são obrigatórios.' });
    }
    try {
        const passwordHash = await bcrypt.hash(password, saltRounds);
        await db.query("INSERT INTO recrutas (nickname, game_id, email, password_hash) VALUES (?, ?, ?, ?)", [nickname, gameid, email, passwordHash]);
        res.status(201).json({ success: true, message: 'Recrutamento enviado com sucesso!' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') { return res.status(409).json({ success: false, message: 'Este email já foi cadastrado.' }); }
        console.error("Erro no /recrutar:", error);
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await db.query("SELECT id, nickname, password_hash FROM recrutas WHERE email = ? AND status = 'aprovado'", [email]);
        if (rows.length > 0) {
            const user = rows[0];
            if (await bcrypt.compare(password, user.password_hash)) {
                const [adminRows] = await db.query("SELECT id FROM admins WHERE username = ?", [user.nickname]);
                req.session.userId = user.id;
                req.session.nickname = user.nickname;
                req.session.isAdmin = adminRows.length > 0;
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
        res.clearCookie('session_cookie_name');
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
    try {
        const [rows] = await db.query("SELECT nickname FROM recrutas WHERE status = 'aprovado' ORDER BY nickname ASC");
        res.json(rows);
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar membros.' }); }
});

app.get('/api/chat', isLoggedIn, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT nickname, message_text, timestamp FROM chat_messages ORDER BY timestamp ASC LIMIT 50');
        res.json(rows);
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar mensagens.' }); }
});

app.post('/api/chat', isLoggedIn, async (req, res) => {
    const { message } = req.body;
    const { userId, nickname } = req.session;
    if (!message || message.trim() === '') { return res.status(400).json({ error: 'Mensagem vazia.' }); }
    try {
        await db.query('INSERT INTO chat_messages (recruta_id, nickname, message_text) VALUES (?, ?, ?)', [userId, nickname, message]);
        res.status(201).json({ success: true });
    } catch (error) { res.status(500).json({ error: 'Erro ao salvar mensagem.' }); }
});

// APIs de Administração
app.get('/api/admin/recrutas-pendentes', isLoggedIn, isAdmin, async (req, res) => {
    try {
        const [rows] = await db.query("SELECT id, nickname, email, game_id, data_registro FROM recrutas WHERE status = 'pendente' ORDER BY data_registro ASC");
        res.json(rows);
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar recrutas pendentes.' }); }
});

app.post('/api/admin/aprovar/:id', isLoggedIn, isAdmin, async (req, res) => {
    try {
        await db.query("UPDATE recrutas SET status = 'aprovado' WHERE id = ?", [req.params.id]);
        res.json({ success: true, message: `Recruta #${req.params.id} aprovado!` });
    } catch (error) { res.status(500).json({ success: false, message: 'Erro ao aprovar recruta.' }); }
});

app.post('/api/admin/rejeitar/:id', isLoggedIn, isAdmin, async (req, res) => {
    try {
        await db.query("DELETE FROM recrutas WHERE id = ?", [req.params.id]);
        res.json({ success: true, message: `Recruta #${req.params.id} rejeitado e removido.` });
    } catch (error) { res.status(500).json({ success: false, message: 'Erro ao rejeitar recruta.' }); }
});

// 8. INICIAR O SERVIDOR
app.listen(port, () => {
    console.log(`Servidor local da Facção China rodando em http://localhost:${port}`);
});