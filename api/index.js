require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const streamifier = require('streamifier');
const cloudinary = require('./config/cloudinary');
const { db } = require('./config/firebase');
const autenticarToken = require('./middlewares/autenticarToken');

const app = express();
app.use(express.json());
// const corsOptions = {
//   origin: '*',
//   methods: ['GET','POST','PUT','DELETE'],
//   allowedHeaders: ['Content-Type', 'Authorization']
// };
// app.use(cors(corsOptions));

// ✅ Configura o multer para armazenar em memória (compatível com Vercel)
const upload = multer({ storage: multer.memoryStorage() });

// Função auxiliar para enviar buffer ao Cloudinary
async function uploadToCloudinary(buffer) {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: 'doacoes' },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    streamifier.createReadStream(buffer).pipe(uploadStream);
  });
}
//ok
// ✅ Cadastro de usuário
app.post('/signup', async (req, res) => {
  const { cargo, nome, email, telefone, identidade, endereco, cidade, estado, cep, senha } = req.body;

  if (!cargo || !nome || !email || !telefone || !identidade || !endereco || !cidade || !estado || !cep || !senha)
    return res.status(400).json({ message: 'Todos os campos são obrigatórios' });

  try {
    const userRef = db.collection('users');
    const snapshot = await userRef.where('email', '==', email).get();

    if (!snapshot.empty) return res.status(400).json({ message: 'Usuário já existe' });

    const hash = await bcrypt.hash(senha, 10);
    await userRef.add({
      cargo, nome, email, telefone, identidade, endereco, cidade, estado, cep,
      password_hash: hash,
      createdAt: new Date()
    });

    res.json({ message: 'Usuário cadastrado com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao cadastrar usuário' });
  }
});
//ok
// ✅ Login
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha)
    return res.status(400).json({ message: 'Email e senha são obrigatórios' });

  try {
    const snapshot = await db.collection('users').where('email', '==', email).get();
    if (snapshot.empty) return res.status(401).json({ message: 'Usuário não encontrado' });

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    const match = await bcrypt.compare(senha, user.password_hash);
    if (!match) return res.status(401).json({ message: 'Senha incorreta' });

    const token = jwt.sign({ id: userDoc.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login bem-sucedido', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro no servidor' });
  }
});
//ok
// ✅ Atualizar perfil
app.put('/usuarios/:id', autenticarToken, async (req, res) => {
  const userId = req.params.id;
  const dados = req.body;

  try {
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) return res.status(404).json({ message: 'Usuário não encontrado' });

    if (dados.senha) {
      dados.password_hash = await bcrypt.hash(dados.senha, 10);
      delete dados.senha;
    }

    await userRef.update(dados);
    res.json({ message: 'Perfil atualizado com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao atualizar perfil' });
  }
});
//ok
// ✅ Cadastro de doação (com Cloudinary e memória)
app.post('/doacoes', autenticarToken, upload.single('foto'), async (req, res) => {
  const { titulo, descricao, categoria, localizacao, cidade, estado } = req.body;
  const usuario_id = req.user.id;

  if (!titulo || !descricao || !categoria || !localizacao || !cidade || !estado) {
    return res.status(400).json({ message: 'Todos os campos obrigatórios devem ser preenchidos (titulo, descricao, categoria, localizacao, cidade, estado)' });
  }

  try {
    let fotoUrl = null;
    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer);
      fotoUrl = result.secure_url;
    }

    await db.collection('doacoes').add({
      usuario_id,
      titulo,
      descricao,
      categoria,
      localizacao,
      cidade,
      estado,
      foto: fotoUrl,
      createdAt: new Date()
    });

    res.json({ message: 'Doação cadastrada com sucesso!' });
  } catch (error) {
    console.error('Erro no upload:', error);
    res.status(500).json({ message: 'Erro ao cadastrar doação' });
  }
});
//ok
// ✅ Histórico de doações
app.get('/api/doacoes/historico', autenticarToken, async (req, res) => {
  const usuario_id = req.user.id;

  try {
    const snapshot = await db.collection('doacoes')
      .where('usuario_id', '==', usuario_id)
      .orderBy('createdAt', 'desc')
      .get();

    const doacoes = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(doacoes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao buscar histórico de doações' });
  }
});
//ok
// ✅ Excluir doação
app.delete('/doacoes/:id', autenticarToken, async (req, res) => {
  const doacaoId = req.params.id;
  const usuario_id = req.user.id;

  try {
    const doacaoRef = db.collection('doacoes').doc(doacaoId);
    const doc = await doacaoRef.get();

    if (!doc.exists) {
      return res.status(404).json({ message: 'Doação não encontrada' });
    }

    const doacao = doc.data();
    if (doacao.usuario_id !== usuario_id) {
      return res.status(403).json({ message: 'Você não tem permissão para excluir esta doação' });
    }

    await doacaoRef.delete();
    res.json({ message: 'Doação excluída com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao excluir doação' });
  }
});
//ok
// ✅ Editar doação
app.put('/doacoes/:id', autenticarToken, upload.single('foto'), async (req, res) => {
  const doacaoId = req.params.id;
  const usuario_id = req.user.id;
  const { titulo, descricao, categoria, localizacao, cidade, estado } = req.body;

  try {
    const doacaoRef = db.collection('doacoes').doc(doacaoId);
    const doc = await doacaoRef.get();

    if (!doc.exists) {
      return res.status(404).json({ message: 'Doação não encontrada' });
    }

    const doacao = doc.data();
    if (doacao.usuario_id !== usuario_id) {
      return res.status(403).json({ message: 'Você não tem permissão para editar esta doação' });
    }

    // Mantém os valores atuais caso não sejam enviados no body
    const novoCidade = (typeof cidade !== 'undefined' && cidade !== null) ? cidade : doacao.cidade || null;
    const novoEstado = (typeof estado !== 'undefined' && estado !== null) ? estado : doacao.estado || null;

    let fotoUrl = doacao.foto;
    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer);
      fotoUrl = result.secure_url;
    }

    await doacaoRef.update({
      // atualiza apenas os campos que vieram — se quiser evitar sobrescrever com undefined, faz assim:
      ...(typeof titulo !== 'undefined' && { titulo }),
      ...(typeof descricao !== 'undefined' && { descricao }),
      ...(typeof categoria !== 'undefined' && { categoria }),
      ...(typeof localizacao !== 'undefined' && { localizacao }),
      cidade: novoCidade,
      estado: novoEstado,
      foto: fotoUrl,
      updatedAt: new Date()
    });

    res.json({ message: 'Doação atualizada com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao atualizar doação' });
  }
});
//ok
// 📌 Solicitar uma doação
app.post('/solicitacoes', autenticarToken, async (req, res) => {
  const { doacao_id, motivo } = req.body;
  const usuario_id = req.user.id;

  if (!doacao_id || !motivo) {
    return res.status(400).json({ message: 'Doação e motivo são obrigatórios' });
  }

  try {
    const doacaoRef = db.collection('doacoes').doc(doacao_id);
    const doc = await doacaoRef.get();

    if (!doc.exists) {
      return res.status(404).json({ message: 'Doação não encontrada' });
    }

    // salva solicitação
    await db.collection('solicitacoes').add({
      doacao_id,
      receptor_id: usuario_id,
      motivo,
      status: 'pendente',
      createdAt: new Date()
    });

    res.json({ message: 'Solicitação enviada com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao solicitar doação' });
  }
});
//ok
// 📌 Histórico de solicitações do receptor
app.get('/solicitacoes/historico', autenticarToken, async (req, res) => {
  const usuario_id = req.user.id;

  try {
    const snapshot = await db.collection('solicitacoes')
      .where('receptor_id', '==', usuario_id)
      .orderBy('createdAt', 'desc')
      .get();

    const solicitacoes = [];

    for (const doc of snapshot.docs) {
      const data = doc.data();

      // busca dados da doação referenciada
      const doacaoDoc = await db.collection('doacoes').doc(data.doacao_id).get();

      solicitacoes.push({
        id: doc.id,
        ...data,
        doacao: doacaoDoc.exists ? doacaoDoc.data() : null
      });
    }

    res.json(solicitacoes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao buscar histórico de solicitações' });
  }
});
//ok
// 📌 Listar todas as doações disponíveis
app.get('/doacoes', autenticarToken, async (req, res) => {
  const usuario_id = req.user.id;

  try {
    const snapshot = await db.collection('doacoes')
      .orderBy('createdAt', 'desc')
      .get();

    const doacoes = snapshot.docs
      .filter(doc => doc.data().usuario_id !== usuario_id)
      .map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

    res.json(doacoes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao buscar doações disponíveis' });
  }
});
//ok
// 📌 Filtrar e ordenar doações
app.get('/doacoes/filtrar', autenticarToken, async (req, res) => {
  const { categoria, cidade, estado, ordenar } = req.query;
  const usuario_id = req.user.id;

  try {
    let query = db.collection('doacoes');

    if (categoria) query = query.where('categoria', '==', categoria);
    if (cidade) query = query.where('cidade', '==', cidade);
    if (estado) query = query.where('estado', '==', estado);


    const snapshot = await query.get();

    let doacoes = snapshot.docs
      .filter(doc => doc.data().usuario_id !== usuario_id)
      .map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

    // Ordenação
    if (ordenar === 'recente') {
      doacoes.sort((a, b) => b.createdAt.toDate() - a.createdAt.toDate());
    } else if (ordenar === 'antiga') {
      doacoes.sort((a, b) => a.createdAt.toDate() - b.createdAt.toDate());
    }

    res.json(doacoes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erro ao filtrar doações' });
  }
});



// ✅ Inicialização do servidor (local ou Vercel)
app.listen(process.env.PORT || 3000, () => {
  console.log(`🚀 Servidor rodando na porta ${process.env.PORT || 3000}`);
});

// module.exports = app; // obrigatório para Vercel
