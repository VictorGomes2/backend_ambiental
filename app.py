# =======================================================================
# CM REURB v2.3 - Backend Flask Adaptado para Deploy (Render)
# =======================================================================
# VERSÃO COMPLETA: Funcionalidades originais preservadas com as
# adaptações essenciais para rodar em serviços de nuvem como o Render.
# =======================================================================

import os
import datetime
from functools import wraps
import jwt  # PyJWT
import io # Necessário para a função de exportar

import pandas as pd
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =======================================================================
# ⚙️ CONFIGURAÇÃO DA APLICAÇÃO
# =======================================================================

app = Flask(__name__)

# 🔹 CORS configurado para aceitar requisições de qualquer origem.
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# 🔹 Carregando variáveis de ambiente (essencial para o Render)
SECRET_KEY = os.environ.get('SECRET_KEY', 'uma-chave-secreta-forte-para-desenvolvimento')
DATABASE_URI = os.environ.get('DATABASE_URL')

if DATABASE_URI and DATABASE_URI.startswith("postgres://"):
    DATABASE_URI = DATABASE_URI.replace("postgres://", "postgresql://", 1)

if not DATABASE_URI:
    DATABASE_URI = 'postgresql://reurb_user:D0O9OAg8B0921t0C9RHhk42Ft9noVGXr@dpg-d39l3q0dl3ps73aavla0-a.oregon-postgres.render.com/reurb_apk_zr6m'
    print("AVISO: Usando banco de dados de produção para desenvolvimento local.")


UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =======================================================================
# MODELS (TODAS AS FUNCIONALIDADES ORIGINAIS MANTIDAS)
# =======================================================================

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    senha_hash = db.Column(db.String(1024), nullable=False)
    acesso = db.Column(db.String(20), nullable=False, default='Usuario')

    def __init__(self, nome, usuario, senha, acesso='Usuario'):
        self.nome = nome
        self.usuario = usuario
        self.senha_hash = generate_password_hash(senha, method="scrypt")
        self.acesso = acesso

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)


class CadastroReurb(db.Model):
    __tablename__ = 'cadastros_reurb'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), default='Em Análise')
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    req_nome = db.Column(db.String(150))
    req_cpf = db.Column(db.String(20))
    req_rg = db.Column(db.String(20))
    req_data_nasc = db.Column(db.String(20))
    req_nacionalidade = db.Column(db.String(50))
    req_estado_civil = db.Column(db.String(30))
    conj_nome = db.Column(db.String(150))
    conj_cpf = db.Column(db.String(20))
    req_profissao = db.Column(db.String(100))
    req_telefone = db.Column(db.String(30))
    req_email = db.Column(db.String(150))
    imovel_cep = db.Column(db.String(15))
    imovel_logradouro = db.Column(db.String(150))
    imovel_numero = db.Column(db.String(20))
    imovel_complemento = db.Column(db.String(100))
    imovel_bairro = db.Column(db.String(100))
    imovel_cidade = db.Column(db.String(100))
    imovel_uf = db.Column(db.String(2))
    inscricao_imobiliaria = db.Column(db.String(30), index=True)
    imovel_area_total = db.Column(db.Float)
    imovel_area_construida = db.Column(db.Float)
    imovel_uso = db.Column(db.String(30))
    imovel_tipo_construcao = db.Column(db.String(30))
    reurb_renda_familiar = db.Column(db.Float)
    reurb_outro_imovel = db.Column(db.String(10))
    imovel_infra_agua = db.Column(db.String(10))
    imovel_infra_esgoto = db.Column(db.String(10))
    imovel_infra_iluminacao = db.Column(db.String(10))
    imovel_infra_pavimentacao = db.Column(db.String(10))
    imovel_infra_lixo = db.Column(db.String(10))
    reurb_cadunico = db.Column(db.String(10))
    
    # =================================================================
    # NOVOS CAMPOS ADICIONADOS - INÍCIO
    # =================================================================
    risco_inundacao = db.Column(db.String(10), nullable=True)
    grau_area_risco = db.Column(db.String(50), nullable=True)
    motivo_risco = db.Column(db.Text, nullable=True)
    sensacao_termica = db.Column(db.String(50), nullable=True)
    risco_deslizamento = db.Column(db.String(10), nullable=True)
    ventilacao_natural = db.Column(db.String(50), nullable=True)
    poluicao_sonora = db.Column(db.String(20), nullable=True)
    # =================================================================
    # NOVOS CAMPOS ADICIONADOS - FIM
    # =================================================================


class Documento(db.Model):
    __tablename__ = 'documentos'
    id = db.Column(db.Integer, primary_key=True)
    cadastro_id = db.Column(db.Integer, db.ForeignKey('cadastros_reurb.id'), nullable=False)
    nome_arquivo = db.Column(db.String(255), nullable=False)
    path_arquivo = db.Column(db.String(512), nullable=False)
    tipo_documento = db.Column(db.String(100))
    data_upload = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    cadastro = db.relationship("CadastroReurb", backref=db.backref("documentos", lazy=True, cascade="all, delete-orphan"))


class PadraoConstrutivo(db.Model):
    __tablename__ = 'padroes_construtivos'
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(150), nullable=False)
    valor_m2 = db.Column(db.Float, nullable=False)


class ValorLogradouro(db.Model):
    __tablename__ = 'valores_logradouro'
    id = db.Column(db.Integer, primary_key=True)
    logradouro = db.Column(db.String(150), unique=True, nullable=False)
    valor_m2 = db.Column(db.Float, nullable=False)


class AliquotaIPTU(db.Model):
    __tablename__ = 'aliquotas_iptu'
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(150), unique=True, nullable=False)
    aliquota = db.Column(db.Float, nullable=False)

# =======================================================================
# SERVIÇOS E UTILIDADES (FUNCIONALIDADES ORIGINAIS MANTIDAS)
# =======================================================================

class CalculoTributarioService:
    @staticmethod
    def calcular_valores(cadastro: CadastroReurb):
        vvt, vvc, vvi, iptu = 0.0, 0.0, 0.0, 0.0
        try:
            area_total = float(cadastro.imovel_area_total or 0.0)
            area_construida = float(cadastro.imovel_area_construida or 0.0)

            if cadastro.imovel_logradouro and area_total > 0:
                logradouro = ValorLogradouro.query.filter_by(logradouro=cadastro.imovel_logradouro).first()
                if logradouro:
                    vvt = area_total * logradouro.valor_m2
            if cadastro.imovel_tipo_construcao and area_construida > 0:
                padrao = PadraoConstrutivo.query.filter_by(descricao=cadastro.imovel_tipo_construcao).first()
                if padrao:
                    vvc = area_construida * padrao.valor_m2
            vvi = vvt + vvc
            if cadastro.imovel_uso:
                aliquota_data = AliquotaIPTU.query.filter_by(tipo=cadastro.imovel_uso).first()
                if aliquota_data:
                    iptu = vvi * aliquota_data.aliquota
        except Exception as e:
            print(f"Erro no cálculo: {e}")
        return {"vvt": vvt, "vvc": vvc, "vvi": vvi, "iptu": iptu}

# =======================================================================
# DECORADORES (FUNCIONALIDADES ORIGINAIS MANTIDAS)
# =======================================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return jsonify({'status': 'ok'}), 200
        token = None
        if 'Authorization' in request.headers:
            try:
                auth_header = request.headers['Authorization']
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'mensagem': 'Token inválido!'}), 401
        if not token:
            return jsonify({'mensagem': 'Token de autenticação ausente!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.filter_by(id=data['public_id']).first()
            if not current_user:
                 return jsonify({'mensagem': 'Usuário do token não encontrado!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'mensagem': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensagem': 'Token inválido!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.acesso != 'Administrador':
            return jsonify({'mensagem': 'Permissão de administrador necessária.'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


# =======================================================================
# ROTAS DA API (FUNCIONALIDADES ORIGINAIS MANTIDAS)
# =======================================================================

# ------------------- AUTENTICAÇÃO -------------------
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json()
    if not data or not data.get('usuario') or not data.get('senha'):
        return jsonify({'mensagem': 'Não foi possível verificar'}), 401
    user = Usuario.query.filter_by(usuario=data['usuario']).first()
    if not user:
        return jsonify({'mensagem': 'Usuário não encontrado.'}), 401
    if user.verificar_senha(data['senha']):
        token = jwt.encode({
            'public_id': user.id,
            'usuario': user.usuario,
            'acesso': user.acesso,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'mensagem': 'Login bem-sucedido!', 'token': token, 'nome_usuario': user.nome, 'acesso': user.acesso})
    return jsonify({'mensagem': 'Login ou senha incorretos.'}), 401

# ------------------- CADASTRO REURB -------------------
@app.route('/api/cadastrar_reurb', methods=['POST'])
@token_required
def cadastrar_reurb(current_user):
    data = request.get_json()
    try:
        novo_cadastro = CadastroReurb(
            req_nome=data.get('req_nome'), req_cpf=data.get('req_cpf'), req_rg=data.get('req_rg'),
            req_data_nasc=data.get('req_data_nasc'), req_nacionalidade=data.get('req_nacionalidade'),
            req_estado_civil=data.get('req_estado_civil'), conj_nome=data.get('conj_nome'),
            conj_cpf=data.get('conj_cpf'), req_profissao=data.get('req_profissao'),
            req_telefone=data.get('req_telefone'), req_email=data.get('req_email'),
            imovel_cep=data.get('imovel_cep'), imovel_logradouro=data.get('imovel_logradouro'),
            imovel_numero=data.get('imovel_numero'), imovel_complemento=data.get('imovel_complemento'),
            imovel_bairro=data.get('imovel_bairro'), imovel_cidade=data.get('imovel_cidade'),
            imovel_uf=data.get('imovel_uf'), inscricao_imobiliaria=data.get('inscricao_imobiliaria'),
            imovel_area_total=float(data.get('imovel_area_total') or 0),
            imovel_area_construida=float(data.get('imovel_area_construida') or 0),
            imovel_uso=data.get('imovel_uso'), imovel_tipo_construcao=data.get('imovel_tipo_construcao'),
            reurb_renda_familiar=float(data.get('reurb_renda_familiar') or 0),
            reurb_outro_imovel=data.get('reurb_outro_imovel'),
            imovel_infra_agua=data.get('imovel_infra_agua'),
            imovel_infra_esgoto=data.get('imovel_infra_esgoto'),
            imovel_infra_iluminacao=data.get('imovel_infra_iluminacao'),
            imovel_infra_pavimentacao=data.get('imovel_infra_pavimentacao'),
            imovel_infra_lixo=data.get('imovel_infra_lixo'),
            reurb_cadunico=data.get('reurb_cadunico'),
            # =================================================================
            # NOVOS CAMPOS ADICIONADOS - INÍCIO
            # =================================================================
            risco_inundacao=data.get('risco_inundacao'),
            grau_area_risco=data.get('grau_area_risco'),
            motivo_risco=data.get('motivo_risco'),
            sensacao_termica=data.get('sensacao_termica'),
            risco_deslizamento=data.get('risco_deslizamento'),
            ventilacao_natural=data.get('ventilacao_natural'),
            poluicao_sonora=data.get('poluicao_sonora')
            # =================================================================
            # NOVOS CAMPOS ADICIONADOS - FIM
            # =================================================================
        )
        db.session.add(novo_cadastro)
        db.session.commit()
        return jsonify({'mensagem': 'Cadastro REURB criado com sucesso!', 'id': novo_cadastro.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'mensagem': f'Erro ao criar cadastro: {str(e)}'}), 400

# =================================================================
# FUNÇÃO ATUALIZADA - INÍCIO
# =================================================================
@app.route('/api/cadastros', methods=['GET'])
@token_required
def get_cadastros(current_user):
    cadastros = CadastroReurb.query.order_by(CadastroReurb.id.desc()).all()
    output = []
    for c in cadastros:
        # 1. Converte dinamicamente o objeto do banco de dados em um dicionário.
        #    Isto garante que TODOS os campos da tabela 'CadastroReurb' sejam incluídos.
        cadastro_data = {col.name: getattr(c, col.name) for col in c.__table__.columns}

        # 2. Calcula os valores tributários e o tipo de REURB (mantendo a sua lógica original)
        valores = CalculoTributarioService.calcular_valores(c)
        
        tipo_reurb = 'REURB-E'
        renda_familiar = c.reurb_renda_familiar if c.reurb_renda_familiar is not None else 0
        outro_imovel = c.reurb_outro_imovel if c.reurb_outro_imovel is not None else ''

        if renda_familiar <= 7500 and outro_imovel.lower() == 'nao':
            tipo_reurb = 'REURB-S'

        # 3. Adiciona os campos calculados que não estão no banco de dados ao dicionário
        cadastro_data['tipo_reurb'] = tipo_reurb
        cadastro_data.update(valores)  # Adiciona 'vvt', 'vvc', 'vvi', 'iptu'

        # 4. Formata campos de data para o formato ISO (ideal para JSON)
        for key, value in cadastro_data.items():
            if isinstance(value, datetime.datetime):
                cadastro_data[key] = value.isoformat()

        output.append(cadastro_data)
        
    return jsonify({'cadastros': output})
# =================================================================
# FUNÇÃO ATUALIZADA - FIM
# =================================================================

@app.route('/api/cadastros_sinc', methods=['GET'])
@token_required
def get_cadastros_sinc(current_user):
    cadastros = CadastroReurb.query.order_by(CadastroReurb.req_nome).all()
    output = []
    for c in cadastros:
        cadastro_data = {col.name: getattr(c, col.name) for col in c.__table__.columns}
        if isinstance(cadastro_data.get('data_criacao'), datetime.datetime):
            cadastro_data['data_criacao'] = cadastro_data['data_criacao'].isoformat()
        if isinstance(cadastro_data.get('data_atualizacao'), datetime.datetime):
            cadastro_data['data_atualizacao'] = cadastro_data['data_atualizacao'].isoformat()
        output.append(cadastro_data)
    return jsonify({'cadastros': output})

@app.route('/api/cadastros/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@token_required
def gerenciar_cadastro_por_id(current_user, id):
    cadastro = CadastroReurb.query.get_or_404(id)
    
    if request.method == 'GET':
        docs = [{'id': d.id, 'nome_arquivo': d.nome_arquivo, 'tipo_documento': d.tipo_documento} for d in cadastro.documentos]
        cadastro_data = {key: getattr(cadastro, key) for key in CadastroReurb.__table__.columns.keys()}
        cadastro_data['documentos'] = docs
        cadastro_data['data_criacao'] = cadastro_data['data_criacao'].isoformat() if cadastro_data['data_criacao'] else None
        cadastro_data['data_atualizacao'] = cadastro_data['data_atualizacao'].isoformat() if cadastro_data['data_atualizacao'] else None
        return jsonify(cadastro_data)

    if request.method == 'PUT':
        data = request.get_json()
        for key, value in data.items():
            if hasattr(cadastro, key) and key != 'id':
                if key in ['imovel_area_total', 'imovel_area_construida', 'reurb_renda_familiar']:
                    try:
                        setattr(cadastro, key, float(value) if value else 0.0)
                    except (ValueError, TypeError):
                        setattr(cadastro, key, 0.0)
                else:
                    setattr(cadastro, key, value)
        db.session.commit()
        return jsonify({'mensagem': 'Cadastro atualizado com sucesso!'})

    if request.method == 'DELETE':
        db.session.delete(cadastro)
        db.session.commit()
        return jsonify({'mensagem': 'Cadastro deletado com sucesso!'})

# ------------------- GERENCIAMENTO DE USUÁRIOS (ADMIN) -------------------
@app.route('/api/usuarios', methods=['GET', 'POST'])
@token_required
@admin_required
def gerenciar_usuarios(current_user):
    if request.method == 'GET':
        usuarios = Usuario.query.all()
        output = [{'id': u.id, 'nome': u.nome, 'usuario': u.usuario, 'acesso': u.acesso} for u in usuarios]
        return jsonify({'usuarios': output})
    if request.method == 'POST':
        data = request.get_json()
        try:
            novo_usuario = Usuario(nome=data['nome'], usuario=data['usuario'], senha=data['senha'], acesso=data['acesso'])
            db.session.add(novo_usuario)
            db.session.commit()
            return jsonify({'mensagem': 'Usuário criado com sucesso!'}), 201
        except Exception as e:
            return jsonify({'mensagem': f'Erro ao criar usuário: {e}'}), 400

@app.route('/api/usuarios/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@token_required
@admin_required
def gerenciar_usuario_por_id(current_user, id):
    usuario = Usuario.query.get_or_404(id)
    if request.method == 'GET':
        return jsonify({'id': usuario.id, 'nome': usuario.nome, 'usuario': usuario.usuario, 'acesso': usuario.acesso})
    if request.method == 'PUT':
        data = request.get_json()
        usuario.nome = data.get('nome', usuario.nome)
        usuario.usuario = data.get('usuario', usuario.usuario)
        usuario.acesso = data.get('acesso', usuario.acesso)
        if 'senha' in data and data['senha']:
            usuario.senha_hash = generate_password_hash(data['senha'], method="scrypt")
        db.session.commit()
        return jsonify({'mensagem': 'Usuário atualizado com sucesso!'})
    if request.method == 'DELETE':
        db.session.delete(usuario)
        db.session.commit()
        return jsonify({'mensagem': 'Usuário deletado com sucesso!'})


# ------------------- PLANTA GENÉRICA DE VALORES -------------------
@app.route('/api/planta_generica/<tipo>', methods=['GET', 'POST'])
@token_required
def pgv_geral(current_user, tipo):
    model_map = {
        'padroes': PadraoConstrutivo,
        'logradouros': ValorLogradouro,
        'aliquotas': AliquotaIPTU
    }
    if tipo not in model_map:
        return jsonify({'erro': 'Tipo inválido'}), 404
    
    Model = model_map[tipo]

    if request.method == 'POST':
        if current_user.acesso != 'Administrador':
            return jsonify({'erro': 'Acesso negado'}), 403
        data = request.get_json()
        try:
            novo_item = Model(**data)
            db.session.add(novo_item)
            db.session.commit()
            return jsonify({'sucesso': True, 'mensagem': f'{tipo.capitalize()} adicionado(a) com sucesso!'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'erro': f'Erro ao adicionar: {str(e)}'}), 400
            
    items = Model.query.all()
    items_dict = [ {c.name: getattr(item, c.name) for c in item.__table__.columns} for item in items ]
    return jsonify(items_dict)

@app.route('/api/planta_generica/<tipo>/<int:id>', methods=['DELETE'])
@token_required
@admin_required
def delete_pgv_item(current_user, tipo, id):
    model_map = {
        'padroes': PadraoConstrutivo,
        'logradouros': ValorLogradouro,
        'aliquotas': AliquotaIPTU
    }
    if tipo not in model_map:
        return jsonify({'erro': 'Tipo inválido'}), 404

    Model = model_map[tipo]
    item = Model.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'sucesso': True, 'mensagem': 'Item deletado com sucesso!'})


# ------------------- CÁLCULO E IMPORTAÇÃO -------------------
@app.route('/api/gerar_iptu/<inscricao_imobiliaria>', methods=['GET'])
@token_required
def gerar_iptu(current_user, inscricao_imobiliaria):
    cadastro = CadastroReurb.query.filter_by(inscricao_imobiliaria=inscricao_imobiliaria).first_or_404()
    valores = CalculoTributarioService.calcular_valores(cadastro)
    return jsonify(valores)

@app.route('/api/importar', methods=['POST'])
@token_required
@admin_required
def importar_dados(current_user):
    if 'arquivo' not in request.files:
        return jsonify({'erro': 'Nenhum arquivo enviado'}), 400
    file = request.files['arquivo']
    if file.filename == '':
        return jsonify({'erro': 'Nome de arquivo vazio'}), 400
    if file:
        try:
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            else:
                df = pd.read_excel(file)
            
            column_mapping = {
                'Nome do Requerente': 'req_nome', 'CPF do Requerente': 'req_cpf',
                'Inscrição Imobiliária': 'inscricao_imobiliaria',
                'Área Total do Lote (m²)': 'imovel_area_total',
                'Área Construída (m²)': 'imovel_area_construida',
                'Renda Familiar (R$)': 'reurb_renda_familiar',
            }
            df.rename(columns=column_mapping, inplace=True)
            
            float_columns = ['imovel_area_total', 'imovel_area_construida', 'reurb_renda_familiar', 'latitude', 'longitude']

            for col in float_columns:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
            
            df = df.where(pd.notnull(df), None)

            for _, row in df.iterrows():
                valid_data = {k: v for k, v in row.to_dict().items() if k in CadastroReurb.__table__.columns.keys()}
                cadastro = CadastroReurb(**valid_data)
                db.session.add(cadastro)
            
            db.session.commit()
            return jsonify({'mensagem': 'Dados importados com sucesso!'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'erro': f'Erro ao importar dados: {e}'}), 500
    return jsonify({'erro': 'Tipo de arquivo não suportado'}), 400

@app.route('/api/exportar', methods=['POST'])
@token_required
def exportar_dados(current_user):
    try:
        data = request.get_json()
        colunas_solicitadas = data.get('colunas')

        if not colunas_solicitadas:
            return jsonify({'erro': 'Nenhuma coluna selecionada para exportação.'}), 400

        cadastros_query = CadastroReurb.query.all()
        
        cadastros_lista = []
        for cadastro in cadastros_query:
            cad_dict = {c.name: getattr(cadastro, c.name) for c in cadastro.__table__.columns}
            cadastros_lista.append(cad_dict)
            
        if not cadastros_lista:
            return jsonify({'erro': 'Não há dados para exportar.'}), 404

        df = pd.DataFrame(cadastros_lista)
        
        df_exportar = df[colunas_solicitadas]

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df_exportar.to_excel(writer, index=False, sheet_name='Cadastros')
        
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheet.sheet',
            as_attachment=True,
            download_name='cadastros_reurb.xlsx'
        )

    except Exception as e:
        return jsonify({'erro': f'Ocorreu um erro inesperado no servidor: {e}'}), 500

# ------------------- UPLOAD DE DOCUMENTOS -------------------
@app.route('/api/upload_documento/<int:id>', methods=['POST'])
@token_required
def upload_documento(current_user, id):
    cadastro = CadastroReurb.query.get_or_404(id)
    if 'file' not in request.files:
        return jsonify({'mensagem': 'Nenhum arquivo enviado'}), 400
    file = request.files['file']
    tipo_documento = request.form.get('tipo_documento', 'Não especificado')
    if file.filename == '':
        return jsonify({'mensagem': 'Nome de arquivo vazio'}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        novo_documento = Documento(
            cadastro_id=cadastro.id,
            nome_arquivo=filename,
            path_arquivo=filepath,
            tipo_documento=tipo_documento
        )
        db.session.add(novo_documento)
        db.session.commit()
        return jsonify({'mensagem': 'Documento enviado com sucesso!', 'nome_arquivo': filename}), 201

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# =======================================================================
# ROTA TEMPORÁRIA PARA CRIAR TABELAS E ADMINISTRADOR (NOVA)
# =======================================================================
@app.route('/setup')
def setup_database():
    try:
        with app.app_context():
            db.create_all()
            admin_existente = Usuario.query.filter_by(usuario="admin").first()
            if not admin_existente:
                admin_user = Usuario(
                    nome="Administrador",
                    usuario="admin",
                    senha="admin",
                    acesso="Administrador"
                )
                db.session.add(admin_user)
                db.session.commit()
                return "Banco de dados e usuário admin criados com sucesso! Login: admin / Senha: admin"
            else:
                return "Tabelas do banco de dados já criadas e usuário 'admin' já existe!"
    except Exception as e:
        return f"Erro ao configurar o banco de dados: {str(e)}"

# =======================================================================
# INICIALIZAÇÃO
# =======================================================================
if __name__ == '__main__':
    with app.app_context():
        print("Executando em modo de desenvolvimento local...")
    app.run(host='0.0.0.0', port=5000, debug=True)