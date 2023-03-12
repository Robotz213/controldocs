from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_mail import Mail, Message
from hashlib import sha256
import mysql.connector
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
import random
import string
from werkzeug.security import generate_password_hash



app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'

# Configurações de conexão com o banco de dados
app.config['MYSQL_HOST'] = 'xmysql1.proexpress.com.br'
app.config['MYSQL_USER'] = 'proexpress1'
app.config['MYSQL_PASSWORD'] = 'FormularioPRO2013@'
app.config['MYSQL_DB'] = 'proexpress1'

mysql = MySQL(app)

# Configurações de envio de e-mails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'seu_email'
app.config['MAIL_PASSWORD'] = 'sua_senha'

mail = Mail(app)

app.permanent_session_lifetime = timedelta(seconds=60)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        hashed_password = sha256(password.encode()).hexdigest()
        

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE user = %s", [login])

        if result > 0:
            data = cur.fetchone()
            db_password = data[2]

            if hashed_password in db_password:
                session['logged_in'] = True
                session['login'] = login
                session['login_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # registra data e hora do login

                # atualiza a coluna login_time na tabela users com a hora de login
                cur.execute("UPDATE users SET login_time = %s WHERE user = %s", [session['login_time'], login])
                mysql.connection.commit()

                flash('Você está logado', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Senha incorreta'
                return render_template('login.html', error=error)
            cur.close()
        else:
            error = 'Usuário não encontrado'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])

        if result > 0:
            data = cur.fetchone()
            user_id = data[1]
            verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

            cur.execute("UPDATE users SET verification_code = %s WHERE user = %s", [verification_code, user_id])
            mysql.connection.commit()

            msg = Message('Redefinir senha', sender='seu_email', recipients=[email])
            msg.body = f"Seu código de verificação é: {verification_code}\n\nInsira este código na página de redefinição de senha para continuar."
            mail.send(msg)

            flash('Um e-mail foi enviado para redefinir a senha.', 'success')
            session['reset_code'] = verification_code  # armazena o código de verificação na sessão
            return redirect(url_for('verify_code'))
        else:
            error = 'Usuário não encontrado'
            return render_template('forgot_password.html', error=error)

    return render_template('forgot_password.html')

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    if 'reset_code' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        code = request.form['code']
        if code == session['reset_code']:
            session['reset_verified'] = True
            return redirect(url_for('change_password'))
        else:
            error = 'Código inválido'
            return render_template('verify_code.html', error=error)

    return render_template('verify_code.html')

@app.route('/redefinir-senha', methods=['GET', 'POST'])
def redefinir_senha():
    if 'reset_verified' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            error = 'As senhas não correspondem'
            return render_template('redefinir_senha.html', error=error)

        if len(password) < 8:
            error = 'A senha deve ter no mínimo 8 caracteres'
            return render_template('redefinir_senha.html', error=error)

        user_id = session['reset_user_id']
        hashed_password = (password)
        hashed_password = generate_password_hash(password)

        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET password = %s, verification_code = NULL WHERE id = %s", [hashed_password, user_id])
        mysql.connection.commit()

        flash('Sua senha foi atualizada com sucesso.', 'success')
        session.pop('reset_verified', None)
        session.pop('reset_user_id', None)
        session.pop('reset_code', None)
        return redirect(url_for('login'))

    return render_template('redefinir_senha.html')

def validar_login():
    if 'login' not in session:
        return redirect('/login')
    else:
        session.permanent = True
        return True
@app.route('/dashboard')
def dashboard():
    if not validar_login():
        return redirect('/login')
    return render_template('dashboard.html')

@app.route('/central-de-avisos')
def central_de_avisos():
    return "Central de avisos"

@app.route('/central-de-documentos')
def central_de_documentos():
    

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT tipo_de_arquivo, data_de_inclusao, link_para_download FROM files WHERE usuario = %s", (session['login'],))
    resultados = cursor.fetchall()

    return render_template('central-de-documentos.html', resultados=resultados)


# @app.route('/dashboard')
# def dashboard():
#     # Verifica se o usuário está logado
#     if 'logged_in' in session:
#         # Obtém o timestamp da última atividade
#         last_activity = session.get('last_activity', time.time())

#         # Verifica se a última atividade foi há mais de 60 segundos
#         if time.time() - last_activity > 60:
#             # Remove a sessão e redireciona para a página de login
#             session.clear()
#             flash('Sessão expirada por inatividade')
#             return redirect(url_for('login'))

#         # Atualiza o timestamp da última atividade
#         session['last_activity'] = time.time()

#         # Obtém os arquivos do banco de dados
#         cur = mysql.connection.cursor()
#         cur.execute("SELECT tipo_de_arquivo, data_de_inclusao, link_para_download FROM files WHERE usuario = %s", (session['login'],))
#         result = cur.fetchall()

#         if result == 0:
#             msg = 'Nenhum arquivo encontrado'
#             return render_template('dashboard.html', msg=msg)
#         else:
#             resultados = cur.fetchall()
#             cur.close()
#             return render_template('dashboard.html', resultados=resultados)
#     else:
#         return redirect(url_for('login'))
    
@app.route('/logout')
def logout():
# Remove a sessão do usuário
    session.clear()
    flash('Você saiu', 'success')
    return redirect(url_for('login'))



#Execução

app.run(host='0.0.0.0', port='80',debug=True)

