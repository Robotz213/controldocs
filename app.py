from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'

app.config['MYSQL_HOST'] = 'seu_host_mysql'
app.config['MYSQL_USER'] = 'seu_usuario_mysql'
app.config['MYSQL_PASSWORD'] = 'sua_senha_mysql'
app.config['MYSQL_DB'] = 'seu_banco_de_dados_mysql'

mysql = MySQL(app)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])

        if result > 0:
            data = cur.fetchone()
            db_password = data['password']

            if sha256_crypt.verify(password, db_password):
                session['logged_in'] = True
                session['email'] = email
                session['login_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # registra data e hora do login

                # atualiza a coluna login_time na tabela users com a hora de login
                cur.execute("UPDATE users SET login_time = %s WHERE email = %s", [session['login_time'], email])
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




@app.route('/dashboard')
def dashboard():
    # Verifica se o usuário está logado
    if 'logged_in' in session:
    # Obtém os arquivos do banco de dados
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM files")

        if result > 0:
            data = cur.fetchall()
            return render_template('dashboard.html', files=data)
        else:
            msg = 'Nenhum arquivo encontrado'
            return render_template('dashboard.html', msg=msg)

            cur.close()
    else:
        return redirect(url_for('login'))
    
@app.route('/logout')
def logout():
# Remove a sessão do usuário
    session.clear()
    flash('Você saiu', 'success')
    return redirect(url_for('login'))

#Execução

app.run(host='0.0.0.0',
        debug=True
        )

