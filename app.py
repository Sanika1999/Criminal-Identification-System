from flask import Flask, render_template,flash,redirect,url_for,session,logging,request
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps
app=Flask(__name__)

#config mysql
app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']='9711'
app.config['MYSQL_DB']='criminal_identification_system'
app.config['MYSQL_CURSORCLASS']='DictCursor'
#init mysql
mysql=MySQL(app)

app.debug=True
@app.route('/')
def index():
    return render_template('home.html')
@app.route('/system')

def system():
    return render_template('system.html')
#Registration 
class RegisterForm(Form):
    name=StringField('Name', [validators.Length(min=1, max=100)])
    username=StringField('Username',[validators.Length(min=3,max=30)])
    email=StringField('Email',[validators.Length(min=6,max=50)])
    password=PasswordField('Password',[
        validators.DataRequired(),
        validators.EqualTo('confirm',message='Passwords do not match'),
    ])
    confirm=PasswordField('Confirm Password')
@app.route('/register',methods=['GET','POST'])
def register():

    form=RegisterForm(request.form)
    if request.method=='POST' and form.validate():
        name=form.name.data
        email=form.email.data
        username=form.username.data
        password=sha256_crypt.encrypt(str(form.password.data))
        #create cursor
        cur=mysql.connection.cursor()
        #execute query
        cur.execute("INSERT INTO users(name,email,username,password) VALUES(%s, %s, %s, %s)",(name,email,username,password))
        #commit to db
        mysql.connection.commit()
        #close connection
        cur.close()
        flash('You are now registered and can login','success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)
#Login
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        #Get form fields
        username = request.form['username']
        password_candidate=request.form['password']
        #create cursor 
        cur=mysql.connection.cursor()
        #get user by username
        result=cur.execute("SELECT * FROM users WHERE username = %s", [username])
        if result > 0:
            #get stored hash
            data=cur.fetchone()
            password=data['password']

            #compare passwords
            if sha256_crypt.verify(password_candidate,password):
                app.logger.info('PASSWORRD MATCHED')
                session['logged_in']=True
                session['username']=username
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))


                
            else:
                app.logger.info('PASSWORRD NOT MATCHED')
                error='Username/Password is invalid'
                return render_template('login.html',error=error)
            cur.close()
        else:
            app.logger.info('NO USER')
            error='Username not found'
            return render_template('login.html',error=error)    
    return render_template('login.html') 
#check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash('Unauthorized, Please Login', 'danger')
            return redirect(url_for('login'))
    return wrap

#logout
@app.route('/logout')


def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('index'))
#dashboard

@app.route('/dashboard')
#@is_logged_in
def dashboard():
    return render_template('dashboard.html')



if __name__=='__main__':
    app.secret_key='1234'
    app.run()