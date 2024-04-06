from flask import Flask, render_template, request,redirect
from flask_mysqldb import MySQL
import mysql.connector
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import fun


# Générer une paire de clés RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)


public_key = private_key.public_key()

# Sérialiser la clé publique
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)



app = Flask(__name__)


# Configuration de la base de données MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="signature_numerique"
)
# Modèle de données pour une table de la base de données
#class User:
   # def __init__(self, id, username, email):
        #self.id = id
        #self.username = username
        #self.email = email
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/newcompte',methods=['POST'] )
def new_user():
    nom = request.form['nom']
    postnom = request.form['postnom']
    username=request.form['username']
    password= request.form['password']
    cur = db.cursor()
    sql=("INSERT INTO utilisateur(nom, postnom, username, password) VALUES (%s,%s,%s,%s)" )
    cur.execute(sql,(nom,postnom,username,password,))
    db.commit() 
    print("votre username est ",username," votre password est",password )    
    return redirect('/')


@app.route('/users')
def get_users():
    cur = db.cursor()
    cur.execute("SELECT * FROM utilisateur")
    data = cur.fetchall()
    #users = [utilisateur(nom, postnom, username, password) for nom, postnom, username, password in data]
    cur.close()
    return render_template('listeutilisateur.html', users=data)

@app.route('/index')
def index():
    cursor = db.cursor()
    cursor.execute("SELECT * FROM message")
    elements = cursor.fetchall()
    return render_template('liste_message.html', element=elements)


@app.route('/login',methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    cur = db.cursor()
    cur.execute("SELECT * FROM utilisateur WHERE username = %s AND password = %s", (username, password))
    user = cur.fetchone()
    
    if user:
        
        cur.execute("SELECT * FROM message")
        elements = cur.fetchall()
        
        return render_template('liste_message.html', element=elements)

    else:
        return redirect('/')

@app.route('/savemessage',methods=['POST'])
def savemessages():
   
    cur = db.cursor()
    message = request.form['message']
    date=request.form['date_envoie']
    signe=fun.signer (message,private_key)
    if(fun.verifier(message, signe, public_key)):
        
        sql=("INSERT INTO message(contenue, date_envoie, signature) VALUES (%s,%s,%s)" )
        cur.execute(sql,(message,date,signe,))
        db.commit()
        return redirect('/index')

    else:
        return"la signature n'est pas valide"

@app.route('/appel', methods=['GET'])
def appel():
    return render_template('message.html')    

@app.route('/creer_compte', methods=['GET'])
def compte():
    return render_template('new_user.html')     



if __name__ == '__main__':
    app.run(debug=True)
