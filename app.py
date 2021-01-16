from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
from werkzeug.security import generate_password_hash,check_password_hash
import datetime
from functools import wraps

app=Flask(__name__)

app.config['SECRET_KEY']='<some_secret_key>'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///todo.db'

db=SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    
    first_name=db.Column(db.String(50))
    last_name=db.Column(db.String(50))
    charlie=db.Column(db.Integer)
    
    name=db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)
    
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        if not token:
            return jsonify({'message':'Token is missing. Authorization required.'}),401
        try:
            data=jwt.decode(token,app.config['SECRET_KEY'],algorithms='HS256')
            print(data)
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'Token is invalid ! Authorization is required'}),401
        return f(current_user,*args,**kwargs)
    return decorated

@app.route('/user/all_users',methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message':'You are not authorized to perform that function'})
    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data['public_id']=user.public_id
        user_data['name']=user.name
        user_data['password']=user.password
        user_data['admin']=user.admin
        user_data['first-name']=user.first_name
        user_data['last-name']=user.last_name
        user_data['charlies']=user.charlie
        output.append(user_data)
    return jsonify({'users':output})

@app.route('/user/details/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'You are not authorized to perform that function'})
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found'})
    user_data={}
    user_data['public_id']=user.public_id
    user_data['name']=user.name
    user_data['password']=user.password
    user_data['admin']=user.admin
    user_data['first-name']=user.first_name
    user_data['last-name']=user.last_name
    user_data['charlies']=user.charlie
    return jsonify({'user':user_data})

@app.route('/user/create',methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'You are not authorized to perform that function'})
    data=request.get_json()
    hashed_password=generate_password_hash(data['password'],method='sha256')
    new_user=User(public_id=str(uuid.uuid4()),name=data['name'],password=hashed_password,admin=False,first_name=data['first-name'],last_name=data['last-name'],charlie=data['charlies'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created !'})

@app.route('/user/promote/<public_id>',methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'You are not authorized to perform that function'})
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found'})
    user.admin=True
    db.session.commit()
    return jsonify({'message':'The user has been promoted'})

@app.route('/user/demote/<public_id>',methods=['PUT'])
@token_required
def demote_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'You are not authorized to perform that function'})
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found'})
    user.admin=False
    db.session.commit()
    return jsonify({'message':'The user has been promoted'})

@app.route('/user/update_charlie/<public_id>/<int:charlie_update>',methods=['PUT','GET'])
@token_required
def charlie_update(current_user,charlie_update,public_id):
    if not current_user.admin:
        return jsonify({'message':'You are not authorized to perform that function'})
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found'})
    data=request.get_json()
    user.charlie=charlie_update
    db.session.commit()
    return jsonify({'message':'Yay ! Charlies updated !'})

@app.route('/user/delete/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'You are not authorized to perform that function'})
    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message':'The user has been deleted'})

@app.route('/user/login')
def login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic-realm="Login Required !"'})
    user=User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic-realm="Login Required !"'})
    if check_password_hash(user.password,auth.password):
        token=jwt.encode({'public_id':user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=36500)},app.config['SECRET_KEY'])
        return jsonify({'token':token})
    return make_response('Could not verify',401,{'WWW-Authenticate':'Basic-realm="Login Required !"'})
    
if __name__ == '__main__':
    app.run(debug=True)
    