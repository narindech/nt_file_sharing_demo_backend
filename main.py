from flask import Flask, jsonify, make_response, request, send_file
from flask_cors import CORS, cross_origin
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import mysql.connector as mysqlcon
from collections import namedtuple
import datetime

import uuid
import jwt
import math
import os


app = Flask(__name__)
cors = CORS(app)
# app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SECRET_KEY']='004f2af45d3a4e161a7dd2d17fdae47f'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
token_miniute_expire = 15 # 15 minute before expire
FILEDIR = "uploaded/"


def init_db(statement):
    try:
        return_list = []
        mydb = mysqlcon.connect(
            host='127.0.0.1',
            user='root',
            password='54010674Nong',
            database='filesharingdb'
        )
        mycursor = mydb.cursor()

        mycursor.execute(statement)
        return_list = [x for x in mycursor]
        mydb.commit()
        return return_list
    except:
        print("Error occurred during connecting to db.")
        return None

def namedtuplefetchall(cursor):
    "Return all rows from a cursor as a namedtuple"
    desc = cursor.description
    nt_result = namedtuple('Result', [col[0] for col in desc])
    return [nt_result(*row) for row in cursor.fetchall()]

def listfile():
    try:
        mydb = mysqlcon.connect(
            host='127.0.0.1',
            user='root',
            password='54010674Nong',
            database='filesharingdb'
        )
        mycursor = mydb.cursor()
        mycursor.execute("SELECT * FROM FileSharing")
        results = namedtuplefetchall(mycursor)
        mydb.commit()
        return results
    except:
        print("Error occurred during connecting to db.")
        return None


def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        print("show me headers ==>", request.headers)

        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
            if 'Basic' in token:
                splited_token = token.split()[1]
                token = splited_token.strip()
                # print("Authorization token ==>", token)

        if not token:
            return make_response(
                jsonify(
                    {"message": "a valid token is missing"}
                ), 401)
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            print("show me data --> ", data)
            mydb = mysqlcon.connect(
                host='127.0.0.1',
                user='root',
                password='54010674Nong',
                database='filesharingdb'
            )
            mycursor = mydb.cursor()

            mycursor.execute("SELECT * FROM UserCredentials WHERE public_id = %s", (data['public_id'],))
            current_user = namedtuplefetchall(mycursor)[0]
            print("current_user --> ", current_user)
            mydb.commit()
        except Exception as e:
            return make_response(
                jsonify(
                    {"message": "token is valid", "Error": f'{e}'}
                ), 401)
 
        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/')
@cross_origin()
def hello():
    return 'Hello, World!'


@app.route('/check_token', methods=['GET'])
@cross_origin()
@token_required
def check_valid_token(current_user):
    print("check_valid_token user --> ", current_user.user_name)
    return make_response(jsonify(
                    {"message": "token is valid", "user": current_user.user_name}
                ), 200)

@app.route('/register', methods=['POST'])
@cross_origin()
def signup_user():
    if request.method == 'POST':
        data = request.get_json() 
        hashed_password = generate_password_hash(data['password'], method='sha256')
    
        mydb = mysqlcon.connect(
                        host='127.0.0.1',
                        user='root',
                        password='54010674Nong',
                        database='filesharingdb'
                    )
        mycursor = mydb.cursor()
        mycursor.execute("SELECT EXISTS(SELECT user_name FROM UserCredentials WHERE user_name = %s) as OUTPUT", (data['username'],))
        result = namedtuplefetchall(mycursor)[0]
        if not result.OUTPUT:
            user_id = str(uuid.uuid4())
            mycursor.execute("INSERT INTO UserCredentials (public_id, user_name, user_password) VALUES (%s, %s, %s)", (user_id, data['username'], hashed_password,))
            mydb.commit()

            token = jwt.encode({'public_id' : user_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=token_miniute_expire)}, app.config['SECRET_KEY'], "HS256")
            return make_response(jsonify(
                        {"message": "registered successfully."}, {"user":str(data['username'])}, {"token": token}
                    ), 200)
        else:
            return make_response(jsonify(
                        {"message": "registered failed"}
                    ), 400)


@app.route('/login', methods=['POST'])
@cross_origin()
def login_user():
    auth = request.authorization
    print("show auth --> ", auth)
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'Authentication': 'login required"'})

    mydb = mysqlcon.connect(
            host='127.0.0.1',
            user='root',
            password='54010674Nong',
            database='filesharingdb'
        )
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM UserCredentials WHERE user_name = %s", (auth.username,))
    users = namedtuplefetchall(mycursor)[0]
    mydb.commit()

    if check_password_hash(users.user_password, auth.password):
        token = jwt.encode({'public_id' : users.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=token_miniute_expire)}, app.config['SECRET_KEY'], "HS256")
        return jsonify({'token' : token})

    return make_response('could not verify',  401, {'Authentication': '"login required"'})


@app.route('/users', methods=['GET'])
@cross_origin()
def get_all_users(): 
    # query all user id
    mydb = mysqlcon.connect(
            host='127.0.0.1',
            user='root',
            password='54010674Nong',
            database='filesharingdb'
        )
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM UserCredentials")
    users = namedtuplefetchall(mycursor)
    mydb.commit()

    result = []  
    for user in users:  
        user_data = {}  
        user_data['public_id'] = user.public_id 
        user_data['user_name'] = user.user_name
        user_data['user_password'] = user.user_password
        user_data['first_name'] = user.first_name
        user_data['last_name'] = user.last_name
        result.append(user_data)  
    return jsonify({'users': result})


@app.route('/files', methods=['GET'])
@cross_origin()
def get_files():
    files = listfile()
    print("show me return_list --> ", files)
    return_files = [{
        "item_id": file.item_id,
        "filename": file.filename,
        "filetype": file.filetype,
        "filesize": file.filesize,
        "filepath": file.filepath,
        "uploadTime": file.upload_time,
        "editTime": file.edit_time,
        "uploader": file.uploader,
        "editor": file.editor
    }for file in files]
    return {
        "status" : "success",
        "status_code": 200,
        "description" : f"Succesfully called.",
        "content": return_files
    }


@app.route('/download/<path:filename>', methods=['GET'])
@cross_origin()
def download_file(filename):
    # Appending app path to upload folder path within app root folder
    mydb = mysqlcon.connect(
            host='127.0.0.1',
            user='root',
            password='54010674Nong',
            database='filesharingdb'
        )
    mycursor = mydb.cursor()
    mycursor.execute(f"SELECT filePath FROM FileSharing WHERE filename = '{filename}'")
    try:
        filepath = mycursor.fetchall()[0][0]
        mydb.commit()
        return send_file(filepath)
    except:
        return make_response('download error', 400, {'error': "no file existed."})
 

@app.route('/uploader', methods = ['GET', 'POST'])
@cross_origin()
@token_required
def upload_file(current_user):
    if request.method == 'POST':
        try:
            f = request.files['avatar']
            
            my_filename = f.filename
            mimetype = f.content_type

            contents = f.read()
            filesize = convert_size(len(contents))
            filepath = f"{FILEDIR}{f.filename}"
            with open(filepath, "wb") as f:
                f.write(contents)

            mydb = mysqlcon.connect(
                host='127.0.0.1',
                user='root',
                password='54010674Nong',
                database='filesharingdb'
            )
            mycursor = mydb.cursor()
            upload_time = datetime.datetime.utcnow()
            edit_time = upload_time
            uploader = current_user.user_name
            editor = uploader
            sql_statement = "INSERT INTO FileSharing (filename, filetype, filesize, filepath, upload_time, edit_time, uploader, editor) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);"
            sql_param = (my_filename, mimetype, filesize, filepath, upload_time, edit_time, uploader, editor)
            mycursor.execute(sql_statement, sql_param)
            mydb.commit()
            
            return make_response('successful', 200, {'message': 'file upload sucessfully'})

        except Exception as e:
            print(f"error occured : {e}")
            return make_response('upload error', 500, {'error': f"internal server error : {e}"})


@app.route('/delete/<path:item_id>', methods = ['DELETE'])
@cross_origin()
@token_required
def delete_file(current_user, item_id):
    print("delete file is called.")
    if request.method == 'DELETE':
        try:
            mydb = mysqlcon.connect(
                host='127.0.0.1',
                user='root',
                password='54010674Nong',
                database='filesharingdb'
            )
            mycursor = mydb.cursor()
            mycursor.execute(f"SELECT filePath FROM FileSharing WHERE item_id = '{item_id}'")
            filepath = mycursor.fetchall()[0][0]

            if filepath:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    mycursor.execute(f"DELETE FROM FileSharing WHERE item_id = '{item_id}'")
                    mydb.commit()
                    return make_response('successful', 200, {'message': 'delete file sucessfully'})
                else:
                    mydb.commit()
                    return make_response('delete error', 500, {'error': "file doesn't exist."})
            else:
                mydb.commit()
                return make_response('delete error', 500, {'error': "file doesn't exist."})

        except Exception as e:
            print(f"error occured : {e}")
            return make_response('delete error', 500, {'error': f"internal server error : {e}"})

            
@app.route('/test_post', methods = ['GET', 'POST'])
@cross_origin()
@token_required
def test_post(current_user):
    print("test_post is called.")
    if request.method == 'POST':
        try:
            print("show request files --> ", request.form)
            username = request.form['username']
            password = request.form['password']
            print(f"show me post --> {username}, {password}")
            return make_response('successful', 200, {'message': 'post sucessfully'})
        except Exception as e:
            print(f"error occured : {e}")
            return make_response('upload error', 500, {'error': f"internal server error : {e}"})

if __name__ == "__main__":
    app.run()