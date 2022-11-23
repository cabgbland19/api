from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "super-secret"  # Cambiar por el que se conveniente
jwt = JWTManager(app)
@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"]+'/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user,
                                   expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401
@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        print("ruta excluida ",request.path)
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"]is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission Denegado"}), 401
        else:
            return jsonify({"message": "Permission Denegado"}), 401
def limpiarURL(url):
    partes = request.path.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
        return url
def validarPermiso(endPoint,metodo,idRol):
    url=dataConfig["url-backend-security"]+"/permisos-roles/validar-permiso/rol/"+str(idRol)
    tienePermiso=False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body={"url":endPoint,"metodo":metodo}
    response = requests.get(url,json=body, headers=headers)
    try:
        data=response.json()
        if("_id" in data):
            tienePermiso=True
    except:
        pass
    return tienePermiso
##################################################################
@app.route("/Candidatos",methods=['GET'])
def getCandidatoss():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Candidatos",methods=['POST'])
def crearCandidatos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Candidatos'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/Candidatos/<string:id>",methods=['GET'])
def getCandidatos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Candidatos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Candidatos/<string:id>",methods=['PUT'])
def modificarCandidatos(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Candidatos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/Candidatos/<string:id>",methods=['DELETE'])
def eliminarCandidatos(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Candidatos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
###################################################################################

@app.route("/Mesas",methods=['GET'])
def getMesass():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Mesas",methods=['POST'])
def crearMesas():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Mesas'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/Mesas/<string:id>",methods=['GET'])
def getMesas(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Mesas/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Mesas/<string:id>",methods=['PUT'])
def modificarMesas(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Mesas/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/Mesas/<string:id>",methods=['DELETE'])
def eliminarMesas(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Mesas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

##################################################################################

@app.route("/Partido",methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Partido'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Partido",methods=['POST'])
def crearPartido():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Partido'
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/Partido/<string:id>",methods=['GET'])
def getPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Partido/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Partido/<string:id>",methods=['PUT'])
def modificarPartido(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Partido/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/Partido/<string:id>",methods=['DELETE'])
def eliminarPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Partido/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

##################################################################################

@app.route("/<string:ido>/Partido/<string:id>",methods=['PUT'])
def modificarPartidosss(ido, id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] +ido + '/Partido/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

##################################################################################

@app.route("/Resultados",methods=['GET'])
def getResultadoss():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Resultados'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Resultados/mesa/<string:idmesa>/candidato/<string:idcandidato>",methods=['POST'])
def crearResultado(idmesa,idcandidato):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Resultados/mesa/'+ idmesa + '/candidato/' + idcandidato
    response = requests.post(url, headers=headers,json=data)
    json = response.json()
    return jsonify(json)

@app.route("/Resultados/<string:id>",methods=['GET'])
def getResultados(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Resultados/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Resultados/<string:idRe>/mesa/<string:idMe>/candidato/<string:idCan>",methods=['PUT'])
def modificarResultado(idRe,idMe,idCan):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Resultados/'+ idRe + '/mesa/' + idMe +'/candidato/'+ idCan
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
############################################################################
#Querys
@app.route("/votos-candidato/<string:idCan>",methods=['GET'])
def getVotosPorCandidato(idCan):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/votos-candidato/'+ idCan 
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/votos-mesa/<string:idMesa>/candidato/<string:idCan>",methods=['GET'])
def getVotosMesaYcandidato(idMesa,idCan):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/votos-mesa/' + idMesa + '/candidato/' + idCan
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/votos-ordenado",methods=['GET'])
def getVotosOrdenados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/votos-ordenado'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesa-ordenado/<string:idMes>",methods=['GET'])
def getVotosMesaOrdenada(idMes):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/mesa-ordenado/' +idMes
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/Mayor-Participacion",methods=['GET'])
def getMesasMayorParticipacion():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/Mayor-Participacion'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)



##################################################################################
@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)


def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data
if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" +
str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])




