import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route("/import", methods=["POST"])
def import_data():
    # Уязвимость: десериализация непроверенных данных
    raw = request.data  # пользователь может прислать произвольные байты
    obj = pickle.loads(raw)  # уязвимый вызов — find_vulnerable_calls увидит 'loads'
    return {"status": "ok", "type": str(type(obj))}

if __name__ == "__main__":
    app.run(debug=True)