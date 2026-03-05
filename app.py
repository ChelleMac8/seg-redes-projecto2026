from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/send")
def send():
    return render_template("send.html")

@app.route("/inbox")
def inbox():
    # Por agora: mensagens dummy (fase 2 vamos buscar do BD)
    messages = [
        {"from": "Alice", "text": "Olá! Mensagem de teste.", "date": "2026-03-05", "has_image": False},
        {"from": "Bob", "text": "Enviei uma imagem também.", "date": "2026-03-05", "has_image": True},
    ]
    return render_template("inbox.html", messages=messages)

if __name__ == "__main__":
    app.run(debug=True)