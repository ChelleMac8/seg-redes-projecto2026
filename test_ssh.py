from app.services.ssh_utils import executar_comando_ssh

resultado = executar_comando_ssh(
    host="127.0.0.1",
    username="michelle-macamo",
    password="alohomora",  # ou usa key_path
    comando="whoami"
)

print(resultado)