import paramiko


def executar_comando_ssh(host, username, password=None, key_path=None, comando="whoami"):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if key_path:
            client.connect(
                hostname=host,
                username=username,
                key_filename=key_path
            )
        else:
            client.connect(
                hostname=host,
                username=username,
                password=password
            )

        stdin, stdout, stderr = client.exec_command(comando)

        resultado = stdout.read().decode()
        erro = stderr.read().decode()

        client.close()

        return {
            "success": True,
            "output": resultado,
            "error": erro
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }