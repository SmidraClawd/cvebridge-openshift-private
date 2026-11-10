import sys, ssl, json
print(json.dumps({"python":sys.version.split()[0], "tls":ssl.OPENSSL_VERSION, "purpose":"late base registration test"}))
