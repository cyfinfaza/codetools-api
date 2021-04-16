import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, KeySerializationEncryption, PrivateFormat, PublicFormat, load_pem_public_key

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=512,
    backend=default_backend()
)
public_key = private_key.public_key()
public_string = base64.urlsafe_b64encode(public_key.public_bytes(Encoding.PEM,PublicFormat.PKCS1)).decode('ASCII')
private_string = base64.urlsafe_b64encode(private_key.private_bytes(Encoding.PEM,PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())).decode('ASCII')

save_string_json = json.dumps({
	'public':public_string,
	'private':private_string
})

save_string_env = f"""
SIGNEE_PUBLICKEY = '{public_string}'
SIGNEE_PRIVATEKEY = '{private_string}'
"""

with open('keys.json', 'w') as file:
	file.write(save_string_json)

with open('.env', 'w') as file:
	file.write(save_string_env)

print(save_string_env)