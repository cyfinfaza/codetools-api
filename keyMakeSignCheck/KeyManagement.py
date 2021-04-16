import base64
import json
from uuid import uuid4
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, KeySerializationEncryption, PrivateFormat, PublicFormat, load_pem_private_key, load_pem_public_key
import json


class Signee:
	def __init__(self, publicKey, privateKey):
		public_bytes = base64.urlsafe_b64decode(publicKey)
		self.public_key = load_pem_public_key(public_bytes)
		private_bytes = base64.urlsafe_b64decode(privateKey)
		self.private_key = load_pem_private_key(private_bytes, None)

	def fromFile(keyFile):
		keyStrings = json.loads(keyFile.read())
		return Signee(keyStrings['public'], keyStrings['private'])

	def sign(self, data: str):
		signature = self.private_key.sign(
			data=data.encode('utf-8'),
			padding=padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			algorithm=hashes.SHA256()
		)
		return base64.urlsafe_b64encode(signature).decode('ASCII')
	
	def verify(self, data:str, signature_string:str):
		# signature = base64.urlsafe_b64decode(signature_string)
		try:
			signature = base64.urlsafe_b64decode(signature_string)
			self.public_key.verify(
				signature=signature,
				data=data.encode('utf-8'),
				padding=padding.PSS(
					mgf=padding.MGF1(hashes.SHA256()),
					salt_length=padding.PSS.MAX_LENGTH
				),
				algorithm=hashes.SHA256()
			)
			is_signature_correct = True
		# except InvalidSignature:
		except:
			is_signature_correct = False
		return is_signature_correct

if __name__ == "__main__":
	signee = Signee(open('keys.json', 'r'))
	someID = str(uuid4())
	signature = signee.sign(someID)
	print(f"UUID: {someID}\nSignature: {signature}")
	sigInput = input("Re-input the signature: ")
	valid = signee.verify(someID, sigInput)
	print("Valid?", valid)
