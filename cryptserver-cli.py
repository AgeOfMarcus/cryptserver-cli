#!/usr/bin/python3

import requests, base64, argparse, json

class Crypt(object):
	def __init__(self, addr, keypair=None):
		self.baseurl = addr
		if keypair is None:
			self.key = requests.get(self.baseurl+"/register").json()
		else:
			self.key = keypair
	def encrypt(self, raw, key=None):
		if key is None:
			key = self.key['pub']
		data = base64.b64encode(raw).decode()
		enc = requests.post(self.baseurl+"/encrypt/"+key, data={
			'data':data
		}).content
		res = base64.b64decode(enc)
		return res
	def decrypt(self, raw, key=None):
		if key is None:
			key = self.key['priv']
		enc = base64.b64encode(raw).decode()
		dec = requests.post(self.baseurl+"/decrypt/"+key, data={
			'data':enc
		}).content
		res = base64.b64decode(dec)
		return res

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"-u","--url",
		help=("Server URL. Eg: https://cryptserver--marcusweinberger.repl.co"),
		required=True)
	parser.add_argument(
		"-k","--key",
		help=("Keyfile, if key is \"gen\" then a new keypair will be requested and output to the terminal. Eg: --key key.json"),
		required=True)
	parser.add_argument(
		"-e","--encrypt",
		help=("Encrypt a file and add \"encrypted.\" to the filename. Eg: --encrypt secrets.txt"))
	parser.add_argument(
		"-d","--decrypt",
		help=("Decrypt a file. Eg: --decrypt encrypted.secrets.txt"))
	return parser.parse_args()

def main(args):
	url = args.url
	if args.key == "gen":
		keys = Crypt(url).key
		print(json.dumps(keys))
		return 0
	key = json.loads(open(args.key,"r").read())
	crypt = Crypt(url,keypair=key)
	if not args.encrypt and not args.decrypt:
		print("Neither --encrypt or --decrypt specified, exiting.")
		return 1
	if args.encrypt:
		data = open(args.encrypt,"rb").read()
		res = crypt.encrypt(data)
		with open("encrypted."+args.encrypt,"wb") as f:
			f.write(res)
		return 0
	if args.decrypt:
		data = open(args.decrypt,"rb").read()
		res = crypt.decrypt(data)
		with open("decrypted."+args.decrypt,"wb") as f:
			f.write(res)
		return 0
	return 0

if __name__ == "__main__":
	exit(main(parse_args()))