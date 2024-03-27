from pwn import *
import sys

if len(sys.argv) != 3:
	print('Invalid argument!')
	print('>> {} <sha256sum> <Password_file>'.format(sys.argv[0]))
	exit()

user_hash = sys.argv[1]
password_file = sys.argv[2]
attempts = 0

with log.progress("Attempting to hack {}!\n".format(user_hash)) as p:
	with open(password_file,'r',encoding='latin-1') as password_list:
		for password in password_list:
			password = password.strip("\n").encode('latin-1')
			password_hash = sha256sumhex(password)
			p.status("[{}] {} == {}".format(attempts,password.decode('latin-1'),password_hash))
			if password_hash == user_hash:
				p.success("Password hash found after {} attempts! {} Hash is '{}'!".format(attempts,user_hash,password.decode('latin-1')))
				exit()
			attempts += 1
		p.failure("Password hash not found")
