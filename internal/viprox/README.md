### Introduction

Socks5 to HTTP Proxy is a simple proxy server that can forward data from a Socks5 proxy to a HTTP proxy. 
It is useful when you have a Socks5 proxy and you want to use it with a program that only supports HTTP proxies.

### BUILD

```go 
GOOS=linux GOARCH=amd64 go build socks_to_http.go 
```

### USAGE

```shell
socks_to_http --listen 0.0.0.0:1080 --proxy <SERVER_IP>:<HTTP_PROXY_PORT> --log /var/log/socks_to_http.log
```

To deploy the script as a service, you can use the following systemd service file:
1. Install golang on the target server `yum install -y golang`
2. Copy the binary `socks_to_http` to `/opt/scripts/`
3. Copy `gosockstohttp.service` to /etc/systemd/system/
4. Update `gosockstohttp.service` with the correct server ip and http proxy port
5. Run `chmod + /opt/scripts/socks_to_http`
6. Run `systemctl daemon-reload`
7. Run `systemctl enable gosockstohttp`
8. Run `systemctl start gosockstohttp`
9. Check the status of the service `systemctl status gosockstohttp`
10. Check the logs at `/var/log/socks_to_http.log`
11. Try sending socks5 traffic to the server and see if it is forwarded to the http proxy
12. Finally, add the following rules to iptables to redirect all traffic to the socks_to_http server
```shell
iptables -I INPUT -p tcp -m tcp --dport 1080 -m comment --comment "Send Socks5 requests via blocked users list" -j BlockedUsers
iptables -I INPUT -p tcp -m tcp --dport 1080 -m comment --comment "Allow socks5 port" -j ACCEPT
```
