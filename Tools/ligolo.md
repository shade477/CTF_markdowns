# Ligolo

Ligolo-ng is a simple, lightweight and fast tool that allows pentesters to establish tunnels from a reverse TCP/TLS connection using a tun interface (without the need of SOCKS).

## Building Ligolo-ng

Building ligolo-ng (Go >= 1.20 is required):

```sh
$ go build -o agent cmd/agent/main.go
$ go build -o proxy cmd/proxy/main.go
# Build for Windows
$ GOOS=windows go build -o agent.exe cmd/agent/main.go
$ GOOS=windows go build -o proxy.exe cmd/proxy/main.go
```

## Setting up Interface

```sh
# Create Interface
sudo ip tuntap add user <user> mode tun ligolo
# Activate Interface
sudo ip link set ligolo up
# Add IP route
sudo ip route add <network> dev ligolo
```

## Start Ligolo proxy

```sh
# To use a self signed cert
sudo ./proxy -selfcert
# To use a Let's Encrypt auto certificate. It uses port 80 to sign the certificate
sudo ./proxy -autocert
ligolo-ng »
```
