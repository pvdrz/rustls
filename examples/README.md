# Examples

Running `tls*-mio` examples:

```console
$ # 0. install mkcert - https://github.com/FiloSottile/mkcert

$ mkcert localhost

$ ls *.pem
localhost-key.pem  localhost.pem

$ # ports < 1024 require root permissions so use a higher port number
$ cargo r --bin tlsserver-mio -- --certs localhost.pem --key localhost-key.pem --port 1443 http

$ # failure mode
$ cargo r --bin tlsclient-mio -- --http --port 1443 localhost

$ # happy path
$ cargo r --bin tlsclient-mio -- --http --port 1443 --cafile $(mkcert -CAROOT)/rootCA.pem localhost
```
