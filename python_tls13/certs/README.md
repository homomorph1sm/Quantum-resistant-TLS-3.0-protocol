# Test certificates

For local test only. Generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=localhost"
```

If you connect to `127.0.0.1`, use `--insecure` in the client or issue a cert with SAN that matches your host.
