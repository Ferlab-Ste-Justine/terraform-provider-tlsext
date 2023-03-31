resource "time_static" "time" {}

resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tlsext_pgp_private_key" "rsa" {
    private_key = tls_private_key.rsa.private_key_pem_pkcs8
    timestamp = time_static.time.id
    name = "You"
    email = "your@email.com"
}
