resource "time_static" "time" {}

resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tlsext_pgp_private_key" "rsa" {
    private_key = tls_private_key.rsa.private_key_pem_pkcs8
    timestamp = time_static.time.id
    name = "Eric Vallee"
    email = "eric_vallee@webificservices.com"
}

resource "local_file" "rsa_pub" {
  content         = tlsext_pgp_private_key.rsa.public_key_gpg_armor
  file_permission = "0600"
  filename        = "${path.module}/keys/rsa_public_key"
}

resource "local_file" "rsa_pri" {
  content         = tlsext_pgp_private_key.rsa.private_key_gpg_armor
  file_permission = "0600"
  filename        = "${path.module}/keys/rsa_private_key"
}