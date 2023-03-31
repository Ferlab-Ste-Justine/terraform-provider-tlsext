resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

data "tlsext_gpg_armor_format" "rsa" {
    private_key = tls_private_key.rsa.private_key_pem_pkcs8
    name = "Eric Vallee"
    email = "eric_vallee@webificservices.com"
    algorithm = "rsa"
}

resource "local_file" "rsa_pub" {
  content         = data.tlsext_gpg_armor_format.rsa.gpg_armor_public_key
  file_permission = "0600"
  filename        = "${path.module}/keys/public_key"
}

resource "local_file" "rsa_pri" {
  content         = data.tlsext_gpg_armor_format.rsa.gpg_armor_private_key
  file_permission = "0600"
  filename        = "${path.module}/keys/private_key"
}