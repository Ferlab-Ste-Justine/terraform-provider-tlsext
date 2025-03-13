module "top_ca" {
  source = "./ca"
}

resource "tls_private_key" "intermediate_ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "intermediate_ca" {
  private_key_pem = tls_private_key.intermediate_ca.private_key_pem

  subject {
    common_name  = "intermediate"
    organization = "Ferlab"
  }
}

resource "tls_locally_signed_cert" "intermediate_ca" {
  cert_request_pem   = tls_cert_request.intermediate_ca.cert_request_pem
  ca_private_key_pem = module.top_ca.key
  ca_cert_pem        = module.top_ca.certificate

  validity_period_hours = 365 * 24
  early_renewal_hours   = 30 * 24

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "cert_signing",
  ]

  is_ca_certificate = true
}

resource "tls_private_key" "server" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "server" {
  private_key_pem = tls_private_key.server.private_key_pem

  subject {
    common_name  = "localhost.test"
    organization = "Ferlab"
  }

  dns_names = [
    "localhost.test",
    "*.localhost.test"
  ]
}

resource "tls_locally_signed_cert" "server" {
  cert_request_pem   = tls_cert_request.server.cert_request_pem
  ca_private_key_pem = tls_private_key.intermediate_ca.private_key_pem
  ca_cert_pem        = tls_locally_signed_cert.intermediate_ca.cert_pem

  validity_period_hours = 365 * 24
  early_renewal_hours   = 30 * 24

  allowed_uses = [
    "server_auth",
  ]

  is_ca_certificate = false
}

data "tlsext_pem_chain" "certs" {
    pem_chain = "${tls_locally_signed_cert.server.cert_pem}\n${tls_locally_signed_cert.intermediate_ca.cert_pem}\n${module.top_ca.certificate}"
}

data "tls_certificate" "certs" {
  for_each = { for idx ,elem in data.tlsext_pem_chain.certs.pem_list : idx => elem }
  content  = each.value
}

data "tls_certificate" "first_cert" {
  content  = data.tlsext_pem_chain.certs.first_pem
}

data "tls_certificate" "last_cert" {
  content  = data.tlsext_pem_chain.certs.last_pem
}

output "certs" {
    value = data.tls_certificate.certs
}

output "first_cert" {
    value = data.tls_certificate.first_cert
}

output "last_cert" {
    value = data.tls_certificate.last_cert
}