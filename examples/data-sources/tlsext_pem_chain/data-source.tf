//This will work as intended
data "tlsext_pem_chain" "certs" {
    pem_chain = file("chain.pem")
}

data "tls_certificate" "certs" {
  for_each = { for idx ,elem in data.tlsext_pem_chain.certs.pem_list : idx => elem }
  content  = each.value
}

output "certs" {
    value = data.tls_certificate.certs
}

//This will not, only a single cert will be processed
data "tls_certificate" "single_cert" {
  content  = file("chain.pem")
}

output "certs" {
    value = data.tls_certificate.single_cert
}