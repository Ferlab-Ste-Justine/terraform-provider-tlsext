terraform {
  required_version = ">= 1.0.0"
  required_providers {
    tlsext = {
      source  = "ferlab/tlsext"
      version = "1.0.0"
    }
  }
}