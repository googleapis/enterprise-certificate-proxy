module signer

go 1.19

require github.com/google/go-pkcs11 v0.2.0

require github.com/googleapis/enterprise-certificate-proxy/utils v0.0.0-00010101000000-000000000000 // indirect

replace github.com/googleapis/enterprise-certificate-proxy/utils => ../../../utils
