openssl genpkey -algorithm RSA -out shark-ca.key -pkeyopt rsa_keygen_bits:4096
openssl req -x509 -new -nodes -key shark-ca.key -sha256 -days 3650 -config shark-ca.cnf -out shark-ca.crt
openssl x509 -noout -text -in shark-ca.crt

openssl genpkey -algorithm RSA -out shark-dev.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key shark-dev.key -out shark-dev.csr -config shark-dev.cnf

openssl x509 -req -in shark-dev.csr -CA shark-ca.crt -CAkey shark-ca.key -CAcreateserial -sha256 -days 365 -out shark-dev.crt