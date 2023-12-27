SHELL := /bin/bash
.DEFAULT_GOAL := all_steps

openssl.cnf step_0.out: openssl.cnf.example steps.sh
	./steps.sh step_0

ca-cert.pem ca-key.pem:
	@echo
	@echo "###########################################"
	@echo "Generate a certificate authority (CA) cert"
	@echo "-------------------------------------------"
	@read -p "Press any key to continue... " -n1 -s
	openssl req -new -x509 -days 3650 -keyout ca-key.pem -out ca-cert.pem

server-key.pem:
	@echo
	@echo "###########################################"
	@echo "Generate Server private key"
	@echo "-------------------------------------------"
	@read -p "Press any key to continue... " -n1 -s
	openssl genpkey -algorithm RSA -out server-key.pem

server-csr.pem: server-key.pem
	@echo
	@echo "###########################################"
	@echo "Create Server certificate generation request."
	@echo "-------------------------------------------"
	@read -p "Press any key to continue... " -n1 -s
	openssl req -new -key server-key.pem -out server-csr.pem

server-cert.pem: server-csr.pem ca-key.pem ca-cert.pem openssl.cnf
	@echo
	@echo "###########################################"
	@echo "Generate Server cert"
	@echo "-------------------------------------------"
	@read -p "Press any key to continue... " -n1 -s
	openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 3650 -extfile openssl.cnf -extensions v3_req

client-key.pem:
	@echo
	@echo "###########################################"
	@echo "Generate Client private key"
	@echo "-------------------------------------------"
	@read -p "Press any key to continue... " -n1 -s
	openssl genpkey -algorithm RSA -out client-key.pem

client-csr.pem: client-key.pem
	@echo
	@echo "###########################################"
	@echo "Create Client certificate generation request."
	@echo "-------------------------------------------"
	@read -p "Press any key to continue... " -n1 -s
	openssl req -new -key client-key.pem -out client-csr.pem

client-cert.pem: client-csr.pem ca-key.pem ca-cert.pem openssl.cnf
	@echo
	@echo "###########################################"
	@echo "Generate Client cert"
	@echo "-------------------------------------------"
	@read -p "Press any key to continue... " -n1 -s
	openssl x509 -req -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 3650 -extfile openssl.cnf -extensions v3_req

step_1.out: step_0.out
	./steps.sh step_1

step_2.out: step_1.out
	./steps.sh step_2

all_steps: ca-cert.pem server-cert.pem client-cert.pem step_2.out

clean:
	rm -f *.pem
	rm -f *.out
	rm -f openssl.cnf

.PHONY: clean all_steps
