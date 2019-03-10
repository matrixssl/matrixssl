The testkeys directory contains test keys in various formats for use by
included MatrixSSL test and example applications.

DO NOT USE THESE DEFAULT KEYS IN PRODUCTION ENVIRONMENTS.

DH/'bits'_DH_PARAMS.*	# PKCS3 Public DH parameters

EC/'bits'_EC.*		# X.509 ECDH-ECDSA Certificate, signed by _EC_CA
EC/'bits'_EC_KEY.*	# ECC Private Key corresponding with Certificate
EC/'bits'_EC_CA.*	# X.509 Self-Signed ECDH-ECDSA Certificate Authority
EC/ALL_EC_CAS.*		# All _EC_CA certificates concatenated

ECDH_RSA/'bits'_ECDH-RSA_CA.*	# X.509 Self-Signed RSA Certificate Authority
ECDH_RSA/'bits'_ECDH-RSA_KEY.*	# ECC Private key corresponding with certificate
ECDH_RSA/256_ECDH-RSA.*	# X.509 ECDH-RSA Certificate, signed by 1024_ECDH-RSA_CA
ECDH_RSA/521_ECDH-RSA.*	# X.509 ECDH-RSA Certificate, signed by 2048_ECDH-RSA_CA

ECDH_RSA/ALL_ECDH-RSA_CAS.*	# All _ECDH-RSA_CA certificates concatenated

PSK/psk.h	# Pre-shared symmetric keys

RSA/'bits'_RSA.*	# X.509 RSA Certificate, signed by _RSA_CA
RSA/'bits'_RSA_KEY.*	# RSA Private Key corresponding with Certificate
RSA/'bits'_RSA_CA.*		# X.509 Self-Signed RSA Certificate Authority
RSA/2048_RSA_CA_SIGN.*	# Same as above, but with cert and CRL signing capabilities
RSA/2048_RSA_CHAIN.pem  # 2048_RSA.pem and 2048_RSA_CA.pem concatenated
RSA/ALL_RSA_CAS.*		# All _RSA_CA certificates concatenated

