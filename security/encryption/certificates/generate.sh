#!/bin/bash

# Configuration
CERT_DIR="/etc/ssl/irssh-panel"
DAYS_VALID=365
KEY_SIZE=4096
COUNTRY="IR"
STATE="Tehran"
LOCALITY="Tehran"
ORGANIZATION="IRSSH Panel"
ORGANIZATIONAL_UNIT="Security"
COMMON_NAME="irssh-panel.example.com"
EMAIL="admin@example.com"

# Create directories
mkdir -p "${CERT_DIR}"
mkdir -p "${CERT_DIR}/private"
chmod 700 "${CERT_DIR}/private"

# Generate CA key and certificate
openssl genrsa -out "${CERT_DIR}/private/ca.key" ${KEY_SIZE}
chmod 400 "${CERT_DIR}/private/ca.key"

openssl req -x509 -new -nodes \
  -key "${CERT_DIR}/private/ca.key" \
  -sha256 -days ${DAYS_VALID} \
  -out "${CERT_DIR}/ca.crt" \
  -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/OU=${ORGANIZATIONAL_UNIT}/CN=${COMMON_NAME}/emailAddress=${EMAIL}"

# Generate server key and CSR
openssl genrsa -out "${CERT_DIR}/private/server.key" ${KEY_SIZE}
chmod 400 "${CERT_DIR}/private/server.key"

openssl req -new \
  -key "${CERT_DIR}/private/server.key" \
  -out "${CERT_DIR}/server.csr" \
  -config tls.conf

# Sign the server certificate
openssl x509 -req \
  -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/private/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/server.crt" \
  -days ${DAYS_VALID} \
  -sha256 \
  -extfile tls.conf \
  -extensions v3_req

# Generate Diffie-Hellman parameters
openssl dhparam -out "${CERT_DIR}/dhparam.pem" 2048

# Verify certificates
openssl verify -CAfile "${CERT_DIR}/ca.crt" "${CERT_DIR}/server.crt"

# Create certificate chain
cat "${CERT_DIR}/server.crt" "${CERT_DIR}/ca.crt" > "${CERT_DIR}/chain.crt"
