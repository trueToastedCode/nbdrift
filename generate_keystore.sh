#!/bin/bash

KEYSTORE_NAME="trueToastedCode-release-key.jks"
ALIAS_NAME="trueToastedCode-key"
STOREPASS="StrongPass123!"
KEYPASS="StrongPass123!"
DNAME="CN=True Toasted Code, OU=Development, O=TrueToastedCode Ltd., L=Berlin, S=Berlin, C=DE"
VALIDITY=10000
KEYALG="RSA"
KEYSIZE=2048

echo "Generating keystore '${KEYSTORE_NAME}' with alias '${ALIAS_NAME}'..."

keytool -genkeypair -v \
  -keystore "$KEYSTORE_NAME" \
  -alias "$ALIAS_NAME" \
  -keyalg "$KEYALG" \
  -keysize "$KEYSIZE" \
  -validity "$VALIDITY" \
  -storepass "$STOREPASS" \
  -keypass "$KEYPASS" \
  -dname "$DNAME"

echo "Keystore generation completed."
