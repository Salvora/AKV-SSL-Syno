#!/bin/bash -eu
# Synology DSM SSL Certificate Renewal from Azure Key Vault

# Version: 1.0.0
# Release Date: 2023-10-01
# Author: Salvora
# Description: This script automates the renewal and replacement of SSL certificates on Synology NAS using Azure Key Vault.

### Parameters ###
AZURE_API_VERSION="7.1"


# Name of the script
SCRIPTNAME="$(basename "${0}")"
echo "Script Name: ${SCRIPTNAME}"

# Define the log file path in the same directory as the script
LOGFILE="$(dirname "${0}")/azure-ssl-renew.log"

# Function to prepend timestamps
log_with_timestamp() {
  while IFS= read -r line; do
    echo "$(date '+[%Y-%m-%d %H:%M:%S]') $line"
  done
}

# Redirect stdout and stderr to the log file with timestamps and also to the console
exec > >(tee >(log_with_timestamp >> "${LOGFILE}")) 2>&1

for cmd in jq curl openssl; do
  if ! command -v "${cmd}" &> /dev/null; then
    echo "ERROR: ${cmd} is not installed."
    exit 1
  fi
done

# Check parameters (Azure Key Vault name and certificate name)
if [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
  printf -- '%s\n' \
    "ERROR/${SCRIPTNAME}: Missing parameter(s)" \
    "Usage: ${0} <Azure_Key_Vault_Name> <Azure_Certificate_Name>"
  exit 64
fi

VAULT_NAME="${1}"       # Azure Key Vault name
CERT_NAME="${2}"        # Certificate name in Azure Key Vault
echo "Vault Name: ${VAULT_NAME}, Certificate Name: ${CERT_NAME}"

CERTS_FOLDER="$(dirname "${0}")/certs"
# Create a certificate folder
mkdir -p "${CERTS_FOLDER}"


# Load Azure Credentials from .env file in the script's directory
CREDENTIALS_FILE="$(dirname "${0}")/credentials.env"
if [ -f "${CREDENTIALS_FILE}" ]; then
  echo "Loading credentials from ${CREDENTIALS_FILE}..."
  source "${CREDENTIALS_FILE}"
else
  printf -- '%s\n' \
    "ERROR/${SCRIPTNAME}: Credentials file not found: ${CREDENTIALS_FILE}"
  exit 65
fi

fetch_certs() {
  # Fetch PKCS12 (PFX) certificate from Key Vault
  CERT_PFX_URL="https://${VAULT_NAME}.vault.azure.net/secrets/${CERT_NAME}/?api-version=${AZURE_API_VERSION}"
  curl -s --max-time 30 -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    "${CERT_PFX_URL}" | jq -r '.value' | base64 -d > "${CERTS_FOLDER}/${CERT_NAME}.pfx"
  if [ $? -ne 0 ]; then
    printf -- '%s\n' "ERROR/${SCRIPTNAME}: Failed to fetch certificate from Azure Key Vault"
    exit 65
  fi 
}

convert_certs() {
  echo "Converting PFX certificate to PEM formats..."
  # Convert PFX to PEM (extract public cert and private key)
  openssl pkcs12 -in "${CERTS_FOLDER}/${CERT_NAME}.pfx" -clcerts -nokeys -passin pass: | openssl x509 -out "${CERTS_FOLDER}/cert.pem" || {
    echo "ERROR: Failed to obtain the public certificate (cert.pem) from the PFX file"
    exit 65
  }
  openssl pkcs12 -in "${CERTS_FOLDER}/${CERT_NAME}.pfx" -nokeys -cacerts -passin pass: | openssl x509 -out "${CERTS_FOLDER}/chain.pem" || {
    echo "ERROR: Failed to obtain the intermediate certificate (chain.pem) from the PFX file"
    exit 65
  }
  openssl pkcs12 -in "${CERTS_FOLDER}/${CERT_NAME}.pfx" -nocerts -nodes -passin pass: | openssl rsa -out "${CERTS_FOLDER}/privkey.pem" || {
    echo "ERROR: Failed to obtain the private key (privkey.pem) from the PFX file"
    exit 65
  }
  cat "${CERTS_FOLDER}/cert.pem" "${CERTS_FOLDER}/chain.pem" > "${CERTS_FOLDER}/fullchain.pem" || {
      echo "ERROR: Failed to create fullchain.pem"
      exit 65
  }

restart_services() {
  systemctl restart pkgctl-WebStation
  systemctl restart nginx
}

  # Debugging: Display the contents of the certificate and key files
  echo "Certificate (cert.pem):"
  cat "${CERTS_FOLDER}/cert.pem"
  echo "Intermediate Certificate (chain.pem):"
  cat "${CERTS_FOLDER}/chain.pem"
  echo "Private Key (privkey.pem):"
  cat "${CERTS_FOLDER}/privkey.pem"
  # Check if certificate and private key are present
  if [ ! -f "${CERTS_FOLDER}/cert.pem" ] || [ ! -f "${CERTS_FOLDER}/privkey.pem" ]; then
    printf -- '%s\n' \
      "ERROR/${SCRIPTNAME}: Failed to retrieve certificate or key from Azure Key Vault"
    exit 65
  fi
}

# Authenticate and get an access token from Azure
TOKEN=$(curl -X POST -s --max-time 30 -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=${AZURE_CLIENT_ID}&client_secret=${AZURE_CLIENT_SECRET}&resource=https://vault.azure.net" \
  "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/token" | jq -r '.access_token')
if [ $? -ne 0 ] || [ -z "${TOKEN}" ] || [ "${TOKEN}" = "null" ]; then
  printf -- '%s\n' \
    "ERROR/${SCRIPTNAME}: Failed to obtain access token from Azure. Make sure that the credentials are correct and not expired."
  exit 65
fi
printf -- "Access Token obtained successfully.\n"

# Fetch certificate properties from Key Vault
CERT_URL="https://${VAULT_NAME}.vault.azure.net/certificates/${CERT_NAME}/?api-version=${AZURE_API_VERSION}"
CERT_PROPERTIES=$(curl -s --max-time 30 -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  "${CERT_URL}")
if [ $? -ne 0 ]; then
  printf -- '%s\n' "ERROR/${SCRIPTNAME}: Failed to fetch certificate properties from Azure Key Vault"
  exit 65
fi

# echo "Certificate Properties Retrieved: ${CERT_PROPERTIES}"

# Extract the x5t field and decode it to get the thumbprint
KEYVAULT_CERT_THUMBPRINT=$(echo "${CERT_PROPERTIES}" | jq -r '.x5t // empty')
if [ -z "${KEYVAULT_CERT_THUMBPRINT}" ]; then
  echo "ERROR: x5t is empty."
  exit 65
fi

# Replace URL-safe characters and pad the base64 string if necessary
BASE64_STANDARD=$(echo "${KEYVAULT_CERT_THUMBPRINT}" | sed 's/-/+/g; s/_/\//g')
BASE64_PADDED="${BASE64_STANDARD}$(printf '%*s' $(( (4 - ${#BASE64_STANDARD} % 4) % 4 )) | tr ' ' '=')"

# Convert base64 x5t to binary and then to hex
DECODING=$(echo "${BASE64_PADDED}" | base64 --decode | xxd -p | tr -d '\n')
KEYVAULT_CERT_THUMBPRINT="${DECODING}"

echo "Azure Key Vault Certificate Thumbprint: ${KEYVAULT_CERT_THUMBPRINT}"

# Determine certificate ID for certificate name in Synology
CERTID="$(/usr/bin/jq -r --arg desc "${CERT_NAME}" 'to_entries[] | select(.value.desc == $desc) | .key' /usr/syno/etc/certificate/_archive/INFO)"


if [ -z "${CERTID}" ]; then
  printf -- '%s\n' "WARNING/${SCRIPTNAME}: Certificate file ${CERT_FILE} does not exist on the Synology. Importing from Azure Key Vault as a New Certificate."
  fetch_certs
  convert_certs
  RESULT="$(/usr/syno/bin/synowebapi --exec-fastwebapi \
      "api=SYNO.Core.Certificate" \
      "method=import" \
      "version=1" \
      "key_tmp=\"${CERTS_FOLDER}/privkey.pem\"" \
      "cert_tmp=\"${CERTS_FOLDER}/cert.pem\"" \
      "inter_cert_tmp=\"${CERTS_FOLDER}/chain.pem\"" \
      "desc=\"${CERT_NAME}\"")"
else
  # Get the current certificate's thumbprint from Synology
  CERT_FILE="/usr/syno/etc/certificate/_archive/${CERTID}/cert.pem"
  CURRENT_CERT_THUMBPRINT="$(openssl x509 -noout -fingerprint -in "${CERT_FILE}" | sed 's/^.*=//' | sed 's/://g')"
  echo "Current Syno Certificate Thumbprint: ${CURRENT_CERT_THUMBPRINT}"
  if [ "$(echo "${CURRENT_CERT_THUMBPRINT}" | tr '[:upper:]' '[:lower:]')" == "$(echo "${KEYVAULT_CERT_THUMBPRINT}" | tr '[:upper:]' '[:lower:]')" ]; then
    echo "INFO: Certificate is up-to-date (Thumbprints match). No action required."
    if [ ! -f "${CERTS_FOLDER}/${CERT_NAME}.pfx" ]; then
      fetch_certs
      convert_certs
    fi
    exit 0
  else
    echo "INFO: Certificate is outdated (Thumbprints do not match). Updating certificate..."
    echo "Synology Certificate ID: ${CERTID}"
    fetch_certs
    convert_certs
    RESULT="$(/usr/syno/bin/synowebapi --exec-fastwebapi \
        "api=SYNO.Core.Certificate" \
        "method=import" \
        "version=1" \
        "key_tmp=\"${CERTS_FOLDER}/privkey.pem\"" \
        "cert_tmp=\"${CERTS_FOLDER}/cert.pem\"" \
        "inter_cert_tmp=\"${CERTS_FOLDER}/chain.pem\"" \
        "cert_id=\"${CERTID}\"" \
        "desc=\"${CERT_NAME}\"")"
  fi
  restart_services
fi

if [ $? -ne 0 ]; then
  printf -- '%s\n' "ERROR/${SCRIPTNAME}: Failed to import certificate into DSM"
  exit 73
fi
printf -- "${RESULT}\n"

# Check JSON result and error out if not successful
SUCCESS="$(printf -- "${RESULT}" | /usr/bin/jq -r '.success')"
if [ "${SUCCESS}" != 'true' ]; then
  ERROR_CODE="$(printf -- "${RESULT}" | /usr/bin/jq -r '.error.code')"
  printf -- "ERROR/${SCRIPTNAME}: Certificate import failed with error code ${ERROR_CODE}\n"
  exit 73  # Error importing certificate
fi

echo "Certificate operation completed successfully."

# Cleanup temporary certificate folder
trap 'rm -rf "${CERTS_FOLDER}"' EXIT