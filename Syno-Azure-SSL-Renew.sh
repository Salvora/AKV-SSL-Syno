#!/bin/bash -eu
# Synology DSM SSL Certificate Renewal from Azure Key Vault

# Version: 2.3.1
# Release Date: 2023-10-01
# Author: Salvora
# Description: This script automates the renewal and replacement of SSL certificates on Synology NAS using Azure Key Vault.
# shellcheck source=./credentials.env
# shellcheck disable=SC1091

### Parameters ###
AZURE_API_VERSION="7.1"
RENEWAL_METHOD="api" # Default method

# Parse method argument
if [[ "$1" == "--api" || "$1" == "--file" ]]; then
  RENEWAL_METHOD="${1#--}"
  shift
fi

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
exec > >(tee >(log_with_timestamp >>"${LOGFILE}")) 2>&1

# Check if required commands are available
for cmd in jq curl openssl rsync; do
  if ! command -v "${cmd}" &>/dev/null; then
    echo "ERROR: ${cmd} is not installed."
    exit 1
  fi
done

# Check parameters (Azure Key Vault name and certificate name)
if [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
  printf -- '%s\n' \
    "ERROR/${SCRIPTNAME}: Missing parameter(s)" \
    "Usage: ${0} [--api|--file] <Azure_Key_Vault_Name> <Azure_Certificate_Name>"
  exit 64
fi

VAULT_NAME="${1}" # Azure Key Vault name
CERT_NAME="${2}"  # Certificate name in Azure Key Vault
echo "Vault Name: ${VAULT_NAME}, Certificate Name: ${CERT_NAME}"

SYNO_CERTS_BASE_FOLDER="/usr/syno/etc/certificate/_archive"
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

renew_cert_api() {
  echo "INFO: Using API method to renew certificate..."
  if ! RESULT=$(/usr/syno/bin/synowebapi --exec-fastwebapi \
    "api=SYNO.Core.Certificate" \
    "method=import" \
    "version=1" \
    "key_tmp=\"${CERTS_FOLDER}/privkey.pem\"" \
    "cert_tmp=\"${CERTS_FOLDER}/cert.pem\"" \
    "inter_cert_tmp=\"${CERTS_FOLDER}/chain.pem\"" \
    "cert_id=\"${CERTID}\"" \
    "desc=\"${CERT_NAME}\"" \
    "as_default=\"${AS_DEFAULT}\""); then
    printf -- '%s\n' "ERROR/${SCRIPTNAME}: Failed to import new certificate into DSM."
    exit 73
  fi

  # Verify Import Success
  SUCCESS="$(printf -- '%s' "${RESULT}" | /usr/bin/jq -r '.success')"
  if [ "${SUCCESS}" != 'true' ]; then
    ERROR_CODE="$(printf -- '%s' "${RESULT}" | /usr/bin/jq -r '.error.code')"
    printf -- "ERROR/%s: Certificate import failed with error code %s\n" "${SCRIPTNAME}" "${ERROR_CODE}"
    exit 73
  fi
  echo "INFO: New certificate imported successfully."
}

renew_cert_file() {
  echo "INFO: Using file method to renew certificate..."
  echo "INFO: Replacing old certificates in ${SYNO_CERTS_FOLDER} with the new certificates"

  SYNO_CERTS_FOLDER="${SYNO_CERTS_BASE_FOLDER}/${CERTID}"
  rsync -av "${CERTS_FOLDER}/privkey.pem" "${SYNO_CERTS_FOLDER}/privkey.pem"
  rsync -av "${CERTS_FOLDER}/chain.pem" "${SYNO_CERTS_FOLDER}/chain.pem"
  rsync -av "${CERTS_FOLDER}/cert.pem" "${SYNO_CERTS_FOLDER}/cert.pem"
  rsync -av "${CERTS_FOLDER}/fullchain.pem" "${SYNO_CERTS_FOLDER}/fullchain.pem"
  echo "INFO: Certificates replaced successfully."

  REPLACED_CERT_THUMBPRINT="$(calculate_cert_thumbprint "${CERT_FILE}")"

  if compare_cert_thumbprints "${REPLACED_CERT_THUMBPRINT}" "${KEYVAULT_CERT_THUMBPRINT}"; then
    echo "INFO: Old certificates have been replaced and thumbprints match."
  else
    echo "ERROR: Thumbprints do not match after replacement."
    exit 1
  fi
}

fetch_certs() {
  # Fetch PKCS12 (PFX) certificate from Key Vault
  CERT_PFX_URL="https://${VAULT_NAME}.vault.azure.net/secrets/${CERT_NAME}/?api-version=${AZURE_API_VERSION}"
  if ! curl -s --max-time 30 -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    "${CERT_PFX_URL}" | jq -r '.value' | base64 -d >"${CERTS_FOLDER}/${CERT_NAME}.pfx"; then
    printf -- '%s\n' "ERROR/${SCRIPTNAME}: Failed to fetch certificate from Azure Key Vault"
    exit 65
  fi
}

# Function to get the thumbprint of a certificate
calculate_cert_thumbprint() {
  local cert_file="$1"
  openssl x509 -noout -fingerprint -in "${cert_file}" | sed 's/^.*=//' | sed 's/://g'
}

# Function to compare two thumbprints
compare_cert_thumbprints() {
  local thumbprint1="$1"
  local thumbprint2="$2"
  if [ "$(echo "${thumbprint1}" | tr '[:upper:]' '[:lower:]')" == "$(echo "${thumbprint2}" | tr '[:upper:]' '[:lower:]')" ]; then
    return 0
  else
    return 1
  fi
}

restart_services() {
  echo "INFO: Restarting services..."
  systemctl restart pkgctl-WebStation
  systemctl restart nginx
  echo "INFO: Services restarted successfully."
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
  cat "${CERTS_FOLDER}/cert.pem" "${CERTS_FOLDER}/chain.pem" >"${CERTS_FOLDER}/fullchain.pem" || {
    echo "ERROR: Failed to create fullchain.pem"
    exit 65
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
  echo "INFO: Certificate converted to PEM formats successfully."
}

# Authenticate and get an access token from Azure
if ! TOKEN=$(curl -X POST -s --max-time 30 -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=${AZURE_CLIENT_ID}&client_secret=${AZURE_CLIENT_SECRET}&resource=https://vault.azure.net" \
  "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/token" | jq -r '.access_token') || [ -z "${TOKEN}" ] || [ "${TOKEN}" = "null" ]; then
  printf -- '%s\n' \
    "ERROR/${SCRIPTNAME}: Failed to obtain access token from Azure. Make sure that the credentials are correct and not expired."
  exit 65
fi
printf -- "Access Token obtained successfully.\n"

# Fetch certificate properties from Key Vault
echo "INFO: Fetching certificate properties from Azure Key Vault..."
CERT_URL="https://${VAULT_NAME}.vault.azure.net/certificates/${CERT_NAME}/?api-version=${AZURE_API_VERSION}"
if ! CERT_PROPERTIES=$(curl -s --max-time 30 -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  "${CERT_URL}"); then
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
BASE64_PADDED="${BASE64_STANDARD}$(printf '%*s' $(((4 - ${#BASE64_STANDARD} % 4) % 4)) '' | tr ' ' '=')"

# Convert base64 x5t to binary and then to hex
DECODING=$(echo "${BASE64_PADDED}" | base64 --decode | xxd -p | tr -d '\n')
KEYVAULT_CERT_THUMBPRINT="${DECODING}"

echo "Azure Key Vault Certificate Thumbprint: ${KEYVAULT_CERT_THUMBPRINT}"

# Determine certificate ID for certificate name in Synology
CERTINFO_FILE="/usr/syno/etc/certificate/_archive/INFO"
if [ ! -f "${CERTINFO_FILE}" ]; then
  echo "ERROR: Certificate info file not found at ${CERTINFO_FILE}"
  exit 73
fi

CERTID="$(jq -r --arg desc "${CERT_NAME}" 'to_entries[] | select(.value.desc == $desc) | .key' "${CERTINFO_FILE}")"

if [ -z "${CERTID}" ]; then
  echo "WARNING/${SCRIPTNAME}: Certificate '${CERT_NAME}' does not exist on the Synology. Importing from Azure Key Vault as a new certificate."

  # Fetch and convert new certificates
  fetch_certs
  convert_certs

  echo "INFO: Importing new certificate '${CERT_NAME}' into Synology DSM..."
  RESULT="$(/usr/syno/bin/synowebapi --exec-fastwebapi \
    "api=SYNO.Core.Certificate" \
    "method=import" \
    "version=1" \
    "key_tmp=\"${CERTS_FOLDER}/privkey.pem\"" \
    "cert_tmp=\"${CERTS_FOLDER}/cert.pem\"" \
    "inter_cert_tmp=\"${CERTS_FOLDER}/chain.pem\"" \
    "desc=\"${CERT_NAME}\"")"

  # Verify import success
  SUCCESS="$(printf -- '%s' "${RESULT}" | /usr/bin/jq -r '.success')"
  if [ "${SUCCESS}" != 'true' ]; then
    ERROR_CODE="$(printf -- '%s' "${RESULT}" | /usr/bin/jq -r '.error.code')"
    printf -- "ERROR/%s: Certificate import failed with error code %s\n" "${SCRIPTNAME}" "${ERROR_CODE}"
    exit 73
  fi

  echo "INFO: New certificate imported successfully."
  # Restart services to apply the new certificate
  echo "INFO: Restarting services to apply the new certificate..."
  restart_services
else
  # Get the current certificate's thumbprint from Synology
  SYNO_CERTS_FOLDER="${SYNO_CERTS_BASE_FOLDER}/${CERTID}"
  CERT_FILE="${SYNO_CERTS_FOLDER}/cert.pem"

  if [ ! -f "${CERT_FILE}" ]; then
    echo "ERROR: Certificate file not found at ${CERT_FILE}"
    exit 73
  fi
  CURRENT_CERT_THUMBPRINT="$(calculate_cert_thumbprint "${CERT_FILE}")"
  echo "Current Syno Certificate Thumbprint: ${CURRENT_CERT_THUMBPRINT}"

  if compare_cert_thumbprints "${CURRENT_CERT_THUMBPRINT}" "${KEYVAULT_CERT_THUMBPRINT}"; then
    echo "INFO: Certificate is up-to-date (Thumbprints match). No action required."
    if [ ! -f "${CERTS_FOLDER}/${CERT_NAME}.pfx" ]; then
      fetch_certs
      convert_certs
    fi
    exit 0
  else

    echo "INFO: Certificate is outdated (Thumbprints do not match). Updating certificate..."
    echo "Synology Certificate ID: ${CERTID}"

    # Check if the certificate is the default
    CERT_DEFAULT_FLAG=$(jq -r --arg id "${CERTID}" \
      '.[$id] | select(.is_default == true)' "${SYNO_CERTS_BASE_FOLDER}/INFO")

    if [ -n "${CERT_DEFAULT_FLAG}" ]; then
      echo "INFO: Current certificate is the default. Will set the new certificate as default."
      AS_DEFAULT=true
    else
      echo "INFO: Current certificate is NOT the default."
      AS_DEFAULT=false
    fi

    # Fetch and Convert New Certificates
    fetch_certs
    convert_certs

    # Verify new certificate files exist
    if [ ! -f "${CERTS_FOLDER}/cert.pem" ] || [ ! -f "${CERTS_FOLDER}/privkey.pem" ] || [ ! -f "${CERTS_FOLDER}/chain.pem" ]; then
      printf -- '%s\n' "ERROR/${SCRIPTNAME}: New certificate files not ready"
      exit 73
    fi

    if [ "${RENEWAL_METHOD}" = "api" ]; then
      renew_cert_api
    else
      renew_cert_file
    fi

    # Restart Services to Apply New Certificate
    echo "INFO: Restarting services to apply the new certificate..."
    restart_services
  fi
fi
echo "INFO: Certificate operation completed successfully."
printf -- '%s\n' "${RESULT}"

echo "Certificate operation completed successfully."

# Cleanup temporary certificate folder
trap 'rm -rf "${CERTS_FOLDER}"' EXIT
