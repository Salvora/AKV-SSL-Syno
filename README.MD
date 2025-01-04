# AKV-SSL-Syno

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)

Automate the renewal and replacement of SSL certificates on Synology NAS using Azure Key Vault.

## Version

**Current Version:** 1.0.0  
**Release Date:** 2023-10-01

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)

## Description

The `AKV-SSL-Syno` script automates the process of renewing SSL certificates stored in Azure Key Vault and replacing them on your Synology NAS. This ensures that your services remain secure with up-to-date certificates without manual intervention.

## Features

- **Automatic Renewal:** Checks and renews SSL certificates before they expire.
- **Secure Storage:** Integrates with Azure Key Vault for secure certificate management.
- **Seamless Replacement:** Automatically replaces old certificates on Synology NAS without downtime.
- **Logging:** Provides detailed logs for monitoring and troubleshooting.
- **Customizable:** Easily configurable to fit different environments and requirements.

## Prerequisites

- **Synology NAS** with administrative access.
- **Azure Key Vault** containing your SSL certificates.
- **Shell Access** to your Synology NAS (e.g., via SSH).
- **Synowebapi** tool installed on your Synology NAS.
- **Git** installed on your local machine.
- **Bash Shell** for running the script.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/your-username/AKV-SSL-Syno.git
   ```

2. **Navigate to the Script Directory:**

   ```bash
   cd AKV-SSL-Syno/Shell Scripts
   ```

3. **Make the Script Executable:**

   ```bash
   chmod +x Azure-SSL-Renew.sh
   ```

4. **Install Dependencies:**

   Ensure that all necessary dependencies are installed on your Synology NAS. This may include tools like `openssl` and `jq`.

   ```bash
   sudo apt-get update
   sudo apt-get install openssl jq -y
   ```

5. **Copy the Example Credentials File**

   - Create a copy of the `credentials.env.example` file and name it `credentials.env`.
   - Enter your credentials.

   ```bash
   cp credentials.env.example credentials.env
   ```

## Usage

Run the script with the following command:

```bash
./Syno-Azure-SSL-Renew.sh <Azure_Key_Vault_Name> <Azure_Certificate_Name>
```
