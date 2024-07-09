#!/bin/bash

# Function to print help
print_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --company-name              Company name for the project (required)"
    echo "  --create-gcp-project        Enable GCP project creation (default: false)"
    echo "  --assign-gcp-billing        Enable GCP billing assignment (default: false)"
    echo "  --billing-account-name      Billing account name (default: keephq)"
    echo "  --create-service-account    Enable service account creation (default: false)"
    echo "  --create-sql-instance       Enable MySQL instance creation (default: false)"
    echo "  --mysql-instance-name       MySQL instance name (default: keep-db)"
    echo "  --mysql-tier                MySQL tier (default: db-f1-micro)"
    echo "  --mysql-storage-size        MySQL storage size in GB (default: 10)"
    echo "  --mysql-sort-buffer-size    MySQL sort buffer size (default: 256000000)"
    echo "  --create-gcp-secrets        Enable GCP secrets creation (default: false)"
    echo "  --keep-default-username     Default Keep username (default: admin)"
    echo "  --keep-default-password     Default Keep password (default: admin)"
    echo "  --create-cloud-run-service  Enable Cloud Run service creation (default: false)"
    echo "  --create-cloudflare-dns     Enable Cloudflare DNS records creation (default: false)"
    echo "  --cloudflare-api-token      Cloudflare API token"
    echo "  --cloudflare-zone-id        Cloudflare zone ID"
    echo "  --deploy-to-vercel          Enable Vercel deployment (default: false)"
    echo "  --keep-ui-folder            Local path to the keep-ui folder"
    echo "  --configure-auth0           Enable Auth0 configuration (default: false)"
    echo "  --all                       Enable all steps"
    echo "  -h, --help                  Display this help and exit"
    echo ""
}

# Default values for options (disabled by default)
CREATE_GCP_PROJECT_ENABLED="false"
ASSIGN_GCP_BILLING_ENABLED="false"
BILLING_ACCOUNT_NAME="keephq"
CREATE_SERVICE_ACCOUNT_ENABLED="false"
CREATE_SQL_INSTANCE_ENABLED="false"
MYSQL_INSTANCE_NAME="keep-db"
MYSQL_TIER="db-f1-micro"
MYSQL_STORAGE_SIZE=10
MYSQL_SORT_BUFFER_SIZE=256000000
CREATE_GCP_SECRETS_ENABLED="false"
KEEP_DEFAULT_USERNAME="admin"
KEEP_DEFAULT_PASSWORD="admin"
CREATE_CLOUD_RUN_SERVICE_ENABLED="false"
CREATE_CLOUDFLARE_DNS_RECORDS="false"
CLOUDFLARE_API_TOKEN=${CLOUDFLARE_API_TOKEN:-""}
CLOUDFLARE_ZONE_ID=${CLOUDFLARE_ZONE_ID:-""}
DEPLOY_TO_VERCEL_ENABLED="false"
KEEP_UI_FOLDER=""
CONFIGURE_AUTH0_ENABLED="false"

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --company-name) COMPANY_NAME="$2"; PROJECT_NAME="keep-$2"; shift ;;
        --create-gcp-project) CREATE_GCP_PROJECT_ENABLED="true"; shift ;;
        --assign-gcp-billing) ASSIGN_GCP_BILLING_ENABLED="true"; shift ;;
        --billing-account-name) BILLING_ACCOUNT_NAME="$2"; shift ;;
        --create-service-account) CREATE_SERVICE_ACCOUNT_ENABLED="true"; shift ;;
        --create-sql-instance) CREATE_SQL_INSTANCE_ENABLED="true"; shift ;;
        --mysql-instance-name) MYSQL_INSTANCE_NAME="$2"; shift ;;
        --mysql-tier) MYSQL_TIER="$2"; shift ;;
        --mysql-storage-size) MYSQL_STORAGE_SIZE="$2"; shift ;;
        --mysql-sort-buffer-size) MYSQL_SORT_BUFFER_SIZE="$2"; shift ;;
        --create-gcp-secrets) CREATE_GCP_SECRETS_ENABLED="true"; shift ;;
        --keep-default-username) KEEP_DEFAULT_USERNAME="$2"; shift ;;
        --keep-default-password) KEEP_DEFAULT_PASSWORD="$2"; shift ;;
        --create-cloud-run-service) CREATE_CLOUD_RUN_SERVICE_ENABLED="true"; shift ;;
        --create-cloudflare-dns) CREATE_CLOUDFLARE_DNS_RECORDS="true"; shift ;;
        --cloudflare-api-token) CLOUDFLARE_API_TOKEN="$2"; shift ;;
        --cloudflare-zone-id) CLOUDFLARE_ZONE_ID="$2"; shift ;;
        --deploy-to-vercel) DEPLOY_TO_VERCEL_ENABLED="true"; shift ;;
        --keep-ui-folder) KEEP_UI_FOLDER="$2"; shift ;;
        --configure-auth0) CONFIGURE_AUTH0_ENABLED="true"; shift ;;
        --all)
            CREATE_GCP_PROJECT_ENABLED="true"
            ASSIGN_GCP_BILLING_ENABLED="true"
            CREATE_SERVICE_ACCOUNT_ENABLED="true"
            CREATE_SQL_INSTANCE_ENABLED="true"
            CREATE_GCP_SECRETS_ENABLED="true"
            CREATE_CLOUD_RUN_SERVICE_ENABLED="true"
            CREATE_CLOUDFLARE_DNS_RECORDS="true"
            DEPLOY_TO_VERCEL_ENABLED="true"
            CONFIGURE_AUTH0_ENABLED="true"
            ;;
        -h|--help) print_help; exit 0 ;;
        *) echo "Unknown parameter passed: $1"; print_help; exit 1 ;;
    esac
    shift
done

# Check for required parameters
if [ -z "$COMPANY_NAME" ]; then
    echo "Error: --company-name is required."
    print_help
    exit 1
fi

# Check if at least one step is enabled
if [ "$CREATE_GCP_PROJECT_ENABLED" == "false" ] && [ "$ASSIGN_GCP_BILLING_ENABLED" == "false" ] && \
   [ "$CREATE_SERVICE_ACCOUNT_ENABLED" == "false" ] && [ "$CREATE_SQL_INSTANCE_ENABLED" == "false" ] && \
   [ "$CREATE_GCP_SECRETS_ENABLED" == "false" ] && [ "$CREATE_CLOUD_RUN_SERVICE_ENABLED" == "false" ] && \
   [ "$CREATE_CLOUDFLARE_DNS_RECORDS" == "false" ] && [ "$DEPLOY_TO_VERCEL_ENABLED" == "false" ] & \
   [ "$CONFIGURE_AUTH0_ENABLED" == "false" ]; then
    echo "Error: At least one step must be enabled."
    print_help
    exit 1
fi

# Function to print logs
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Step 0: Check if gcloud is installed
check_gcloud_installed() {
    if ! command -v gcloud &> /dev/null; then
        log "gcloud could not be found. Please install the Google Cloud SDK before running this script."
        exit 1
    fi
}

# Step 0c: Check if curl and jq are installed
check_curl_jq_installed() {
    if ! command -v curl &> /dev/null; then
        log "curl could not be found. Please install curl before running this script."
        exit 1
    fi
    if ! command -v jq &> /dev/null; then
        log "jq could not be found. Please install jq before running this script."
        exit 1
    fi
}

# Function to check if auth0 CLI is installed
check_auth0_installed() {
    if ! command -v auth0 &> /dev/null; then
        log "auth0 CLI could not be found. Please install the Auth0 CLI before running this script."
        exit 1
    fi
}

check_cloudflare_api_token() {
    if [ "$CREATE_CLOUDFLARE_DNS_RECORDS" == "true" ]; then
        if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
            log "CLOUDFLARE_API_TOKEN is not set. Please set the Cloudflare API token before running this script."
            exit 1
        fi

        local RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type:application/json")
        local SUCCESS=$(echo "${RESPONSE}" | jq -r '.success')

        if [ "${SUCCESS}" == "false" ]; then
            log "Could not authenticate to cloudflare: $(echo "${RESPONSE}" | jq -r '.errors')"
            exit 1
        fi
    fi
}

# Function to check if vercel CLI is installed
check_vercel_installed() {
    if [ "$DEPLOY_TO_VERCEL_ENABLED" == "true" ]; then
        if ! command -v vercel &> /dev/null; then
            log "vercel CLI could not be found. Installing Vercel CLI... Run `npm install -g vercel`"
            exit 1
        fi
    fi
}

# Check for necessary installations
check_gcloud_installed
check_curl_jq_installed
check_cloudflare_api_token
check_vercel_installed

#############
# Functions #
#############

# Function to configure Auth0
configure_auth0() {
    log "Configuring Auth0..."

    check_auth0_installed

    read -p "Enter Auth0 tenant name (e.g., tenant-name.region.auth0.com): " AUTH0_TENANT_NAME

    log "Using Auth0 tenant: $AUTH0_TENANT_NAME"
    auth0 tenants use "$AUTH0_TENANT_NAME"
    if [ $? -eq 1 ]; then
        log "Could not find the tenant. Please execute 'auth0 login' and create or find the tenant."
        exit 1
    fi

    APP_EXISTS=$(auth0 apps list --json | jq -r '.[] | select(.name=="keep") | .client_id')

    if [ -z "$APP_EXISTS" ]; then
        log "Creating 'keep' app in Auth0..."
        APP_DETAILS=$(auth0 apps create --name keep --description keep --type regular --reveal-secrets --json)
        CLIENT_ID=$(echo "$APP_DETAILS" | jq -r '.client_id')
        CLIENT_SECRET=$(echo "$APP_DETAILS" | jq -r '.client_secret')
    else
        log "'keep' app already exists in Auth0."
        CLIENT_ID=$APP_EXISTS
        CLIENT_SECRET=$(auth0 apps list --json | jq -r '.[] | select(.name=="keep") | .client_secret')
    fi

    log "Auth0 Client ID: $CLIENT_ID"
    log "Auth0 Client Secret: $CLIENT_SECRET"

    auth0 apps update "$CLIENT_ID" --callbacks "https://$COMPANY_NAME.keephq.dev" --logout-urls "https://$COMPANY_NAME.keephq.dev" --origins "https://$COMPANY_NAME.keephq.dev"
    auth0 api patch "clients/$APP_EXISTS" --data "{\"initiate_login_uri\": \"https://$COMPANY_NAME.keephq.dev/api/auth/callback/auth0\"}"

    log "Updated 'keep' app in Auth0 with necessary URLs."
}

# Function to create DNS record in Cloudflare
create_dns_record() {
    local TYPE=$1
    local NAME=$2
    local CONTENT=$3
    local PROXY_STATUS=${4:-false}
    local TTL=${5:-1}  # Default to auto TTL

    log "Creating DNS record in Cloudflare: TYPE=${TYPE}, NAME=${NAME}, CONTENT=${CONTENT}, PROXY_STATUS=${PROXY_STATUS}, TTL=${TTL}"

    local DATA=$(cat <<EOF
{
    "type": "${TYPE}",
    "name": "${NAME}",
    "content": "${CONTENT}",
    "proxied": ${PROXY_STATUS},
    "ttl": ${TTL}
}
EOF
    )

    local RESPONSE=$(curl --silent --request POST \
        --url "https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records" \
        --header "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        --header "Content-Type: application/json" \
        --data "${DATA}")

    local SUCCESS=$(echo "${RESPONSE}" | jq -r '.success')

    if [ "${SUCCESS}" == "true" ]; then
        log "DNS record created successfully: ${NAME}"
    else
        log "Failed to create DNS record: $(echo "${RESPONSE}" | jq -r '.errors')"
    fi
}

create_gcp_env() {
    log "Starting GCP Environment creation for project $PROJECT_NAME..."

    # Check if GCP project already exists
    EXISTING_PROJECT=$(gcloud projects list --filter="name:${PROJECT_NAME}" --format="value(name)")

    if [ -n "$EXISTING_PROJECT" ]; then
        log "GCP project ${PROJECT_NAME} already exists. Skipping creation."
    else
        log "Creating GCP project ${PROJECT_NAME}..."
        gcloud projects create "${PROJECT_NAME}" --set-as-default
        # Add more GCP setup commands as needed
        log "GCP project ${PROJECT_NAME} created successfully."
    fi
}

enable_compute_engine_api() {
    log "Checking if Compute Engine API is enabled..."

    COMPUTE_ENGINE_API_ENABLED=$(gcloud services list --enabled --filter="name:compute.googleapis.com" --format="value(name)")
    if [ -z "$COMPUTE_ENGINE_API_ENABLED" ]; then
        log "Compute Engine API is not enabled. Enabling Compute Engine API..."
        gcloud services enable compute.googleapis.com --project="${PROJECT_NAME}"
        log "Compute Engine API enabled successfully."
    else
        log "Compute Engine API is already enabled."
    fi
}

connect_billing_account() {
    log "Connecting GCP project ${PROJECT_NAME} to billing account ${BILLING_ACCOUNT_NAME}..."
    # tb: I opened https://issuetracker.google.com/issues/350764038 but the issue was capital NAME vs name (wtf? :X)
    BILLING_ACCOUNT_ID=$(gcloud beta billing accounts list --filter="NAME:${BILLING_ACCOUNT_NAME}" --format="value(name)")

    if [ -z "$BILLING_ACCOUNT_ID" ]; then
        log "Billing account ${BILLING_ACCOUNT_NAME} not found. Please check the billing account name and try again."
        exit 1
    fi

    # Check if the project is already linked to a billing account
    CURRENT_BILLING_ACCOUNT=$(gcloud beta billing projects describe "${PROJECT_NAME}" --format="value(billingAccountName)")

    if [ "$CURRENT_BILLING_ACCOUNT" == "billingAccounts/$BILLING_ACCOUNT_ID" ]; then
        log "GCP project ${PROJECT_NAME} is already connected to billing account ${BILLING_ACCOUNT_NAME}. Skipping connection."
    else
        log "Linking GCP project ${PROJECT_NAME} to billing account ${BILLING_ACCOUNT_NAME}..."
        gcloud beta billing projects link "${PROJECT_NAME}" --billing-account="${BILLING_ACCOUNT_ID}"
        log "GCP project ${PROJECT_NAME} connected to billing account ${BILLING_ACCOUNT_NAME} successfully."
    fi
}

create_service_account() {
    log "Creating service account ‘keep-api’ for project $PROJECT_NAME..."
    # Check if service account already exists
    EXISTING_SERVICE_ACCOUNT=$(gcloud iam service-accounts list --filter="name:keep-api" --format="value(email)" --project="${PROJECT_NAME}")

    if [ -n "$EXISTING_SERVICE_ACCOUNT" ]; then
        log "Service account 'keep-api' already exists. Skipping creation."
    else
        log "Creating service account 'keep-api'..."
        gcloud iam service-accounts create keep-api --project="${PROJECT_NAME}" --display-name="keep-api"

        # Assign roles to the service account
        gcloud projects add-iam-policy-binding "${PROJECT_NAME}" --member="serviceAccount:keep-api@${PROJECT_NAME}.iam.gserviceaccount.com" --role="roles/cloudsql.client"
        gcloud projects add-iam-policy-binding "${PROJECT_NAME}" --member="serviceAccount:keep-api@${PROJECT_NAME}.iam.gserviceaccount.com" --role="roles/cloudsql.user"
        gcloud projects add-iam-policy-binding "${PROJECT_NAME}" --member="serviceAccount:keep-api@${PROJECT_NAME}.iam.gserviceaccount.com" --role="roles/secretmanager.admin"
        gcloud projects add-iam-policy-binding "${PROJECT_NAME}" --member="serviceAccount:keep-api@${PROJECT_NAME}.iam.gserviceaccount.com" --role="roles/storage.admin"

        log "Service account 'keep-api' created and roles assigned successfully."
    fi
}

# Function to check if database flags are set
check_database_flags() {
    CURRENT_FLAGS=$(gcloud sql instances describe "${MYSQL_INSTANCE_NAME}" --project="${PROJECT_NAME}" --format="json(settings.databaseFlags)")

    SORT_BUFFER_SIZE_SET=$(echo "${CURRENT_FLAGS}" | jq -r '.[].databaseFlags[] | select(.name == "sort_buffer_size") | .value')
    CLOUDSQL_IAM_AUTH_SET=$(echo "${CURRENT_FLAGS}" | jq -r '.[].databaseFlags[] | select(.name == "cloudsql_iam_authentication") | .value')

    log "Current MySQL flags: sort_buffer_size=${SORT_BUFFER_SIZE_SET}, cloudsql_iam_authentication=${CLOUDSQL_IAM_AUTH_SET}"

    if [[ "${SORT_BUFFER_SIZE_SET}" == "256000000" ]] && [[ "${CLOUDSQL_IAM_AUTH_SET}" == "on" ]]; then
        return 1
    else
        return 0
    fi
}

create_sql_instance() {
log "Creating MySQL instance ‘${MYSQL_INSTANCE_NAME}’ in project $PROJECT_NAME..."
# Check if the MySQL instance already exists
EXISTING_INSTANCE=$(gcloud sql instances list --filter="name:${MYSQL_INSTANCE_NAME}" --format="value(name)" --project="${PROJECT_NAME}")
local MYSQL_ROOT_PASSWORD=$(openssl rand -base64 12)

if [ -n "$EXISTING_INSTANCE" ]; then
    log "MySQL instance '${MYSQL_INSTANCE_NAME}' already exists, setting root password"

    if check_database_flags; then
        log "Setting MySQL flag 'sort_buffer_size' to ${MYSQL_SORT_BUFFER_SIZE} and 'cloudsql_iam_authentication' to on..."
        gcloud sql instances patch "${MYSQL_INSTANCE_NAME}" \
            --project="${PROJECT_NAME}" \
            --database-flags sort_buffer_size="${MYSQL_SORT_BUFFER_SIZE}",cloudsql_iam_authentication=on
    else
        log "MySQL flags are already set. Skipping update."
    fi

    gcloud sql users set-password root --host=% --instance="${MYSQL_INSTANCE_NAME}" --password="${MYSQL_ROOT_PASSWORD}" --project="${PROJECT_NAME}"
    else
        log "Creating MySQL instance '${MYSQL_INSTANCE_NAME}'..."
        gcloud sql instances create "${MYSQL_INSTANCE_NAME}" \
            --project="${PROJECT_NAME}" \
            --tier="${MYSQL_TIER}" \
            --storage-size="${MYSQL_STORAGE_SIZE}" \
            --database-version="MYSQL_8_0_26" \
            --root-password="${MYSQL_ROOT_PASSWORD}"
        log "Setting MySQL flag 'sort_buffer_size' to ${MYSQL_SORT_BUFFER_SIZE} and 'cloudsql_iam_authentication' to on..."
        gcloud sql instances patch "${MYSQL_INSTANCE_NAME}" \
            --project="${PROJECT_NAME}" \
            --database-flags sort_buffer_size="${MYSQL_SORT_BUFFER_SIZE}",cloudsql_iam_authentication=on
        log "MySQL instance '${MYSQL_INSTANCE_NAME}' created and configured successfully."
    fi

    log "Creating MySQL user for service account 'keep-api' in instance '${MYSQL_INSTANCE_NAME}'..."

    log "Adding a public IP address to MySQL instance '${MYSQL_INSTANCE_NAME}'..."

    gcloud sql users create "keep-api@${PROJECT_NAME}.iam.gserviceaccount.com" \
        --instance="${MYSQL_INSTANCE_NAME}" \
        --type=CLOUD_IAM_SERVICE_ACCOUNT \
        --project="${PROJECT_NAME}" \
        --quiet || log "MySQL user already exists."

    log "##################################################################################"
    log "Please use the following root password when prompted: ${MYSQL_ROOT_PASSWORD}"
    log "Then execute (copy & paste): "
    log "GRANT CREATE ON *.* TO 'keep-api'@'%' WITH GRANT OPTION; CREATE DATABASE keepdb; GRANT ALL PRIVILEGES ON keepdb.* TO 'keep-api'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES; QUIT;"
    log "#################################################################################"
    gcloud sql connect "${MYSQL_INSTANCE_NAME}" --project="${PROJECT_NAME}" --user=root

    log "Created MySQL user for service account 'keep-api' in instance '${MYSQL_INSTANCE_NAME}'..."
}

create_gcp_secrets() {
    log "Creating Keep GCP secrets..."
    gcloud services enable secretmanager.googleapis.com --project="${PROJECT_NAME}"

    # Create the KEEP_DEFAULT_USERNAME secret
    if gcloud secrets describe keep-default-username --project="${PROJECT_NAME}" &> /dev/null; then
        log "Secret keep-default-username already exists. Skipping creation."
    else
        echo -n "${KEEP_DEFAULT_USERNAME}" | gcloud secrets create keep-default-username --data-file=- --project="${PROJECT_NAME}"
        log "Secret keep-default-username created successfully."
    fi

    # Create the KEEP_DEFAULT_PASSWORD secret
    if gcloud secrets describe keep-default-password --project="${PROJECT_NAME}" &> /dev/null; then
        log "Secret keep-default-password already exists. Skipping creation."
    else
        echo -n "${KEEP_DEFAULT_PASSWORD}" | gcloud secrets create keep-default-password --data-file=- --project="${PROJECT_NAME}"
        log "Secret keep-default-password created successfully."
    fi

    # Create the KEEP_JWT_SECRET secret
    if gcloud secrets describe keep-jwt-secret --project="${PROJECT_NAME}" &> /dev/null; then
        log "Secret keep-jwt-secret already exists. Skipping creation."
    else
        echo -n "${KEEP_JWT_SECRET}" | gcloud secrets create keep-jwt-secret --data-file=- --project="${PROJECT_NAME}"
        log "Secret keep-jwt-secret created successfully."
    fi
}

enable_cloud_run_api() {
    log "Checking if Cloud Run API is enabled..."
    CLOUD_RUN_API_ENABLED=$(gcloud services list --enabled --filter="name:run.googleapis.com" --format="value(name)")

    if [ -z "$CLOUD_RUN_API_ENABLED" ]; then
        log "Cloud Run API is not enabled. Enabling Cloud Run API..."
        gcloud services enable run.googleapis.com --project="${PROJECT_NAME}"
        log "Cloud Run API enabled successfully."
    else
        log "Cloud Run API is already enabled."
    fi
}

create_cloud_run_service() {
    log "Creating Cloud Run service ‘${SERVICE_NAME}’..."
    # Check if the region is us-central1, if not find the region
    REGION=$(gcloud run regions list --format="value(locationId)" | grep -m 1 "us-central1")
    if [ -z "$REGION" ]; then
        REGION=$(gcloud run regions list --format="value(locationId)" | head -n 1)
        log "Region 'us-central1’ is not available. Using default region ‘${REGION}’."
    else
    log "Using region ‘us-central1’."
    fi
    # Deploy the Cloud Run service
    gcloud run deploy "${SERVICE_NAME}" \
        --image="us-central1-docker.pkg.dev/keephq/keep/keep-api:latest" \
        --region="${REGION}" \
        --cpu=4 \
        --memory=4Gi \
        --min-instances=1 \
        --platform=managed \
        --service-account="keep-api@${PROJECT_NAME}.iam.gserviceaccount.com" \
        --allow-unauthenticated \
        --add-cloudsql-instances="${DB_CONNECTION_NAME}" \
        --set-env-vars AUTH_TYPE="${AUTH_TYPE}",SERVICE_NAME="${SERVICE_NAME}",KEEP_API_URL="https://${KEEP_API_URL}",GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT}",CLOUD_TRACE_ENABLED="${CLOUD_TRACE_ENABLED}",SECRET_MANAGER_TYPE="${SECRET_MANAGER_TYPE}",STORAGE_MANAGER_TYPE="${STORAGE_MANAGER_TYPE}",PUSHER_DISABLED="${PUSHER_DISABLED}",OTEL_TRACES_SAMPLER="${OTEL_TRACES_SAMPLER}",OTEL_TRACES_SAMPLER_ARG="${OTEL_TRACES_SAMPLER_ARG}",DB_CONNECTION_NAME="${DB_CONNECTION_NAME}" \
        --update-secrets KEEP_DEFAULT_USERNAME=keep-default-username:latest \
        --update-secrets KEEP_DEFAULT_PASSWORD=keep-default-password:latest \
        --update-secrets KEEP_JWT_SECRET=keep-jwt-secret:latest
        # --update-secrets PUSHER_APP_ID=pusher-app-id:latest \
        # --update-secrets PUSHER_APP_KEY=pusher-app-key:latest \
        # --update-secrets PUSHER_APP_SECRET=pusher-app-secret:latest

    if [ "$CREATE_CLOUDFLARE_DNS_RECORDS" == "true" ]; then
        create_dns_record "CNAME" "api.$COMPANY_NAME" "ghs.googlehosted.com."
        gcloud beta run domain-mappings create \
            --service="${SERVICE_NAME}" \
            --domain="${KEEP_API_URL}" \
            --project="${PROJECT_NAME}" \
            --region="${REGION}" \
            --quiet
    fi

    log "Cloud Run service '${SERVICE_NAME}' created and configured successfully."
}

deploy_keep_ui_to_vercel() {
    log "Deploying keep-ui to Vercel..."

    NEXT_AUTH_SECRET=$(openssl rand -base64 32)

    local CLEANUP="false"
    if [ -n "$KEEP_UI_FOLDER" ]; then
        log "Using existing keep-ui folder: $KEEP_UI_FOLDER"
    else
        log "Cloning keep-ui repository to a temporary directory..."
        KEEP_UI_FOLDER=$(mktemp -d)
        CLEANUP="true"
        git clone https://github.com/keephq/keep.git "$KEEP_UI_FOLDER"
        KEEP_UI_FOLDER="$KEEP_UI_FOLDER/keep-ui"
        log "Using keep-ui folder: $KEEP_UI_FOLDER"
    fi

    vercel switch KeepHQ

    pushd "${KEEP_UI_FOLDER}"

    log "##################################################"
    log "Running vercel command. Please follow the prompts..."
    log " Please note, when prompted the following, please select no (n)"
    log "---> Found project “keephq/keep-ui”. Link to it? [Y/n]"
    log "---> Link to different existing project? [Y/n]"
    log "##################################################"
    vercel --prod
    echo "SINGLE_TENANT" | vercel env add AUTH_TYPE production
    echo "${NEXT_AUTH_SECRET}" | vercel env add NEXTAUTH_SECRET production
    echo "api.$COMPANY_NAME.keephq.dev" | vercel env add API_URL production

    exit 1

    if [  "$CLEANUP" == "true"  ]; then
        log "Cleaning up temporary directory..."
        rm -rf "$KEEP_UI_FOLDER"
    fi

    # log "Setting up custom domain for Vercel deployment..."

    # CUSTOM_DOMAIN="frontend.${COMPANY_NAME}.keephq.dev"

    # # Add the custom domain to the Vercel project
    # vercel domains add "${CUSTOM_DOMAIN}"
    # vercel domains verify "${CUSTOM_DOMAIN}"

    # log "Deployment to Vercel completed."
}

#########################
# Main script execution
#########################

# Step 1: Create GCP Environment

if [ "$CREATE_GCP_PROJECT_ENABLED" == "true" ]; then
    create_gcp_env
else
    log "GCP Environment creation skipped."
fi

# Step 2: Connect GCP Project to Billing Account

if [ "$ASSIGN_GCP_BILLING_ENABLED" == "true" ]; then
    connect_billing_account
else
    log "Billing account connection skipped."
fi

# Step 3: Create Service Account for keep-api

if [ "$CREATE_SERVICE_ACCOUNT_ENABLED" == "true" ]; then
    create_service_account
else
    log "Service account creation skipped."
fi

# Step 4: Create MySQL Instance in Cloud SQL

if [ "$CREATE_SQL_INSTANCE_ENABLED" == "true" ]; then
    enable_compute_engine_api
    create_sql_instance
else
    log "MySQL instance creation skipped."
fi

# Step 5: Create Keep GCP Secrets

if [ "$CREATE_GCP_SECRETS_ENABLED" == "true" ]; then
    create_gcp_secrets
else
    log "GCP secrets creation skipped."
fi

# Step 6a: Check if Cloud Run API is enabled

# Step 6b: Create Cloud Run Service

if [ "$CREATE_CLOUD_RUN_SERVICE_ENABLED" == "true" ]; then
    enable_cloud_run_api
    create_cloud_run_service
else
    log "Cloud Run service creation skipped."
fi

# Step 7:
if [ "$DEPLOY_TO_VERCEL_ENABLED" == "true" ]; then
    deploy_keep_ui_to_vercel
else
    log "Deploy to Vercel skipped."
fi

# Call the configure_auth0 function if enabled
if [ "$CONFIGURE_AUTH0_ENABLED" == "true" ]; then
    configure_auth0
fi
