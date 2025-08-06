#!/bin/bash

APP_NAME="phishing-app"
RESOURCE_GROUP="malloc-phishing"
ACR_NAME="mallocsecurityar"
IMAGE_TAG=$(date +%s)  # Use current timestamp as a unique tag

# Exit immediately if any command fails
set -e

# Login to Azure Container Registry
echo "Logging into ACR..."
az acr login --name $ACR_NAME

# Build and push the Docker image for AMD64 (required by Azure Container Apps)
echo "Building and pushing Docker image..."
docker buildx build \
  --platform linux/amd64 \
  -t $ACR_NAME.azurecr.io/$APP_NAME:$IMAGE_TAG \
  --push .  # Note: --push combines build and push in one command

# Deploy to Azure Container App
echo "Deploying to Azure Container App..."
az containerapp update \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --image $ACR_NAME.azurecr.io/$APP_NAME:$IMAGE_TAG

# Output the deployed image
echo "Successfully deployed: $ACR_NAME.azurecr.io/$APP_NAME:$IMAGE_TAG"