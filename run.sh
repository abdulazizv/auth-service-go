#!/bin/bash

# Print colorful messages
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Generating Swagger documentation...${NC}"
swag init -g cmd/server/main.go

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Swagger documentation generated successfully!${NC}"
    echo -e "${BLUE}Starting the server...${NC}"
    go run cmd/server/main.go
else
    echo -e "\033[0;31mFailed to generate Swagger documentation. Please check the errors above.${NC}"
    exit 1
fi