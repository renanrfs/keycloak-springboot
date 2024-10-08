#!/bin/bash

docker run -p 8090:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
    -v $(pwd)/realm:/opt/keycloak/data/import \
    quay.io/keycloak/keycloak:24.0.4 \
    start-dev --import-realm
