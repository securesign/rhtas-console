#!/bin/bash

# Custom initialization goes here if needed.
# Runs inside the dev container after the container is created

################################################################################
# When using docker we will not be root inside the container
# the following steps are then required
################################################################################

go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest
