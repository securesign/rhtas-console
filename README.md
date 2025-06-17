# RHTAS Console

The RHTAS Console is a Go-based RESTful API server, providing functionality for signing and verifying software artifacts using Cosign, interacting with Sigstore's Rekor transparency log, and managing trust configurations with TUF and Fulcio. This repository serves as the backend for the RHTAS Console application, with plans to potentially add a frontend in the future.

## Features

- **Artifact management**: Sign and verify artifacts (e.g., container images, files, SBOMs) using Cosign.
- **Rekor integration**: Retrieve transparency log entries and public keys from Rekor.
- **Trust configuration**: Get TUF targets and Fulcio certificate authorities for trust policies.
- Built with [Chi](https://github.com/go-chi/chi), a lightweight Go router.
- OpenAPI-driven development with model generation via [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen).

## Installation

### Prerequisites

- [Go](https://golang.org/dl/) 1.16 or higher
- Access to a Rekor server (e.g., `https://rekor.sigstore.dev`)
- [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen) for generating models from OpenAPI specifications
   ```bash
   oapi-codegen -generate types,chi-server -package models openapi/rhtas-console.yaml > internal/models/models.go
   ```
- Optional: [rekor-cli](https://docs.sigstore.dev/rekor/installation/) and [cosign](https://docs.sigstore.dev/cosign/installation/) for testing Rekor and Cosign interactions

### Steps

1. **Clone the repository**:

   ```bash
   git clone https://github.com/securesign/rhtas-console.git
   cd rhtas-console
   ```

2. **Build the application**:

   ```bash
   make build
   ```

3. **Run the server**:

   ```bash
   ./bin/rhtas_console
   ```

   The backend server runs on `localhost:8080` by default. Configure the port via `--port` flag.

3. **Clean the project**:

   ```bash
   make clean
   ```

## Usage

### Running the Backend server

Start the server with:

```bash
./bin/rhtas_console
```

The API will be available at `http://localhost:8080` (or `https://api.rhtas.example.com` in production).

### API endpoints

The backend exposes the following RESTful endpoints, as defined in the OpenAPI specification:

| Method | Endpoint                          | Description                                      |
|--------|-----------------------------------|--------------------------------------------------|
| GET    | `/healthz`                           | Retrieves the current health status of the server. |
| GET    | `/swagger-ui`                        | Serves the Swagger User Interface. |
| GET    | `/rhtas-console.yaml`                | Returns the project OpenAPI spec file. |
| POST   | `/api/v1/artifacts/sign`             | Signs an artifact using Cosign.                  |
| POST   | `/api/v1/artifacts/verify`           | Verifies an artifact using Cosign.               |
| GET    | `/api/v1/artifacts/{artifact}/policies` | Retrieves policies and attestations for an artifact. |
| GET    | `/api/v1/artifacts/*`                | Retrieves metadata for a container image by full reference URI. |
| GET    | `/api/v1/rekor/entries/{uuid}`       | Retrieves a Rekor transparency log entry by UUID. |
| GET    | `/api/v1/rekor/public-key`           | Retrieves the Rekor public key in PEM format.     |
| GET    | `/api/v1/trust/config`               | Retrieves TUF targets and Fulcio certificate authorities. |

#### Example: Sign an artifact

To sign a container image using Cosign (keyless signing with OIDC token):

```bash
curl -X POST http://localhost:8080/api/v1/artifacts/sign \
  -H "Content-Type: application/json" \
  -d '{
    "artifact": "quay.io/example/app:latest",
    "artifactType": "container-image",
    "identityToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "annotations": {"env": "prod"}
  }'
```

Response:
```json
{
  "success": true,
  "signature": "MEUCIQC...",
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkq...\n-----END CERTIFICATE-----",
  "logEntry": {
    "uuid": "108e9186e8c5677a249f2ad46ab96976656298b3feb5e031777b9e1fa5c55aaf7e0115bee955ccaa",
    "integratedTime": 1747816420,
    "logIndex": 216249784
  }
}
```

#### Example: Retrieve a Rekor entry

To fetch a Rekor entry by UUID:

```bash
curl -X GET http://localhost:8080/api/v1/rekor/entries/108e9186e8c5677a249f2ad46ab96976656298b3feb5e031777b9e1fa5c55aaf7e0115bee955ccaa
```

Response:
```json
{
  "uuid": "108e9186e8c5677a249f2ad46ab96976656298b3feb5e031777b9e1fa5c55aaf7e0115bee955ccaa",
  "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIwMDliOTc3Y2Y3ZDYxMjIyZTRlMmY4OTY4NzE5M2JiM2IzOGQwYzFlNWM4MDNkYTE1ODk4OGIyZWU3ZDEzYTJmIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6InN0dWItc2lnbmF0dXJlLWNvbnRlbnQiLCJmb3JtYXQiOiJwZ3AiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6InN0dWItcHVibGljLWtleS1jb250ZW50In19fX0=",
  "integratedTime": 1747816420,
  "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
  "logIndex": 216249784,
  "verification": {
    "inclusionProof": {
      "checkpoint": "rekor.sigstore.dev - 1193050959916656506\n94345560\nmIq7oIDCYIfjP2wGrF+r+CTAAjyppyooQjGZtdh6XQc=\n\n— rekor.sigstore.dev wNI9ajBEAiBLqZTpbx5Ckvlvz/YXZ1aLk3q7TMBRtOa4wyYIPq/vRwIgTSo8mkOPZKfokHMePRNQ0XMAZG6Oc0KP0gKfqvzOLtA=\n",
      "hashes": [
        "fde82d05f63f2b3d1b8f4ed622517c941daeed51eeb7511664ec31ef289323e4",
        "1b14ee72fb681c74460d95fc4e04cd817d41e18696021107e92d3507938887b9",
        "bf7846e8e491286d402c29dee7f94bf648d65055cea5da961f9e6412436d62af"
      ],
      "logIndex": 94345522,
      "rootHash": "988abba080c26087e33f6c06ac5fabf824c0023ca9a72a28423199b5d87a5d07",
      "treeSize": 94345560
    },
    "signedEntryTimestamp": "MEUCIEl+0a7jUQRzS8Sq9WgBy9v4Hj9anYSBQpIHQvhLHK+6AiEAy/i+gmXl+a2ccSLLrzLc5saySQBAz67TwnVX9Et3tVE="
  }
}
```

## Dependencies

- [github.com/go-chi/chi/v5](https://github.com/go-chi/chi): Lightweight HTTP router for Go.
- [github.com/oapi-codegen/oapi-codegen](https://github.com/oapi-codegen/oapi-codegen): Generates Go types and server code from OpenAPI specifications.
- Standard Go libraries (`context`, `net/http`, etc.).

Run `go mod tidy` to install dependencies defined in `go.mod`.

## Development

### Project structure

```
rhtas-console/
├── cmd/
│   └── rhtas_console/
│       └── main.go         # Backend entry point
├── internal/
│   ├── api/                # API routes and handlers
│   │   ├── openapi/
│   │   │   └── rhtas-console.yaml  # OpenAPI specification
│   ├── models/             # Data models
│   └── services/           # Business logic (ArtifactService, RekorService, TrustService)
├── go.mod                  
└── go.sum
```

### Generating models

The `models` package is generated from the OpenAPI specification:

```bash
make generate-openapi
```

This generates Go types such as `RekorEntry`, `SignArtifactRequest`, `VerifyArtifactResponse`, and others.
