# RHTAS Console

The RHTAS Console is a Go-based RESTful API server, providing functionality for verifying software artifacts, interacting with Sigstore's Rekor transparency log, and managing trust configurations with TUF and Fulcio. This repository serves as the backend for the RHTAS Console application, with plans to potentially add a frontend in the future.

## Features

- **Artifact management**: Verify artifacts (e.g., container images, files, SBOMs).
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

### Steps

1. **Clone the repository**:

   ```bash
   git clone https://github.com/securesign/rhtas-console.git
   cd rhtas-console
   ```

2. **Run the server**:

   ```bash
   # Builds and runs the application, including deploying a MariaDB container.
   make run
   ```

   The backend server runs on `localhost:8080` by default. Configure the port via `--port` flag.

3. **Clean the project**:

   ```bash
   make clean
   ```

## Usage

### Using the Makefile
The project includes a Makefile to streamline common development tasks. Below are the key make targets available:

| Target                          | Description                                      |
|-----------------------------------|--------------------------------------------------|
| `make generate-openapi`      | Generates Go code from the OpenAPI specification (`rhtas-console.yaml`). |
| `make build`                 | Builds the `rhtas_console` binary, placing it in the `bin/` directory. |
| `make run`                   | Builds and runs the application, including deploying a MariaDB container. |
| `make deps`                  | Installs Go dependencies and the oapi-codegen tool.                  |
| `make deploy-mariadb`        | Starts a MariaDB container for the database with configured settings.               |
| `make stop-mariadb`          | Stops the running MariaDB container. |
| `make clean-mariadb`         | Removes the MariaDB container. |
| `make restart-mariadb`       | Restarts the MariaDB container by stopping and redeploying it. |
| `make clean`                 | Removes build artifacts and the MariaDB container.     |

### Running the Backend server

Start the server with:

```bash
make run
```

The API will be available at `http://localhost:8080` (or `https://api.rhtas.example.com` in production).

### API endpoints

The backend exposes the following RESTful endpoints, as defined in the OpenAPI specification:

| Method | Endpoint                          | Description                                      |
|--------|-----------------------------------|--------------------------------------------------|
| GET    | `/healthz`                                  | Retrieves the current health status of the server. |
| GET    | `/swagger-ui`                               | Serves the Swagger User Interface. |
| GET    | `/rhtas-console.yaml`                       | Returns the project OpenAPI spec file. |
| POST   | `/api/v1/artifacts/verify`                  | Verifies an artifact.               |
| GET    | `/api/v1/artifacts/{artifact}/policies`     | Retrieves policies and attestations for an artifact. |
| GET    | `/api/v1/artifacts/image`                   | Retrieves metadata for a container image by full reference URI. |
| GET    | `/api/v1/rekor/entries/{uuid}`              | Retrieves a Rekor transparency log entry by UUID. |
| GET    | `/api/v1/rekor/public-key`                  | Retrieves the Rekor public key in PEM format.     |
| GET    | `/api/v1/trust/config`                      | Retrieves Fulcio certificate authorities and Rekor transparency logs. |
| GET    | `/api/v1/trust/root-metadata-info`          | Retrieves the full history of TUF root metadata versions, including version, expiration date, and status (valid, expiring, expired). |
| GET    | `/api/v1/trust/targets`                     | Retrieves all TUF targets. |
| GET    | `/api/v1/trust/target`                      | Retrieves a specific TUF target. |
| GET    | `/api/v1/trust/targets/certificates`        | Retrieves certificates for TUF targets. |

#### Example: Verify an artifact

To verify an OCI image:


- Using `ociImage`:
```bash
curl -X POST http://localhost:8080/api/v1/artifacts/verify \
  -H "Content-Type: application/json" \
  -d '{
    "ociImage": "ttl.sh/rhtas/test-image:1h",
    "expectedOIDIssuer": "https://accounts.google.com",
    "expectedSAN": "jdoe@redhat.com",
    "tufRootURL": "https://tuf-repo-cdn.sigstore.dev"
  }'
```
- Using `bundle`:
```bash
# bundle.json: the file which contains the bundle
bundle_json=$(jq -c '.' bundle.json)
curl -X POST http://localhost:8080/api/v1/artifacts/verify \
  -H "Content-Type: application/json" \
  -d '{
  	"artifactDigest": "e128e0a064433c8d46f0467b149c70052fedbfa1f9e96ac22e3deefdc943e965",
    "expectedOIDIssuer": "https://accounts.google.com",
    "expectedSAN": "jdoe@redhat.com",
    "tufRootURL": "https://tuf-repo-cdn.sigstore.dev",
    "bundle": '"$bundle_json"'
  }'
```

Response:
```json
{
   "details":{
      "mediaType":"application/vnd.dev.sigstore.verificationresult+json;version=0.1",
      "signature":{
         "certificate":{
            "certificateIssuer":"CN=sigstore-intermediate,O=sigstore.dev",
            "issuer":"https://accounts.google.com",
            "subjectAlternativeName":"jdoe@redhat.com"
         }
      },
      "statement":{
         
      },
      "verifiedIdentity":{
         "issuer":{
            "issuer":"https://accounts.google.com"
         },
         "subjectAlternativeName":{
            "subjectAlternativeName":"jdoe@redhat.com"
         }
      },
      "verifiedTimestamps":[
         {
            "timestamp":"2025-10-14T09:05:19+02:00",
            "type":"Tlog",
            "uri":"https://rekor.sigstore.dev"
         }
      ]
   },
   "verified":true
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

This generates Go types such as `RekorEntry`, `VerifyArtifactResponse`, and others.
