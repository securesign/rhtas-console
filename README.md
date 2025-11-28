# RHTAS Console

The RHTAS Console is a Go-based RESTful API server, providing functionality for verifying software artifacts, interacting with Rekor transparency log, and managing trust configurations with TUF and Fulcio. This repository serves as the backend for the RHTAS Console application, which now includes a [frontend interface](https://github.com/securesign/rhtas-console-ui).

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


```bash
curl -X POST http://localhost:8080/api/v1/artifacts/verify \
  -H "Content-Type: application/json" \
  -d '{
    "ociImage": "ttl.sh/rhtas/test-image:1h",
    "tufRootURL": "https://tuf-repo-cdn.sigstore.dev"
  }'
```
Response:
<details>
<summary>Full verification result – click to expand</summary>

```json
{
   "artifact":{
      "digest":"sha256:26228cd4256c4370c51b4a25cfd8636cb18b1ef34ae51f7152fc05c803c41aa7",
      "image":"ttl.sh/rhtas/console-test-image",
      "metadata":{
         "created":"2025-11-21T13:48:39.182642034Z",
         "labels":{
            "io.buildah.version":"1.41.5"
         },
         "mediaType":"application/vnd.oci.image.manifest.v1+json",
         "size":414
      },
      "registry":"https://ttl.sh"
   },
   "attestations":[
      {
         "attestationStatus":{
            "attestation":"verified",
            "chain":"verified",
            "rekor":"verified"
         },
         "certificateChain":[
            {
               "isCa":true,
               "issuer":"CN=sigstore,O=sigstore.dev",
               "notAfter":"2031-10-05T13:56:58Z",
               "notBefore":"2022-04-13T20:06:15Z",
               "pem":"-----BEGIN CERTIFICATE-----\nMIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C\nAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7\n7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS\n0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB\nBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp\nKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI\nzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR\nnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP\nmygUY7Ii2zbdCdliiow=\n-----END CERTIFICATE-----\n",
               "role":"intermediate",
               "sans":null,
               "serialNumber":"4144239514159843648641554259375047022727364004",
               "subject":"CN=sigstore-intermediate,O=sigstore.dev"
            },
            {
               "isCa":true,
               "issuer":"CN=sigstore,O=sigstore.dev",
               "notAfter":"2031-10-05T13:56:58Z",
               "notBefore":"2021-10-07T13:56:59Z",
               "pem":"-----BEGIN CERTIFICATE-----\nMIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7\nXeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex\nX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j\nYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY\nwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ\nKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM\nWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9\nTNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ\n-----END CERTIFICATE-----\n",
               "role":"root",
               "sans":null,
               "serialNumber":"4065443592980134080728682916587645234900384766",
               "subject":"CN=sigstore,O=sigstore.dev"
            }
         ],
         "digest":"sha256:2fa626c007df213bbe4c86355fd44a2fca834416d7c3f66c1f2ea9dae963d371",
         "id":0,
         "predicateType":"https://example.com/attestations/build",
         "rawBundleJson":"{\n  \"mediaType\": \"application/vnd.dev.sigstore.bundle+json;version=0.1\",\n  \"verificationMaterial\": {\n    \"x509CertificateChain\": {\n      \"certificates\": [\n        {\n          \"rawBytes\": \"MIICyzCCAlGgAwIBAgIUaaW8kM/EEsciH7ULccE9r9xjkH4wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUxMTI0MTI1NDMzWhcNMjUxMTI0MTMwNDMzWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiymFVHOUqVDv/RM7cnUXW/Qx1mzTQUwxI6Cy3BiLtf7xIt3WZSAVW939bQY72JP4XySL+l4IwAsgH6mmnMtC4aOCAXAwggFsMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUoHTu2FND+hHHCZUQ7U/HpjGEF+8wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIAYDVR0RAQH/BBYwFIESZmdoYW5taUByZWRoYXQuY29tMCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgEEAYO/MAEIBB0MG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABmrXuH+AAAAQDAEcwRQIhAOqTTmtILU15KjMFxHZOB5Pl1+QTy0918EgObl0OG6e1AiA0LBJ1eFA2L1gO+8eqil5a/vYoUPIjVPmCDWWMtf7jUjAKBggqhkjOPQQDAwNoADBlAjBZGceXBBLychZ41eJv0dg/dkJ7/4qAHclevqn3aTD4ZyKQjC+UQAzySTHhXPdXmtMCMQDkhDLTavdpV6/hW500hhjgUwT+tEOIC8wxOkBbcarSqg9t2Re5kmMJOcOcKE5oxv0=\"\n        }\n      ]\n    },\n    \"tlogEntries\": [\n      {\n        \"logIndex\": \"720620781\",\n        \"logId\": {\n          \"keyId\": \"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=\"\n        },\n        \"kindVersion\": {\n          \"kind\": \"dsse\",\n          \"version\": \"0.0.1\"\n        },\n        \"integratedTime\": \"1763988873\",\n        \"inclusionPromise\": {\n          \"signedEntryTimestamp\": \"MEUCIBIMIi23C+k4nK+0v3gAMtI8+SWzuZY+irkr/zTok2VFAiEA3pLg9vZMVcZ9FpugGpQ0N+yYhVYutlb8S7obdNp2aPM=\"\n        },\n        \"canonicalizedBody\": \"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiMmZhNjI2YzAwN2RmMjEzYmJlNGM4NjM1NWZkNDRhMmZjYTgzNDQxNmQ3YzNmNjZjMWYyZWE5ZGFlOTYzZDM3MSJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjBiMWEwNjA1ODUyMjNiNzM3M2Q4ZTkwZTczMGIxNjM4MjBmZDQ5ZTMyY2U0OWE2ODVmNjFhYTk5Y2I4OGRmOGUifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVVQ0lRRHRIcXlNc1V3SUJMVTlBS0xHeEFRQUJFYXp3L2lwb3VXZVNQc28wNjNJbHdJZ1prZVkxTnRTVHdMejJUYVV5OHYrajhPQUU1cHBuM09FOHBnTWl4L244VVk9IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VONWVrTkRRV3hIWjBGM1NVSkJaMGxWWVdGWE9HdE5MMFZGYzJOcFNEZFZUR05qUlRseU9YaHFhMGcwZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwVmVFMVVTVEJOVkVreFRrUk5lbGRvWTA1TmFsVjRUVlJKTUUxVVRYZE9SRTE2VjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVnBlVzFHVmtoUFZYRldSSFl2VWswM1kyNVZXRmN2VVhneGJYcFVVVlYzZUVrMlEza0tNMEpwVEhSbU4zaEpkRE5YV2xOQlZsYzVNemxpVVZrM01rcFFORmg1VTB3cmJEUkpkMEZ6WjBnMmJXMXVUWFJETkdGUFEwRllRWGRuWjBaelRVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdSQ1owNVdTRkUwUlVablVWVnZTRlIxQ2pKR1RrUXJhRWhJUTFwVlVUZFZMMGh3YWtkRlJpczRkMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4VG1wd1MwWlhhWGhwTkZrS1drUTRkMGxCV1VSV1VqQlNRVkZJTDBKQ1dYZEdTVVZUV20xa2IxbFhOWFJoVlVKNVdsZFNiMWxZVVhWWk1qbDBUVU5yUjBOcGMwZEJVVkZDWnpjNGR3cEJVVVZGUnpKb01HUklRbnBQYVRoMldWZE9hbUl6Vm5Wa1NFMTFXakk1ZGxveWVHeE1iVTUyWWxSQmNrSm5iM0pDWjBWRlFWbFBMMDFCUlVsQ1FqQk5Da2N5YURCa1NFSjZUMms0ZGxsWFRtcGlNMVoxWkVoTmRWb3lPWFphTW5oc1RHMU9kbUpVUTBKcFoxbExTM2RaUWtKQlNGZGxVVWxGUVdkU09FSkliMEVLWlVGQ01rRk9NRGxOUjNKSGVIaEZlVmw0YTJWSVNteHVUbmRMYVZOc05qUXphbmwwTHpSbFMyTnZRWFpMWlRaUFFVRkJRbTF5V0hWSUswRkJRVUZSUkFwQlJXTjNVbEZKYUVGUGNWUlViWFJKVEZVeE5VdHFUVVo0U0ZwUFFqVlFiREVyVVZSNU1Ea3hPRVZuVDJKc01FOUhObVV4UVdsQk1FeENTakZsUmtFeUNrd3haMDhyT0dWeGFXdzFZUzkyV1c5VlVFbHFWbEJ0UTBSWFYwMTBaamRxVldwQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG05QlJFSnNRV3BDV2tkalpWZ0tRa0pNZVdOb1dqUXhaVXAyTUdSbkwyUnJTamN2TkhGQlNHTnNaWFp4YmpOaFZFUTBXbmxMVVdwREsxVlJRWHA1VTFSSWFGaFFaRmh0ZEUxRFRWRkVhd3BvUkV4VVlYWmtjRlkyTDJoWE5UQXdhR2hxWjFWM1ZDdDBSVTlKUXpoM2VFOXJRbUpqWVhKVGNXYzVkREpTWlRWcmJVMUtUMk5QWTB0Rk5XOTRkakE5Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzBLIn1dfX0=\"\n      }\n    ]\n  },\n  \"dsseEnvelope\": {\n    \"payload\": \"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2V4YW1wbGUuY29tL2F0dGVzdGF0aW9ucy9idWlsZCIsInN1YmplY3QiOlt7Im5hbWUiOiJ0dGwuc2gvcmh0YXMvY29uc29sZS10ZXN0LWltYWdlLTEiLCJkaWdlc3QiOnsic2hhMjU2IjoiMjYyMjhjZDQyNTZjNDM3MGM1MWI0YTI1Y2ZkODYzNmNiMThiMWVmMzRhZTUxZjcxNTJmYzA1YzgwM2M0MWFhNyJ9fV0sInByZWRpY2F0ZSI6eyJidWlsZFR5cGUiOiJtYW51YWwtdGVzdCIsImJ1aWxkZXIiOnsiaWQiOiJleGFtcGxlLWJ1aWxkZXIifSwibWV0YWRhdGEiOnsiYnVpbGRGaW5pc2hlZE9uIjoiMjAyNS0xMC0yMFQxNDo1MDozOSswMjowMCIsImJ1aWxkU3RhcnRlZE9uIjoiMjAyNS0xMC0yMFQxNDo1MDozOSswMjowMCJ9LCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9hdHRlc3RhdGlvbnMvYnVpbGQifX0=\",\n    \"payloadType\": \"application/vnd.in-toto+json\",\n    \"signatures\": [\n      {\n        \"sig\": \"MEUCIQDtHqyMsUwIBLU9AKLGxAQABEazw/ipouWeSPso063IlwIgZkeY1NtSTwLz2TaUy8v+j8OAE5ppn3OE8pgMix/n8UY=\"\n      }\n    ]\n  }\n}",
         "rawStatementJson":"{\n  \"type\": \"https://in-toto.io/Statement/v0.1\",\n  \"subject\": [\n    {\n      \"name\": \"ttl.sh/rhtas/console-test-image-1\",\n      \"digest\": {\n        \"sha256\": \"26228cd4256c4370c51b4a25cfd8636cb18b1ef34ae51f7152fc05c803c41aa7\"\n      }\n    }\n  ],\n  \"predicate_type\": \"https://example.com/attestations/build\",\n  \"predicate\": {\n    \"buildType\": \"manual-test\",\n    \"builder\": {\n      \"id\": \"example-builder\"\n    },\n    \"metadata\": {\n      \"buildFinishedOn\": \"2025-10-20T14:50:39+02:00\",\n      \"buildStartedOn\": \"2025-10-20T14:50:39+02:00\"\n    },\n    \"predicateType\": \"https://example.com/attestations/build\"\n  }\n}",
         "rekorEntry":{
            "canonicalized_body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiMmZhNjI2YzAwN2RmMjEzYmJlNGM4NjM1NWZkNDRhMmZjYTgzNDQxNmQ3YzNmNjZjMWYyZWE5ZGFlOTYzZDM3MSJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjBiMWEwNjA1ODUyMjNiNzM3M2Q4ZTkwZTczMGIxNjM4MjBmZDQ5ZTMyY2U0OWE2ODVmNjFhYTk5Y2I4OGRmOGUifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVVQ0lRRHRIcXlNc1V3SUJMVTlBS0xHeEFRQUJFYXp3L2lwb3VXZVNQc28wNjNJbHdJZ1prZVkxTnRTVHdMejJUYVV5OHYrajhPQUU1cHBuM09FOHBnTWl4L244VVk9IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VONWVrTkRRV3hIWjBGM1NVSkJaMGxWWVdGWE9HdE5MMFZGYzJOcFNEZFZUR05qUlRseU9YaHFhMGcwZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwVmVFMVVTVEJOVkVreFRrUk5lbGRvWTA1TmFsVjRUVlJKTUUxVVRYZE9SRTE2VjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVnBlVzFHVmtoUFZYRldSSFl2VWswM1kyNVZXRmN2VVhneGJYcFVVVlYzZUVrMlEza0tNMEpwVEhSbU4zaEpkRE5YV2xOQlZsYzVNemxpVVZrM01rcFFORmg1VTB3cmJEUkpkMEZ6WjBnMmJXMXVUWFJETkdGUFEwRllRWGRuWjBaelRVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdSQ1owNVdTRkUwUlVablVWVnZTRlIxQ2pKR1RrUXJhRWhJUTFwVlVUZFZMMGh3YWtkRlJpczRkMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4VG1wd1MwWlhhWGhwTkZrS1drUTRkMGxCV1VSV1VqQlNRVkZJTDBKQ1dYZEdTVVZUV20xa2IxbFhOWFJoVlVKNVdsZFNiMWxZVVhWWk1qbDBUVU5yUjBOcGMwZEJVVkZDWnpjNGR3cEJVVVZGUnpKb01HUklRbnBQYVRoMldWZE9hbUl6Vm5Wa1NFMTFXakk1ZGxveWVHeE1iVTUyWWxSQmNrSm5iM0pDWjBWRlFWbFBMMDFCUlVsQ1FqQk5Da2N5YURCa1NFSjZUMms0ZGxsWFRtcGlNMVoxWkVoTmRWb3lPWFphTW5oc1RHMU9kbUpVUTBKcFoxbExTM2RaUWtKQlNGZGxVVWxGUVdkU09FSkliMEVLWlVGQ01rRk9NRGxOUjNKSGVIaEZlVmw0YTJWSVNteHVUbmRMYVZOc05qUXphbmwwTHpSbFMyTnZRWFpMWlRaUFFVRkJRbTF5V0hWSUswRkJRVUZSUkFwQlJXTjNVbEZKYUVGUGNWUlViWFJKVEZVeE5VdHFUVVo0U0ZwUFFqVlFiREVyVVZSNU1Ea3hPRVZuVDJKc01FOUhObVV4UVdsQk1FeENTakZsUmtFeUNrd3haMDhyT0dWeGFXdzFZUzkyV1c5VlVFbHFWbEJ0UTBSWFYwMTBaamRxVldwQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG05QlJFSnNRV3BDV2tkalpWZ0tRa0pNZVdOb1dqUXhaVXAyTUdSbkwyUnJTamN2TkhGQlNHTnNaWFp4YmpOaFZFUTBXbmxMVVdwREsxVlJRWHA1VTFSSWFGaFFaRmh0ZEUxRFRWRkVhd3BvUkV4VVlYWmtjRlkyTDJoWE5UQXdhR2hxWjFWM1ZDdDBSVTlKUXpoM2VFOXJRbUpqWVhKVGNXYzVkREpTWlRWcmJVMUtUMk5QWTB0Rk5XOTRkakE5Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzBLIn1dfX0=",
            "inclusion_promise":{
               "signed_entry_timestamp":"MEUCIBIMIi23C+k4nK+0v3gAMtI8+SWzuZY+irkr/zTok2VFAiEA3pLg9vZMVcZ9FpugGpQ0N+yYhVYutlb8S7obdNp2aPM="
            },
            "integrated_time":1763988873,
            "kind_version":{
               "kind":"dsse",
               "version":"0.0.1"
            },
            "log_id":{
               "key_id":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
            },
            "log_index":720620781
         },
         "signingCertificate":{
            "isCa":false,
            "issuer":"CN=sigstore-intermediate,O=sigstore.dev",
            "notAfter":"2025-11-24T13:04:33Z",
            "notBefore":"2025-11-24T12:54:33Z",
            "pem":"-----BEGIN CERTIFICATE-----\nMIICyzCCAlGgAwIBAgIUaaW8kM/EEsciH7ULccE9r9xjkH4wCgYIKoZIzj0EAwMw\nNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl\ncm1lZGlhdGUwHhcNMjUxMTI0MTI1NDMzWhcNMjUxMTI0MTMwNDMzWjAAMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAEiymFVHOUqVDv/RM7cnUXW/Qx1mzTQUwxI6Cy\n3BiLtf7xIt3WZSAVW939bQY72JP4XySL+l4IwAsgH6mmnMtC4aOCAXAwggFsMA4G\nA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUoHTu\n2FND+hHHCZUQ7U/HpjGEF+8wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y\nZD8wIAYDVR0RAQH/BBYwFIESZmdoYW5taUByZWRoYXQuY29tMCkGCisGAQQBg78w\nAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgEEAYO/MAEIBB0M\nG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBigYKKwYBBAHWeQIEAgR8BHoA\neAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABmrXuH+AAAAQD\nAEcwRQIhAOqTTmtILU15KjMFxHZOB5Pl1+QTy0918EgObl0OG6e1AiA0LBJ1eFA2\nL1gO+8eqil5a/vYoUPIjVPmCDWWMtf7jUjAKBggqhkjOPQQDAwNoADBlAjBZGceX\nBBLychZ41eJv0dg/dkJ7/4qAHclevqn3aTD4ZyKQjC+UQAzySTHhXPdXmtMCMQDk\nhDLTavdpV6/hW500hhjgUwT+tEOIC8wxOkBbcarSqg9t2Re5kmMJOcOcKE5oxv0=\n-----END CERTIFICATE-----\n",
            "role":"leaf",
            "sans":[
               "jdoe@redhat.com"
            ],
            "serialNumber":"603140080280844976576430244671554004848635777150",
            "subject":""
         },
         "timestamp":"2025-11-24T12:54:33Z",
         "type":"https://in-toto.io/Statement/v0.1"
      }
   ],
   "signatures":[
      {
         "certificateChain":[
            {
               "isCa":true,
               "issuer":"CN=sigstore,O=sigstore.dev",
               "notAfter":"2031-10-05T13:56:58Z",
               "notBefore":"2022-04-13T20:06:15Z",
               "pem":"-----BEGIN CERTIFICATE-----\nMIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C\nAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7\n7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS\n0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB\nBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp\nKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI\nzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR\nnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP\nmygUY7Ii2zbdCdliiow=\n-----END CERTIFICATE-----\n",
               "role":"intermediate",
               "sans":null,
               "serialNumber":"4144239514159843648641554259375047022727364004",
               "subject":"CN=sigstore-intermediate,O=sigstore.dev"
            },
            {
               "isCa":true,
               "issuer":"CN=sigstore,O=sigstore.dev",
               "notAfter":"2031-10-05T13:56:58Z",
               "notBefore":"2021-10-07T13:56:59Z",
               "pem":"-----BEGIN CERTIFICATE-----\nMIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7\nXeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex\nX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j\nYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY\nwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ\nKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM\nWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9\nTNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ\n-----END CERTIFICATE-----\n",
               "role":"root",
               "sans":null,
               "serialNumber":"4065443592980134080728682916587645234900384766",
               "subject":"CN=sigstore,O=sigstore.dev"
            }
         ],
         "digest":"sha256:b40eabb38ea04307954c94e124519dcba4135ea99f5d8132e7287b412f0f0d28",
         "id":0,
         "rawBundleJson":"{\n  \"mediaType\": \"application/vnd.dev.sigstore.bundle+json;version=0.1\",\n  \"verificationMaterial\": {\n    \"x509CertificateChain\": {\n      \"certificates\": [\n        {\n          \"rawBytes\": \"MIICzDCCAlGgAwIBAgIUAuHdnILVBzWlvKq+grRVqWO4ft4wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUxMTI0MDgxMzIzWhcNMjUxMTI0MDgyMzIzWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpTbIY9BrJHRmijvtKk0nOP3meSm3309GaLFALH5vy4F3gSBndKJFVWPeTQ52nffnorWVgj7Alzqp/DhHKKNEB6OCAXAwggFsMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUuwVTfPSINvMTkj69H8muSr1+BxkwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIAYDVR0RAQH/BBYwFIESZmdoYW5taUByZWRoYXQuY29tMCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgEEAYO/MAEIBB0MG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABmrTstyAAAAQDAEcwRQIgMzVdkleCV1Y4Pr8l6I+iMCT0UgkgScIDLgbRMEODN6MCIQDN+8we4LMrtaJCBzNUqVf8KovBHB6ef8vAzFRGTwkcVTAKBggqhkjOPQQDAwNpADBmAjEAjmXlQUMrTHGE4ghHvmxpby6mQ2IZ5+uyVI9qEw/lISzp6nbP0EluNXQazlzKbLFeAjEA3DupjGzzDFzySwHEdOOh42u9KXy2Kc6pcaqpNheKLhOgMmxTeAus2Up9jHRR4tJo\"\n        }\n      ]\n    },\n    \"tlogEntries\": [\n      {\n        \"logIndex\": \"719634143\",\n        \"logId\": {\n          \"keyId\": \"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=\"\n        },\n        \"kindVersion\": {\n          \"kind\": \"hashedrekord\",\n          \"version\": \"0.0.1\"\n        },\n        \"integratedTime\": \"1763972005\",\n        \"inclusionPromise\": {\n          \"signedEntryTimestamp\": \"MEQCICaFLkFfR8oDEDiumqmi0YykKCMrzDcJlTc8DiFl6ovHAiASj1Qx2WWJDf/8ebSYv7a8OIiboczum66+wVsHL3CFeg==\"\n        },\n        \"canonicalizedBody\": \"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJiNDBlYWJiMzhlYTA0MzA3OTU0Yzk0ZTEyNDUxOWRjYmE0MTM1ZWE5OWY1ZDgxMzJlNzI4N2I0MTJmMGYwZDI4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQrOVJWbVg0cG45SitlcERFZWRHRXNvaXBYMGlwY2I1Qm91Y2VnTzBOT2tBSWhBTTdnQndqOG8zdXZjSEdHbTR5bEVXUWFmL01jQnh2S1psRWZveWhsZEFmbyIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTjZSRU5EUVd4SFowRjNTVUpCWjBsVlFYVklaRzVKVEZaQ2VsZHNka3R4SzJkeVVsWnhWMDgwWm5RMGQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFZlRTFVU1RCTlJHZDRUWHBKZWxkb1kwNU5hbFY0VFZSSk1FMUVaM2xOZWtsNlYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZ3VkdKSldUbENja3BJVW0xcGFuWjBTMnN3Yms5UU0yMWxVMjB6TXpBNVIyRk1Sa0VLVEVnMWRuazBSak5uVTBKdVpFdEtSbFpYVUdWVVVUVXlibVptYm05eVYxWm5hamRCYkhweGNDOUVhRWhMUzA1RlFqWlBRMEZZUVhkblowWnpUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlYxZDFaVUNtWlFVMGxPZGsxVWEybzJPVWc0YlhWVGNqRXJRbmhyZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBsQldVUldVakJTUVZGSUwwSkNXWGRHU1VWVFdtMWtiMWxYTlhSaFZVSjVXbGRTYjFsWVVYVlpNamwwVFVOclIwTnBjMGRCVVZGQ1p6YzRkd3BCVVVWRlJ6Sm9NR1JJUW5wUGFUaDJXVmRPYW1JelZuVmtTRTExV2pJNWRsb3llR3hNYlU1MllsUkJja0puYjNKQ1owVkZRVmxQTDAxQlJVbENRakJOQ2tjeWFEQmtTRUo2VDJrNGRsbFhUbXBpTTFaMVpFaE5kVm95T1haYU1uaHNURzFPZG1KVVEwSnBaMWxMUzNkWlFrSkJTRmRsVVVsRlFXZFNPRUpJYjBFS1pVRkNNa0ZPTURsTlIzSkhlSGhGZVZsNGEyVklTbXh1VG5kTGFWTnNOalF6YW5sMEx6UmxTMk52UVhaTFpUWlBRVUZCUW0xeVZITjBlVUZCUVVGUlJBcEJSV04zVWxGSlowMTZWbVJyYkdWRFZqRlpORkJ5T0d3MlNTdHBUVU5VTUZWbmEyZFRZMGxFVEdkaVVrMUZUMFJPTmsxRFNWRkVUaXM0ZDJVMFRFMXlDblJoU2tOQ2VrNVZjVlptT0V0dmRrSklRalpsWmpoMlFYcEdVa2RVZDJ0alZsUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFXcHRXR3dLVVZWTmNsUklSMFUwWjJoSWRtMTRjR0o1Tm0xUk1rbGFOU3QxZVZaSk9YRkZkeTlzU1ZONmNEWnVZbEF3Uld4MVRsaFJZWHBzZWt0aVRFWmxRV3BGUVFvelJIVndha2Q2ZWtSR2VubFRkMGhGWkU5UGFEUXlkVGxMV0hreVMyTTJjR05oY1hCT2FHVkxUR2hQWjAxdGVGUmxRWFZ6TWxWd09XcElVbEkwZEVwdkNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19\"\n      }\n    ]\n  },\n  \"messageSignature\": {\n    \"messageDigest\": {\n      \"algorithm\": \"SHA2_256\",\n      \"digest\": \"tA6rs46gQweVTJThJFGdy6QTXqmfXYEy5yh7QS8PDSg=\"\n    },\n    \"signature\": \"MEYCIQD+9RVmX4pn9J+epDEedGEsoipX0ipcb5BoucegO0NOkAIhAM7gBwj8o3uvcHGGm4ylEWQaf/McBxvKZlEfoyhldAfo\"\n  }\n}",
         "rekorEntry":{
            "canonicalized_body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJiNDBlYWJiMzhlYTA0MzA3OTU0Yzk0ZTEyNDUxOWRjYmE0MTM1ZWE5OWY1ZDgxMzJlNzI4N2I0MTJmMGYwZDI4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQrOVJWbVg0cG45SitlcERFZWRHRXNvaXBYMGlwY2I1Qm91Y2VnTzBOT2tBSWhBTTdnQndqOG8zdXZjSEdHbTR5bEVXUWFmL01jQnh2S1psRWZveWhsZEFmbyIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTjZSRU5EUVd4SFowRjNTVUpCWjBsVlFYVklaRzVKVEZaQ2VsZHNka3R4SzJkeVVsWnhWMDgwWm5RMGQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFZlRTFVU1RCTlJHZDRUWHBKZWxkb1kwNU5hbFY0VFZSSk1FMUVaM2xOZWtsNlYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZ3VkdKSldUbENja3BJVW0xcGFuWjBTMnN3Yms5UU0yMWxVMjB6TXpBNVIyRk1Sa0VLVEVnMWRuazBSak5uVTBKdVpFdEtSbFpYVUdWVVVUVXlibVptYm05eVYxWm5hamRCYkhweGNDOUVhRWhMUzA1RlFqWlBRMEZZUVhkblowWnpUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlYxZDFaVUNtWlFVMGxPZGsxVWEybzJPVWc0YlhWVGNqRXJRbmhyZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBsQldVUldVakJTUVZGSUwwSkNXWGRHU1VWVFdtMWtiMWxYTlhSaFZVSjVXbGRTYjFsWVVYVlpNamwwVFVOclIwTnBjMGRCVVZGQ1p6YzRkd3BCVVVWRlJ6Sm9NR1JJUW5wUGFUaDJXVmRPYW1JelZuVmtTRTExV2pJNWRsb3llR3hNYlU1MllsUkJja0puYjNKQ1owVkZRVmxQTDAxQlJVbENRakJOQ2tjeWFEQmtTRUo2VDJrNGRsbFhUbXBpTTFaMVpFaE5kVm95T1haYU1uaHNURzFPZG1KVVEwSnBaMWxMUzNkWlFrSkJTRmRsVVVsRlFXZFNPRUpJYjBFS1pVRkNNa0ZPTURsTlIzSkhlSGhGZVZsNGEyVklTbXh1VG5kTGFWTnNOalF6YW5sMEx6UmxTMk52UVhaTFpUWlBRVUZCUW0xeVZITjBlVUZCUVVGUlJBcEJSV04zVWxGSlowMTZWbVJyYkdWRFZqRlpORkJ5T0d3MlNTdHBUVU5VTUZWbmEyZFRZMGxFVEdkaVVrMUZUMFJPTmsxRFNWRkVUaXM0ZDJVMFRFMXlDblJoU2tOQ2VrNVZjVlptT0V0dmRrSklRalpsWmpoMlFYcEdVa2RVZDJ0alZsUkJTMEpuWjNGb2EycFBVRkZSUkVGM1RuQkJSRUp0UVdwRlFXcHRXR3dLVVZWTmNsUklSMFUwWjJoSWRtMTRjR0o1Tm0xUk1rbGFOU3QxZVZaSk9YRkZkeTlzU1ZONmNEWnVZbEF3Uld4MVRsaFJZWHBzZWt0aVRFWmxRV3BGUVFvelJIVndha2Q2ZWtSR2VubFRkMGhGWkU5UGFEUXlkVGxMV0hreVMyTTJjR05oY1hCT2FHVkxUR2hQWjAxdGVGUmxRWFZ6TWxWd09XcElVbEkwZEVwdkNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19",
            "inclusion_promise":{
               "signed_entry_timestamp":"MEQCICaFLkFfR8oDEDiumqmi0YykKCMrzDcJlTc8DiFl6ovHAiASj1Qx2WWJDf/8ebSYv7a8OIiboczum66+wVsHL3CFeg=="
            },
            "integrated_time":1763972005,
            "kind_version":{
               "kind":"hashedrekord",
               "version":"0.0.1"
            },
            "log_id":{
               "key_id":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
            },
            "log_index":719634143
         },
         "signatureStatus":{
            "chain":"verified",
            "rekor":"verified",
            "signature":"verified"
         },
         "signingCertificate":{
            "isCa":false,
            "issuer":"CN=sigstore-intermediate,O=sigstore.dev",
            "notAfter":"2025-11-24T08:23:23Z",
            "notBefore":"2025-11-24T08:13:23Z",
            "pem":"-----BEGIN CERTIFICATE-----\nMIICzDCCAlGgAwIBAgIUAuHdnILVBzWlvKq+grRVqWO4ft4wCgYIKoZIzj0EAwMw\nNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl\ncm1lZGlhdGUwHhcNMjUxMTI0MDgxMzIzWhcNMjUxMTI0MDgyMzIzWjAAMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAEpTbIY9BrJHRmijvtKk0nOP3meSm3309GaLFA\nLH5vy4F3gSBndKJFVWPeTQ52nffnorWVgj7Alzqp/DhHKKNEB6OCAXAwggFsMA4G\nA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUuwVT\nfPSINvMTkj69H8muSr1+BxkwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y\nZD8wIAYDVR0RAQH/BBYwFIESZmdoYW5taUByZWRoYXQuY29tMCkGCisGAQQBg78w\nAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgEEAYO/MAEIBB0M\nG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBigYKKwYBBAHWeQIEAgR8BHoA\neAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABmrTstyAAAAQD\nAEcwRQIgMzVdkleCV1Y4Pr8l6I+iMCT0UgkgScIDLgbRMEODN6MCIQDN+8we4LMr\ntaJCBzNUqVf8KovBHB6ef8vAzFRGTwkcVTAKBggqhkjOPQQDAwNpADBmAjEAjmXl\nQUMrTHGE4ghHvmxpby6mQ2IZ5+uyVI9qEw/lISzp6nbP0EluNXQazlzKbLFeAjEA\n3DupjGzzDFzySwHEdOOh42u9KXy2Kc6pcaqpNheKLhOgMmxTeAus2Up9jHRR4tJo\n-----END CERTIFICATE-----\n",
            "role":"leaf",
            "sans":[
               "jdoe@redhat.com"
            ],
            "serialNumber":"16454954284462972846380960106456630522921123550",
            "subject":""
         },
         "timestamp":"2025-11-24T08:13:25Z"
      }
   ],
   "summary":{
      "attestationCount":1,
      "identities":[
         {
            "id":0,
            "issuer":"CN=sigstore-intermediate,O=sigstore.dev",
            "source":"san",
            "type":"email",
            "value":"jdoe@redhat.com"
         }
      ],
      "overallStatus":"verified",
      "rekorEntryCount":2,
      "signatureCount":1,
      "timeCoherence":{
         "maxIntegratedTime":"2025-11-24T12:54:33Z",
         "minIntegratedTime":"2025-11-24T08:13:25Z",
         "status":"ok"
      }
   }
}
```
</details>

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
