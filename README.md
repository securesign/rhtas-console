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
```json
{
   "artifact":{
      "digest":"sha256:2d3c848f0ddda17041d006f4a410a373c87479e1cf9ab011a1947a0e439d3d12",
      "image":"ttl.sh/rhtas/console-test-image",
      "metadata":{
         "created":"2025-11-19T13:36:42.255223807Z",
         "labels":{
            "io.buildah.version":"1.41.5"
         },
         "mediaType":"application/vnd.oci.image.manifest.v1+json",
         "size":414
      }
   },
   "attestations":[
      {
         "attestationStatus":"Verified",
         "digest":"sha256:9c5df6ac3d44b722501226fd4385ac73aa9ecaa8bacf370f14b9f63c20239184",
         "id":0,
         "predicateType":"https://example.com/attestations/build",
         "rawBundleJson":"{\n  \"mediaType\": \"application/vnd.dev.sigstore.bundle+json;version=0.1\",\n  \"verificationMaterial\": {\n    \"x509CertificateChain\": {\n      \"certificates\": [\n        {\n          \"rawBytes\": \"MIICzDCCAlGgAwIBAgIUPhHM3Fe6XIze8Gb68pgtV86eq1cwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUxMTE5MTMzODM4WhcNMjUxMTE5MTM0ODM4WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5EqlEVRdsT1dLCAVt9MlsJf9iTyW4xybf403f4We4ufzwZ0nh/TpWQ1A1qxSLsG4nhMWaF4ODmYd9tMzZypZHKOCAXAwggFsMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUWn6DUhLd8FDVELq6yGqdREQ8yA0wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIAYDVR0RAQH/BBYwFIESZmdoYW5taUByZWRoYXQuY29tMCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgEEAYO/MAEIBB0MG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABmpxWsTYAAAQDAEcwRQIhAPWE08+PxAg4xaSgoirDDYiUrL1Dl99GRqXI8qOb0RpYAiBUMaoQdNspcgx6wC4C/jF0+rmiUSkNjSuS9Q8p9lkVkDAKBggqhkjOPQQDAwNpADBmAjEAniw/iuSzAY0asGzySLk9DaB3vb5r5q2wkCFMYdxBVE0lAWTX6KoVZVvrx8QsViTgAjEAi27m8fo+o40y/Et8LTFkVT7FESzRlah++9ekEYQsclrOpZ279w85PyfymkQ1ukD0\"\n        }\n      ]\n    },\n    \"tlogEntries\": [\n      {\n        \"logIndex\": \"708587538\",\n        \"logId\": {\n          \"keyId\": \"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=\"\n        },\n        \"kindVersion\": {\n          \"kind\": \"dsse\",\n          \"version\": \"0.0.1\"\n        },\n        \"integratedTime\": \"1763559518\",\n        \"inclusionPromise\": {\n          \"signedEntryTimestamp\": \"MEYCIQCdRORVAWWIO2UkwXxC6A9+UQI0GbX5we5dFkF09MO17AIhAJHDIFajc0rkzTD7/5cYuhoUx700cBn0UmR5G0DxNz3l\"\n        },\n        \"canonicalizedBody\": \"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiOWM1ZGY2YWMzZDQ0YjcyMjUwMTIyNmZkNDM4NWFjNzNhYTllY2FhOGJhY2YzNzBmMTRiOWY2M2MyMDIzOTE4NCJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6ImVjMDIwMTkxMzQ1YzhiY2Q0NjA1ZjczZTdmMmVhNDRhYjU4NWM5YzZiMGZjOGVmYTRhNDNlZTMyMDEyOTJkOWIifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVRQ0lCK2NTY2dzcGgxdjZyZnF0WGxnM2E1WEloeTJleEZWODkxRlNkaTdUT2NIQWlCeFdXQkRaK3ZnZGdKSCt0UVZYei93a0tUTkptNHlQQUpPdG1OMXY5ZllNQT09IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VONlJFTkRRV3hIWjBGM1NVSkJaMGxWVUdoSVRUTkdaVFpZU1hwbE9FZGlOamh3WjNSV09EWmxjVEZqZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwVmVFMVVSVFZOVkUxNlQwUk5ORmRvWTA1TmFsVjRUVlJGTlUxVVRUQlBSRTAwVjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVTFSWEZzUlZaU1pITlVNV1JNUTBGV2REbE5iSE5LWmpscFZIbFhOSGg1WW1ZME1ETUtaalJYWlRSMVpucDNXakJ1YUM5VWNGZFJNVUV4Y1hoVFRITkhORzVvVFZkaFJqUlBSRzFaWkRsMFRYcGFlWEJhU0V0UFEwRllRWGRuWjBaelRVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdSQ1owNVdTRkUwUlVablVWVlhialpFQ2xWb1RHUTRSa1JXUlV4eE5ubEhjV1JTUlZFNGVVRXdkMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4VG1wd1MwWlhhWGhwTkZrS1drUTRkMGxCV1VSV1VqQlNRVkZJTDBKQ1dYZEdTVVZUV20xa2IxbFhOWFJoVlVKNVdsZFNiMWxZVVhWWk1qbDBUVU5yUjBOcGMwZEJVVkZDWnpjNGR3cEJVVVZGUnpKb01HUklRbnBQYVRoMldWZE9hbUl6Vm5Wa1NFMTFXakk1ZGxveWVHeE1iVTUyWWxSQmNrSm5iM0pDWjBWRlFWbFBMMDFCUlVsQ1FqQk5Da2N5YURCa1NFSjZUMms0ZGxsWFRtcGlNMVoxWkVoTmRWb3lPWFphTW5oc1RHMU9kbUpVUTBKcFoxbExTM2RaUWtKQlNGZGxVVWxGUVdkU09FSkliMEVLWlVGQ01rRk9NRGxOUjNKSGVIaEZlVmw0YTJWSVNteHVUbmRMYVZOc05qUXphbmwwTHpSbFMyTnZRWFpMWlRaUFFVRkJRbTF3ZUZkelZGbEJRVUZSUkFwQlJXTjNVbEZKYUVGUVYwVXdPQ3RRZUVGbk5IaGhVMmR2YVhKRVJGbHBWWEpNTVVSc09UbEhVbkZZU1RoeFQySXdVbkJaUVdsQ1ZVMWhiMUZrVG5Od0NtTm5lRFozUXpSREwycEdNQ3R5YldsVlUydE9hbE4xVXpsUk9IQTViR3RXYTBSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG5CQlJFSnRRV3BGUVc1cGR5OEthWFZUZWtGWk1HRnpSM3A1VTB4ck9VUmhRak4yWWpWeU5YRXlkMnREUmsxWlpIaENWa1V3YkVGWFZGZzJTMjlXV2xaMmNuZzRVWE5XYVZSblFXcEZRUXBwTWpkdE9HWnZLMjgwTUhrdlJYUTRURlJHYTFaVU4wWkZVM3BTYkdGb0t5czVaV3RGV1ZGelkyeHlUM0JhTWpjNWR6ZzFVSGxtZVcxclVURjFhMFF3Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzBLIn1dfX0=\"\n      }\n    ]\n  },\n  \"dsseEnvelope\": {\n    \"payload\": \"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2V4YW1wbGUuY29tL2F0dGVzdGF0aW9ucy9idWlsZCIsInN1YmplY3QiOlt7Im5hbWUiOiJ0dGwuc2gvcmh0YXMvY29uc29sZS10ZXN0LWltYWdlIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjJkM2M4NDhmMGRkZGExNzA0MWQwMDZmNGE0MTBhMzczYzg3NDc5ZTFjZjlhYjAxMWExOTQ3YTBlNDM5ZDNkMTIifX1dLCJwcmVkaWNhdGUiOnsiYnVpbGRUeXBlIjoibWFudWFsLXRlc3QiLCJidWlsZGVyIjp7ImlkIjoiZXhhbXBsZS1idWlsZGVyIn0sIm1ldGFkYXRhIjp7ImJ1aWxkRmluaXNoZWRPbiI6IjIwMjUtMTAtMjBUMTQ6NTA6MzkrMDI6MDAiLCJidWlsZFN0YXJ0ZWRPbiI6IjIwMjUtMTAtMjBUMTQ6NTA6MzkrMDI6MDAifSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vYXR0ZXN0YXRpb25zL2J1aWxkIn19\",\n    \"payloadType\": \"application/vnd.in-toto+json\",\n    \"signatures\": [\n      {\n        \"sig\": \"MEQCIB+cScgsph1v6rfqtXlg3a5XIhy2exFV891FSdi7TOcHAiBxWWBDZ+vgdgJH+tQVXz/wkKTNJm4yPAJOtmN1v9fYMA==\"\n      }\n    ]\n  }\n}",
         "rawStatementJson":"{\n  \"type\": \"https://in-toto.io/Statement/v0.1\",\n  \"subject\": [\n    {\n      \"name\": \"ttl.sh/rhtas/console-test-image\",\n      \"digest\": {\n        \"sha256\": \"2d3c848f0ddda17041d006f4a410a373c87479e1cf9ab011a1947a0e439d3d12\"\n      }\n    }\n  ],\n  \"predicate_type\": \"https://example.com/attestations/build\",\n  \"predicate\": {\n    \"buildType\": \"manual-test\",\n    \"builder\": {\n      \"id\": \"example-builder\"\n    },\n    \"metadata\": {\n      \"buildFinishedOn\": \"2025-10-20T14:50:39+02:00\",\n      \"buildStartedOn\": \"2025-10-20T14:50:39+02:00\"\n    },\n    \"predicateType\": \"https://example.com/attestations/build\"\n  }\n}",
         "timestamp":"2025-11-19T13:38:38Z",
         "tlogEntry":{
            "canonicalized_body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiOWM1ZGY2YWMzZDQ0YjcyMjUwMTIyNmZkNDM4NWFjNzNhYTllY2FhOGJhY2YzNzBmMTRiOWY2M2MyMDIzOTE4NCJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6ImVjMDIwMTkxMzQ1YzhiY2Q0NjA1ZjczZTdmMmVhNDRhYjU4NWM5YzZiMGZjOGVmYTRhNDNlZTMyMDEyOTJkOWIifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVRQ0lCK2NTY2dzcGgxdjZyZnF0WGxnM2E1WEloeTJleEZWODkxRlNkaTdUT2NIQWlCeFdXQkRaK3ZnZGdKSCt0UVZYei93a0tUTkptNHlQQUpPdG1OMXY5ZllNQT09IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VONlJFTkRRV3hIWjBGM1NVSkJaMGxWVUdoSVRUTkdaVFpZU1hwbE9FZGlOamh3WjNSV09EWmxjVEZqZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwVmVFMVVSVFZOVkUxNlQwUk5ORmRvWTA1TmFsVjRUVlJGTlUxVVRUQlBSRTAwVjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVTFSWEZzUlZaU1pITlVNV1JNUTBGV2REbE5iSE5LWmpscFZIbFhOSGg1WW1ZME1ETUtaalJYWlRSMVpucDNXakJ1YUM5VWNGZFJNVUV4Y1hoVFRITkhORzVvVFZkaFJqUlBSRzFaWkRsMFRYcGFlWEJhU0V0UFEwRllRWGRuWjBaelRVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdSQ1owNVdTRkUwUlVablVWVlhialpFQ2xWb1RHUTRSa1JXUlV4eE5ubEhjV1JTUlZFNGVVRXdkMGgzV1VSV1VqQnFRa0puZDBadlFWVXpPVkJ3ZWpGWmEwVmFZalZ4VG1wd1MwWlhhWGhwTkZrS1drUTRkMGxCV1VSV1VqQlNRVkZJTDBKQ1dYZEdTVVZUV20xa2IxbFhOWFJoVlVKNVdsZFNiMWxZVVhWWk1qbDBUVU5yUjBOcGMwZEJVVkZDWnpjNGR3cEJVVVZGUnpKb01HUklRbnBQYVRoMldWZE9hbUl6Vm5Wa1NFMTFXakk1ZGxveWVHeE1iVTUyWWxSQmNrSm5iM0pDWjBWRlFWbFBMMDFCUlVsQ1FqQk5Da2N5YURCa1NFSjZUMms0ZGxsWFRtcGlNMVoxWkVoTmRWb3lPWFphTW5oc1RHMU9kbUpVUTBKcFoxbExTM2RaUWtKQlNGZGxVVWxGUVdkU09FSkliMEVLWlVGQ01rRk9NRGxOUjNKSGVIaEZlVmw0YTJWSVNteHVUbmRMYVZOc05qUXphbmwwTHpSbFMyTnZRWFpMWlRaUFFVRkJRbTF3ZUZkelZGbEJRVUZSUkFwQlJXTjNVbEZKYUVGUVYwVXdPQ3RRZUVGbk5IaGhVMmR2YVhKRVJGbHBWWEpNTVVSc09UbEhVbkZZU1RoeFQySXdVbkJaUVdsQ1ZVMWhiMUZrVG5Od0NtTm5lRFozUXpSREwycEdNQ3R5YldsVlUydE9hbE4xVXpsUk9IQTViR3RXYTBSQlMwSm5aM0ZvYTJwUFVGRlJSRUYzVG5CQlJFSnRRV3BGUVc1cGR5OEthWFZUZWtGWk1HRnpSM3A1VTB4ck9VUmhRak4yWWpWeU5YRXlkMnREUmsxWlpIaENWa1V3YkVGWFZGZzJTMjlXV2xaMmNuZzRVWE5XYVZSblFXcEZRUXBwTWpkdE9HWnZLMjgwTUhrdlJYUTRURlJHYTFaVU4wWkZVM3BTYkdGb0t5czVaV3RGV1ZGelkyeHlUM0JhTWpjNWR6ZzFVSGxtZVcxclVURjFhMFF3Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzBLIn1dfX0=",
            "inclusion_promise":{
               "signed_entry_timestamp":"MEYCIQCdRORVAWWIO2UkwXxC6A9+UQI0GbX5we5dFkF09MO17AIhAJHDIFajc0rkzTD7/5cYuhoUx700cBn0UmR5G0DxNz3l"
            },
            "integrated_time":1763559518,
            "kind_version":{
               "kind":"dsse",
               "version":"0.0.1"
            },
            "log_id":{
               "key_id":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
            },
            "log_index":708587538
         },
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
         "digest":"sha256:12f4a9a2ee1dbbc9b6d152a49097fc33469e9b12fc7185c6a97c4984f0e49458",
         "id":0,
         "rawBundleJson":"{\n  \"mediaType\": \"application/vnd.dev.sigstore.bundle+json;version=0.1\",\n  \"verificationMaterial\": {\n    \"x509CertificateChain\": {\n      \"certificates\": [\n        {\n          \"rawBytes\": \"MIICyzCCAlKgAwIBAgIUV129C1uC3f21G3PpgdKSXpoFBCowCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUxMTE5MTMzNzEzWhcNMjUxMTE5MTM0NzEzWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJdSyCyf1hpw+OYvJzDl6nDctROIgjMrlvt38tWvculFZM6qK1t2Fyk6YrL5AFtF1T0vqPtSlPAQJg3LprSXjKKOCAXEwggFtMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUjai9Lj0l+6fULcQb/ryG4zbbMVcwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIAYDVR0RAQH/BBYwFIESZmdoYW5taUByZWRoYXQuY29tMCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgEEAYO/MAEIBB0MG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBiwYKKwYBBAHWeQIEAgR9BHsAeQB3AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABmpxVZZkAAAQDAEgwRgIhAN/EaO+1X63f2ig60iOsJ44MIL5R+Pj8VPy5B8JxjXnoAiEAnCZBhtRmrh1qQyQnn2A+Zzwe85+tt6mkCIfo86GglKcwCgYIKoZIzj0EAwMDZwAwZAIwMnVQX8fDZKQZbQMjb0akx0tzsZetSwOgBQRMxp4IzmstX+4Vlqo/RXG2+ypBk7OKAjB0ivQN5WW3iytuw3C2fE/flR5Ry/1K8xIXOet4GWZYrITqNw3hPkeRSFKLwE9OSr0=\"\n        }\n      ]\n    },\n    \"tlogEntries\": [\n      {\n        \"logIndex\": \"708587072\",\n        \"logId\": {\n          \"keyId\": \"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=\"\n        },\n        \"kindVersion\": {\n          \"kind\": \"hashedrekord\",\n          \"version\": \"0.0.1\"\n        },\n        \"integratedTime\": \"1763559435\",\n        \"inclusionPromise\": {\n          \"signedEntryTimestamp\": \"MEUCIQDdNwTBlf15PaOEN1KvCZQh25CXkMK52+xmSIDUouYsywIgS1MYJEWPN0L9QQsYx7MJgPtNy6nIbG+gdzghwv3soks=\"\n        },\n        \"canonicalizedBody\": \"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIxMmY0YTlhMmVlMWRiYmM5YjZkMTUyYTQ5MDk3ZmMzMzQ2OWU5YjEyZmM3MTg1YzZhOTdjNDk4NGYwZTQ5NDU4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUNUL2ZOUEJ3UkZhQjZyVVpDcUhMN1g5L08zM1pVNnYyMEJlZVRCK0NNNEZRSWhBSnhPbi9NZnM0MDJCSTQxSW41TjhPUTJ2UEZtVVY3Wmc5S2ZBekY0OWVlYSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTjVla05EUVd4TFowRjNTVUpCWjBsVlZqRXlPVU14ZFVNelpqSXhSek5RY0dka1MxTlljRzlHUWtOdmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFZlRTFVUlRWTlZFMTZUbnBGZWxkb1kwNU5hbFY0VFZSRk5VMVVUVEJPZWtWNlYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZLWkZONVEzbG1NV2h3ZHl0UFdYWktla1JzTm01RVkzUlNUMGxuYWsxeWJIWjBNemdLZEZkMlkzVnNSbHBOTm5GTE1YUXlSbmxyTmxseVREVkJSblJHTVZRd2RuRlFkRk5zVUVGUlNtY3pUSEJ5VTFocVMwdFBRMEZZUlhkblowWjBUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZxWVdrNUNreHFNR3dyTm1aVlRHTlJZaTl5ZVVjMGVtSmlUVlpqZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBsQldVUldVakJTUVZGSUwwSkNXWGRHU1VWVFdtMWtiMWxYTlhSaFZVSjVXbGRTYjFsWVVYVlpNamwwVFVOclIwTnBjMGRCVVZGQ1p6YzRkd3BCVVVWRlJ6Sm9NR1JJUW5wUGFUaDJXVmRPYW1JelZuVmtTRTExV2pJNWRsb3llR3hNYlU1MllsUkJja0puYjNKQ1owVkZRVmxQTDAxQlJVbENRakJOQ2tjeWFEQmtTRUo2VDJrNGRsbFhUbXBpTTFaMVpFaE5kVm95T1haYU1uaHNURzFPZG1KVVEwSnBkMWxMUzNkWlFrSkJTRmRsVVVsRlFXZFNPVUpJYzBFS1pWRkNNMEZPTURsTlIzSkhlSGhGZVZsNGEyVklTbXh1VG5kTGFWTnNOalF6YW5sMEx6UmxTMk52UVhaTFpUWlBRVUZCUW0xd2VGWmFXbXRCUVVGUlJBcEJSV2QzVW1kSmFFRk9MMFZoVHlzeFdEWXpaakpwWnpZd2FVOXpTalEwVFVsTU5WSXJVR280VmxCNU5VSTRTbmhxV0c1dlFXbEZRVzVEV2tKb2RGSnRDbkpvTVhGUmVWRnViakpCSzFwNmQyVTROU3QwZERadGEwTkpabTg0TmtkbmJFdGpkME5uV1VsTGIxcEplbW93UlVGM1RVUmFkMEYzV2tGSmQwMXVWbEVLV0RobVJGcExVVnBpVVUxcVlqQmhhM2d3ZEhweldtVjBVM2RQWjBKUlVrMTRjRFJKZW0xemRGZ3JORlpzY1c4dlVsaEhNaXQ1Y0VKck4wOUxRV3BDTUFwcGRsRk9OVmRYTTJsNWRIVjNNME15WmtVdlpteFNOVko1THpGTE9IaEpXRTlsZERSSFYxcFpja2xVY1U1M00yaFFhMlZTVTBaTFRIZEZPVTlUY2pBOUNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19\"\n      }\n    ]\n  },\n  \"messageSignature\": {\n    \"messageDigest\": {\n      \"algorithm\": \"SHA2_256\",\n      \"digest\": \"EvSpou4du8m20VKkkJf8M0aemxL8cYXGqXxJhPDklFg=\"\n    },\n    \"signature\": \"MEYCIQCT/fNPBwRFaB6rUZCqHL7X9/O33ZU6v20BeeTB+CM4FQIhAJxOn/Mfs402BI41In5N8OQ2vPFmUV7Zg9KfAzF49eea\"\n  }\n}",
         "signatureStatus":"Verified",
         "signingCertificate":{
            "isCa":false,
            "issuer":"CN=sigstore-intermediate,O=sigstore.dev",
            "notAfter":"2025-11-19T13:47:13Z",
            "notBefore":"2025-11-19T13:37:13Z",
            "pem":"-----BEGIN CERTIFICATE-----\nMIICyzCCAlKgAwIBAgIUV129C1uC3f21G3PpgdKSXpoFBCowCgYIKoZIzj0EAwMw\nNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl\ncm1lZGlhdGUwHhcNMjUxMTE5MTMzNzEzWhcNMjUxMTE5MTM0NzEzWjAAMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAEJdSyCyf1hpw+OYvJzDl6nDctROIgjMrlvt38\ntWvculFZM6qK1t2Fyk6YrL5AFtF1T0vqPtSlPAQJg3LprSXjKKOCAXEwggFtMA4G\nA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUjai9\nLj0l+6fULcQb/ryG4zbbMVcwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y\nZD8wIAYDVR0RAQH/BBYwFIESZmdoYW5taUByZWRoYXQuY29tMCkGCisGAQQBg78w\nAQEEG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTArBgorBgEEAYO/MAEIBB0M\nG2h0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbTCBiwYKKwYBBAHWeQIEAgR9BHsA\neQB3AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABmpxVZZkAAAQD\nAEgwRgIhAN/EaO+1X63f2ig60iOsJ44MIL5R+Pj8VPy5B8JxjXnoAiEAnCZBhtRm\nrh1qQyQnn2A+Zzwe85+tt6mkCIfo86GglKcwCgYIKoZIzj0EAwMDZwAwZAIwMnVQ\nX8fDZKQZbQMjb0akx0tzsZetSwOgBQRMxp4IzmstX+4Vlqo/RXG2+ypBk7OKAjB0\nivQN5WW3iytuw3C2fE/flR5Ry/1K8xIXOet4GWZYrITqNw3hPkeRSFKLwE9OSr0=\n-----END CERTIFICATE-----\n",
            "role":"leaf",
            "sans":[
               "jdoe@redhat.com"
            ],
            "serialNumber":"498772634451923774098720019490288427942747112490",
            "subject":""
         },
         "timestamp":"2025-11-19T13:37:15Z",
         "tlogEntry":{
            "canonicalized_body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIxMmY0YTlhMmVlMWRiYmM5YjZkMTUyYTQ5MDk3ZmMzMzQ2OWU5YjEyZmM3MTg1YzZhOTdjNDk4NGYwZTQ5NDU4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUNUL2ZOUEJ3UkZhQjZyVVpDcUhMN1g5L08zM1pVNnYyMEJlZVRCK0NNNEZRSWhBSnhPbi9NZnM0MDJCSTQxSW41TjhPUTJ2UEZtVVY3Wmc5S2ZBekY0OWVlYSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTjVla05EUVd4TFowRjNTVUpCWjBsVlZqRXlPVU14ZFVNelpqSXhSek5RY0dka1MxTlljRzlHUWtOdmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFZlRTFVUlRWTlZFMTZUbnBGZWxkb1kwNU5hbFY0VFZSRk5VMVVUVEJPZWtWNlYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZLWkZONVEzbG1NV2h3ZHl0UFdYWktla1JzTm01RVkzUlNUMGxuYWsxeWJIWjBNemdLZEZkMlkzVnNSbHBOTm5GTE1YUXlSbmxyTmxseVREVkJSblJHTVZRd2RuRlFkRk5zVUVGUlNtY3pUSEJ5VTFocVMwdFBRMEZZUlhkblowWjBUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZxWVdrNUNreHFNR3dyTm1aVlRHTlJZaTl5ZVVjMGVtSmlUVlpqZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBsQldVUldVakJTUVZGSUwwSkNXWGRHU1VWVFdtMWtiMWxYTlhSaFZVSjVXbGRTYjFsWVVYVlpNamwwVFVOclIwTnBjMGRCVVZGQ1p6YzRkd3BCVVVWRlJ6Sm9NR1JJUW5wUGFUaDJXVmRPYW1JelZuVmtTRTExV2pJNWRsb3llR3hNYlU1MllsUkJja0puYjNKQ1owVkZRVmxQTDAxQlJVbENRakJOQ2tjeWFEQmtTRUo2VDJrNGRsbFhUbXBpTTFaMVpFaE5kVm95T1haYU1uaHNURzFPZG1KVVEwSnBkMWxMUzNkWlFrSkJTRmRsVVVsRlFXZFNPVUpJYzBFS1pWRkNNMEZPTURsTlIzSkhlSGhGZVZsNGEyVklTbXh1VG5kTGFWTnNOalF6YW5sMEx6UmxTMk52UVhaTFpUWlBRVUZCUW0xd2VGWmFXbXRCUVVGUlJBcEJSV2QzVW1kSmFFRk9MMFZoVHlzeFdEWXpaakpwWnpZd2FVOXpTalEwVFVsTU5WSXJVR280VmxCNU5VSTRTbmhxV0c1dlFXbEZRVzVEV2tKb2RGSnRDbkpvTVhGUmVWRnViakpCSzFwNmQyVTROU3QwZERadGEwTkpabTg0TmtkbmJFdGpkME5uV1VsTGIxcEplbW93UlVGM1RVUmFkMEYzV2tGSmQwMXVWbEVLV0RobVJGcExVVnBpVVUxcVlqQmhhM2d3ZEhweldtVjBVM2RQWjBKUlVrMTRjRFJKZW0xemRGZ3JORlpzY1c4dlVsaEhNaXQ1Y0VKck4wOUxRV3BDTUFwcGRsRk9OVmRYTTJsNWRIVjNNME15WmtVdlpteFNOVko1THpGTE9IaEpXRTlsZERSSFYxcFpja2xVY1U1M00yaFFhMlZTVTBaTFRIZEZPVTlUY2pBOUNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19",
            "inclusion_promise":{
               "signed_entry_timestamp":"MEUCIQDdNwTBlf15PaOEN1KvCZQh25CXkMK52+xmSIDUouYsywIgS1MYJEWPN0L9QQsYx7MJgPtNy6nIbG+gdzghwv3soks="
            },
            "integrated_time":1763559435,
            "kind_version":{
               "kind":"hashedrekord",
               "version":"0.0.1"
            },
            "log_id":{
               "key_id":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
            },
            "log_index":708587072
         }
      }
   ],
   "summary":{
      "attestationCount":1,
      "rekorEntryCount":2,
      "signatureCount":1
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

This generates Go types such as `RekorEntry`, `VerifyArtifactResponse`, and others.
