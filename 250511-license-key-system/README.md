# License Manager

A hardware-bound license management system written in Go that creates and verifies cryptographically secure license keys tied to device MAC addresses.

## Features

- **Hardware binding**: Licenses are bound to device MAC addresses
- **Cryptographic security**: Uses ED25519 for secure digital signatures
- **One-way transformation**: MAC addresses cannot be reverse-engineered from license keys
- **Custom namespaces**: Create unique license namespaces for different products
- **JSON storage**: License and configuration data stored in structured JSON files
- **Command-line interface**: Easy-to-use commands for all operations

## Security Model

This license manager implements several security principles:

1. **Hardware binding**: Licenses are tied to physical device hardware (MAC address)
2. **Cryptographic verification**: ED25519 digital signatures ensure license authenticity
3. **One-way transformation**: UUIDv5 + signature process makes it impossible to extract MAC addresses from license keys
4. **Namespace isolation**: Different products/versions can use separate namespaces
5. **Private key protection**: Private keys are only stored in the licensor configuration

## Installation

### Prerequisites

- Go 1.16 or later
- [github.com/google/uuid](https://github.com/google/uuid) package

### Building from source

```bash
# Install the UUID dependency
go get github.com/google/uuid

# Build the application
go build -o license-manager main.go
```

## Usage

The license manager provides four main commands:

### Initialize License Issuer

Create a new license issuer configuration with unique keys and namespace:

```bash
# Initialize with default configuration file (licensor.json)
./license-manager init

# Or specify a custom configuration file
./license-manager init --config my-product.json
```

This creates a licensor configuration file containing:
- ED25519 private key (for signing licenses)
- ED25519 public key (for verifying licenses)
- A unique namespace UUID

**Important**: Keep your licensor configuration secure! The private key can be used to generate valid licenses.

### Generate a License

Create a license for a device:

```bash
# Generate license for the current device
./license-manager generate --config licensor.json --output license.json

# Generate license for a specific MAC address
./license-manager generate --config licensor.json --mac "00:11:22:33:44:55" --output customer-license.json
```

This creates a license file containing:
- Device MAC address
- Device UUIDv5 (derived from MAC address)
- License key (cryptographic signature)
- Public key (for verification)
- Namespace ID

### Verify a License

Check if a license is valid for a device:

```bash
# Verify for the current device
./license-manager verify --license license.json

# Verify for a specific MAC address
./license-manager verify --license license.json --mac "00:11:22:33:44:55"
```

### Generate a Namespace UUID

Create a random UUID to use as a custom namespace:

```bash
./license-manager namespace
```

## Example Workflow

1. **Initialize the license issuer** (on your secure development machine):
   ```bash
   ./license-manager init --config myapp-licensor.json
   ```

2. **Generate licenses** for your customers (on your secure development machine):
   ```bash
   ./license-manager generate --config myapp-licensor.json --mac "00:11:22:33:44:55" --output customer1-license.json
   ```

3. **Distribute** the license file to your customer.

4. **Verify the license** in your application (on the customer's device):
   ```bash
   ./license-manager verify --license customer1-license.json
   ```

## Integration with Applications

### License Verification in Your Application

You can integrate the license verification into your Go application:

```go
package main

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "github.com/google/uuid"
    "net"
)

func VerifyLicense(publicKeyHex, namespaceIDStr, licenseKey string) (bool, error) {
    // Get MAC address
    mac, err := GetBRLANMacAddress()
    if err != nil {
        return false, err
    }

    // Parse namespace
    namespaceID, err := uuid.Parse(namespaceIDStr)
    if err != nil {
        return false, err
    }

    // Generate UUID from MAC
    deviceUUID := uuid.NewSHA1(namespaceID, []byte(mac))

    // Parse public key
    publicKeyBytes, err := hex.DecodeString(publicKeyHex)
    if err != nil {
        return false, err
    }
    publicKey := ed25519.PublicKey(publicKeyBytes)

    // Decode license key
    signature, err := base64.StdEncoding.DecodeString(licenseKey)
    if err != nil {
        return false, err
    }

    // Verify signature
    return ed25519.Verify(publicKey, deviceUUID[:], signature), nil
}
```

## Security Considerations

- **Keep private keys secure**: Never distribute your licensor configuration or private key
- **Use different namespaces**: Create different namespaces for different products or versions
- **Offline verification**: License verification works offline once the license file is distributed
- **MAC address spoofing**: While MAC addresses can be spoofed, this adds a barrier to casual copying
- **Hardware changes**: If a customer changes their network hardware, they will need a new license

## License File Format

The license file is a JSON document with the following structure:

```json
{
  "device_id": "00:11:22:33:44:55",
  "device_uuid": "12345678-1234-5678-1234-567812345678",
  "license_key": "base64EncodedSignature...",
  "public_key": "hex-encoded-ed25519-public-key",
  "namespace_id": "namespace-uuid-string"
}
```

## Licensor Configuration Format

The licensor configuration file is a JSON document with the following structure:

```json
{
  "private_key": "hex-encoded-ed25519-private-key",
  "public_key": "hex-encoded-ed25519-public-key",
  "namespace_id": "namespace-uuid-string"
}
```

## Technical Details

### License Key Generation Process

1. Read the device MAC address
2. Transform the MAC address into a UUIDv5 using the namespace
3. Sign the UUID bytes using the ED25519 private key
4. Encode the signature as base64 to create the license key

### License Verification Process

1. Read the device MAC address
2. Transform the MAC address into a UUIDv5 using the same namespace
3. Verify the signature (license key) against the UUID using the ED25519 public key

## Troubleshooting

### "Could not find BR-LAN interface"

By default, the program looks for an interface named "br-lan" (common in OpenWrt routers). If not found, it falls back to the first active non-loopback interface.

If you need to specify a particular interface, use the `--mac` flag with the appropriate MAC address.

### "License verification: INVALID"

This can happen if:
- The MAC address has changed (new network hardware)
- The license was generated with a different namespace
- The license key was tampered with
- The wrong public key is being used for verification

### "Error loading configuration"

Check that the path to your configuration file is correct and that the file is a valid JSON document created by the `init` command.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is released under the MIT License.