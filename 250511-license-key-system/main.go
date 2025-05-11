package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// LicenseData represents the license information to be saved
type LicenseData struct {
	DeviceID    string `json:"device_id"`
	DeviceUUID  string `json:"device_uuid"`
	LicenseKey  string `json:"license_key"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key,omitempty"` // Only stored for the licensor
	NamespaceID string `json:"namespace_id"`
}

// Config holds the key pair for signing
type Config struct {
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
	NamespaceID uuid.UUID
}

// SaveConfig saves the configuration to a file
func SaveConfig(config *Config, filename string) error {
	data := struct {
		PrivateKey  string `json:"private_key"`
		PublicKey   string `json:"public_key"`
		NamespaceID string `json:"namespace_id"`
	}{
		PrivateKey:  hex.EncodeToString(config.PrivateKey),
		PublicKey:   hex.EncodeToString(config.PublicKey),
		NamespaceID: config.NamespaceID.String(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	return os.WriteFile(filename, jsonData, 0600)
}

// LoadConfig loads the configuration from a file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var configData struct {
		PrivateKey  string `json:"private_key"`
		PublicKey   string `json:"public_key"`
		NamespaceID string `json:"namespace_id"`
	}

	if err := json.Unmarshal(data, &configData); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	privKeyBytes, err := hex.DecodeString(configData.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key format: %v", err)
	}

	namespaceID, err := uuid.Parse(configData.NamespaceID)
	if err != nil {
		return nil, fmt.Errorf("invalid namespace UUID: %v", err)
	}

	privKey := ed25519.PrivateKey(privKeyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	return &Config{
		PrivateKey:  privKey,
		PublicKey:   pubKey,
		NamespaceID: namespaceID,
	}, nil
}

// GenerateKeyPair creates a new ED25519 key pair
func GenerateKeyPair() (*Config, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	// Generate a random namespace UUID
	namespaceID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate namespace UUID: %v", err)
	}

	return &Config{
		PrivateKey:  privKey,
		PublicKey:   pubKey,
		NamespaceID: namespaceID,
	}, nil
}

// GetBRLANMacAddress attempts to find the BR-LAN interface and returns its MAC address
func GetBRLANMacAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	// First try to find an interface named br-lan (common in OpenWrt routers)
	for _, iface := range interfaces {
		if iface.Name == "br-lan" {
			return iface.HardwareAddr.String(), nil
		}
	}

	// If br-lan is not found, try to find a primary interface that's up and not a loopback
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && // interface is up
			iface.Flags&net.FlagLoopback == 0 && // not a loopback
			len(iface.HardwareAddr) > 0 { // has a MAC address
			return iface.HardwareAddr.String(), nil
		}
	}

	return "", fmt.Errorf("could not find BR-LAN interface or suitable network interface")
}

// MacAddressToUUIDv5 converts a MAC address to a UUIDv5 using our namespace
func MacAddressToUUIDv5(macAddress string, namespaceID uuid.UUID) (uuid.UUID, error) {
	// Clean up the MAC address (remove colons if present)
	macAddress = strings.ReplaceAll(macAddress, ":", "")

	// Generate a UUIDv5 from the MAC address using our namespace
	return uuid.NewSHA1(namespaceID, []byte(macAddress)), nil
}

// GenerateLicenseKey creates a license key by signing the UUID with ED25519
func GenerateLicenseKey(config *Config, id uuid.UUID) (string, error) {
	// Sign the UUID bytes with our private key
	signature := ed25519.Sign(config.PrivateKey, id[:])

	// Encode the signature as base64 for the license key
	licenseKey := base64.StdEncoding.EncodeToString(signature)

	return licenseKey, nil
}

// SaveLicense saves the license information to a file
func SaveLicense(licenseData *LicenseData, filename string) error {
	jsonData, err := json.MarshalIndent(licenseData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal license data: %v", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	return os.WriteFile(filename, jsonData, 0600)
}

// LoadLicense loads license information from a file
func LoadLicense(filename string) (*LicenseData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %v", err)
	}

	var licenseData LicenseData
	if err := json.Unmarshal(data, &licenseData); err != nil {
		return nil, fmt.Errorf("failed to parse license file: %v", err)
	}

	return &licenseData, nil
}

// VerifyLicense checks if a license key is valid for a given UUID
func VerifyLicense(publicKeyHex string, idStr string, licenseKey string, namespaceIDStr string) (bool, error) {
	// Parse public key
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key format: %v", err)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)

	// Parse UUID
	id, err := uuid.Parse(idStr)
	if err != nil {
		return false, fmt.Errorf("invalid UUID format: %v", err)
	}

	// Decode the license key from base64
	signature, err := base64.StdEncoding.DecodeString(licenseKey)
	if err != nil {
		return false, fmt.Errorf("invalid license key format: %v", err)
	}

	// Verify the signature using the public key
	return ed25519.Verify(publicKey, id[:], signature), nil
}

// GenerateNamespaceUUID generates a new random UUID to use as a namespace
func GenerateNamespaceUUID() (uuid.UUID, error) {
	return uuid.NewRandom()
}

func commandInitConfig() {
	configPtr := flag.String("config", "licensor.json", "Configuration file path")
	flag.Parse()

	// Check if config already exists
	if _, err := os.Stat(*configPtr); err == nil {
		fmt.Printf("Configuration file %s already exists. Delete it first if you want to reinitialize.\n", *configPtr)
		return
	}

	// Generate new keypair and namespace
	config, err := GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating configuration: %v\n", err)
		return
	}

	// Save the configuration
	if err := SaveConfig(config, *configPtr); err != nil {
		fmt.Printf("Error saving configuration: %v\n", err)
		return
	}

	fmt.Println("License issuer configuration initialized successfully.")
	fmt.Printf("Configuration saved to: %s\n", *configPtr)
	fmt.Printf("Namespace UUID: %s\n", config.NamespaceID)
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(config.PublicKey))
	fmt.Println("\nKeep your private key secure. It will be needed to generate valid license keys.")
}

func commandGenerateNamespace() {
	namespaceID, err := GenerateNamespaceUUID()
	if err != nil {
		fmt.Printf("Error generating namespace UUID: %v\n", err)
		return
	}

	fmt.Println("Generated new namespace UUID:")
	fmt.Println(namespaceID.String())
}

func commandGenerateLicense() {
	configPtr := flag.String("config", "licensor.json", "Configuration file path")
	macPtr := flag.String("mac", "", "MAC address (if not provided, will detect automatically)")
	outputPtr := flag.String("output", "license.json", "Output license file")
	flag.Parse()

	// Load configuration
	config, err := LoadConfig(*configPtr)
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}

	// Get MAC address
	var macAddress string
	if *macPtr != "" {
		macAddress = *macPtr
	} else {
		macAddress, err = GetBRLANMacAddress()
		if err != nil {
			fmt.Printf("Error getting MAC address: %v\n", err)
			return
		}
	}

	// Convert MAC to UUID
	deviceUUID, err := MacAddressToUUIDv5(macAddress, config.NamespaceID)
	if err != nil {
		fmt.Printf("Error generating UUID: %v\n", err)
		return
	}

	// Generate license key
	licenseKey, err := GenerateLicenseKey(config, deviceUUID)
	if err != nil {
		fmt.Printf("Error generating license key: %v\n", err)
		return
	}

	// Create and save license data
	licenseData := &LicenseData{
		DeviceID:    macAddress,
		DeviceUUID:  deviceUUID.String(),
		LicenseKey:  licenseKey,
		PublicKey:   hex.EncodeToString(config.PublicKey),
		NamespaceID: config.NamespaceID.String(),
	}

	if err := SaveLicense(licenseData, *outputPtr); err != nil {
		fmt.Printf("Error saving license: %v\n", err)
		return
	}

	fmt.Println("License generated successfully:")
	fmt.Printf("  Device ID: %s\n", macAddress)
	fmt.Printf("  Device UUID: %s\n", deviceUUID)
	fmt.Printf("  License Key: %s\n", licenseKey)
	fmt.Printf("  License file saved to: %s\n", *outputPtr)
}

func commandVerifyLicense() {
	licenseFilePtr := flag.String("license", "license.json", "License file to verify")
	macPtr := flag.String("mac", "", "MAC address to check (if not provided, will detect automatically)")
	flag.Parse()

	// Load license data
	licenseData, err := LoadLicense(*licenseFilePtr)
	if err != nil {
		fmt.Printf("Error loading license: %v\n", err)
		return
	}

	// Get MAC address to verify
	var macAddress string
	if *macPtr != "" {
		macAddress = *macPtr
	} else {
		macAddress, err = GetBRLANMacAddress()
		if err != nil {
			fmt.Printf("Error getting MAC address: %v\n", err)
			return
		}
	}

	// Parse namespace UUID
	namespaceID, err := uuid.Parse(licenseData.NamespaceID)
	if err != nil {
		fmt.Printf("Error parsing namespace UUID: %v\n", err)
		return
	}

	// Convert MAC to UUID using the same namespace as the license
	deviceUUID, err := MacAddressToUUIDv5(macAddress, namespaceID)
	if err != nil {
		fmt.Printf("Error generating UUID: %v\n", err)
		return
	}

	// Verify the license
	valid, err := VerifyLicense(
		licenseData.PublicKey,
		deviceUUID.String(),
		licenseData.LicenseKey,
		licenseData.NamespaceID,
	)

	if err != nil {
		fmt.Printf("Error verifying license: %v\n", err)
		return
	}

	fmt.Printf("MAC Address: %s\n", macAddress)
	fmt.Printf("Device UUID: %s\n", deviceUUID)

	if valid {
		fmt.Println("License verification: VALID")
	} else {
		fmt.Println("License verification: INVALID")
	}
}

func printUsage() {
	fmt.Println("License Key Manager")
	fmt.Println("\nUsage:")
	fmt.Println("  license-manager [command] [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  init        Initialize licensor configuration with new keys")
	fmt.Println("  generate    Generate a license key for a device")
	fmt.Println("  verify      Verify a license key")
	fmt.Println("  namespace   Generate a new namespace UUID")
	fmt.Println("\nRun 'license-manager [command] -h' for specific command options")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	switch command {
	case "init":
		commandInitConfig()
	case "generate":
		commandGenerateLicense()
	case "verify":
		commandVerifyLicense()
	case "namespace":
		commandGenerateNamespace()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}
