package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/google/uuid"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	fqdn "github.com/owasp-amass/open-asset-model/domain"
	oamNet "github.com/owasp-amass/open-asset-model/network"
)

// Constants to represent the IPv4 and IPv6 types.
const (
	ipv4 = "IPv4"
	ipv6 = "IPv6"
)

// TODO:
// PUT THE REQUEST STRUCT AND ASSET STRUCT SO THE CLIENT AND SERVER DOES NOT HAVE DUOPLICATED CODE
// FIX THE UNMARSHALLING OF THE ASSET STRUCT

// Request struct to hold the configuration details.
type Request struct {
	Config *config.Config `json:"config,omitempty"`
}

// Asset struct to hold the details about an asset.
type Asset struct {
	Session  uuid.UUID     `json:"session_id,omitempty"`
	Event    string        `json:"event_name,omitempty"`
	OAMAsset oam.Asset     `json:"asset"`
	OAMType  oam.AssetType `json:"type"`
}

func adems_code_for_main_func() {
	// Define a command-line flag and parse the command-line arguments.
	cf := flag.String("cf", "", "config file to use")
	flag.Parse()

	// Create a new configuration instance.
	testConf := config.NewConfig()

	// Acquire the configuration from the specified file.
	err := config.AcquireConfig("", *cf, testConf)
	if err != nil {
		fmt.Println(err) // Handle any errors that occur during configuration acquisition.
	}

	// Populate the Request struct with the acquired configuration.
	Request := Request{
		Config: testConf,
	}

	// Convert the Request struct to a JSON object.
	sessionJSON, err := json.Marshal(Request)
	if err != nil {
		log.Fatalf("Error occurred during marshalling: %s", err) // Handle errors that occur during JSON marshalling.
	}

	// Convert the JSON bytes to a string and print it.
	jsonString := string(sessionJSON)
	fmt.Println(jsonString) // **DEBUG TO SHOW THE JSON STRING**

	// ***DEBUG*** Unmarshal the JSON string back into a Request object and handle any errors.
	// fmt.Println("Config address: ", &testConf, "\n")
	// request, err := UnmarshalRequest(jsonString)
	// if err != nil {
	// 	log.Fatalf("Error unmarshalling Request: %s", err)
	// }

	// *** DEBUG*** Print the unmarshalled Request object and its Config field.
	// fmt.Printf("Unmarshalled Request: %+v\n", request)
	// fmt.Printf("Config: %+v\n", request.Config)

	// Convert the scopes in the configuration to assets.
	Assets := convertScopeToAssets(testConf.Scope)

	// Iterate over each asset, marshal it to JSON, and unmarshal it back to an Asset object.
	for _, asset := range Assets {
		assetJSON, err := json.Marshal(asset)
		if err != nil {
			log.Fatalf("Error occurred during marshalling: %s", err) // Handle marshalling errors.
		}
		assetString := string(assetJSON)
		fmt.Println(assetString) // ***DEBUG*** PRINT THE ASSET JSON STRING

		// ***DEBUG*** Unmarshal the asset JSON into an Asset object.
		// unmarshalledAsset := &Asset{}
		// err = json.Unmarshal(assetJSON, unmarshalledAsset)
		// if err != nil {
		// 	log.Fatalf("Error occurred during unmarshalling: %s", err) // Handle unmarshalling errors.
		// }

		// ***DEBUG*** Print the unmarshalled Asset object.
		// fmt.Printf("Unmarshalled Asset: %+v\n", unmarshalledAsset)
	}
}

// convertScopeToAssets converts all items in a Scope to a slice of *Asset.
func convertScopeToAssets(scope *config.Scope) []*Asset {
	var assets []*Asset

	// Convert Domains to assets.
	for _, domain := range scope.Domains {
		fqdn := fqdn.FQDN{Name: domain}
		assets = append(assets, &Asset{
			OAMAsset: fqdn,
			OAMType:  fqdn.AssetType(),
		})
	}

	var ipType string

	// Convert Addresses to assets.
	for _, ip := range scope.Addresses {
		// Convert net.IP to net.IPAddr.
		if addr, ok := netip.AddrFromSlice(ip); ok {
			// Determine the IP type based on the address characteristics.
			if addr.Is4In6() {
				addr = netip.AddrFrom4(addr.As4())
				ipType = ipv4
			} else if addr.Is6() {
				ipType = ipv6
			} else {
				ipType = ipv4
			}

			// Create an asset from the IP address and append it to the assets slice.
			asset := oamNet.IPAddress{Address: addr, Type: ipType}
			assets = append(assets, &Asset{
				OAMAsset: asset,
				OAMType:  asset.AssetType(),
			})
		}
	}

	// Convert CIDRs to assets.
	for _, cidr := range scope.CIDRs {
		prefix := ipnet2Prefix(*cidr) // Convert net.IPNet to netip.Prefix.

		// Determine the IP type based on the address characteristics.
		addr := prefix.Addr()
		if addr.Is4In6() {
			ipType = ipv4
		} else if addr.Is6() {
			ipType = ipv6
		} else {
			ipType = ipv4
		}

		// Create an asset from the CIDR and append it to the assets slice.
		asset := oamNet.Netblock{Cidr: prefix, Type: ipType}
		assets = append(assets, &Asset{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		})
	}

	// Convert ASNs to assets.
	for _, asn := range scope.ASNs {
		asset := oamNet.AutonomousSystem{Number: asn}
		assets = append(assets, &Asset{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		})
	}

	return assets
}

// ipnet2Prefix converts a net.IPNet to a netip.Prefix.
func ipnet2Prefix(ipn net.IPNet) netip.Prefix {
	addr, _ := netip.AddrFromSlice(ipn.IP)
	cidr, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr, cidr)
}

// UnmarshalRequest unmarshals a JSON string into a Request object.
func UnmarshalRequest(jsonData string) (*Request, error) {
	// Declare a new Request struct variable.
	var req Request
	// Unmarshal the jsonData into the req variable.
	err := json.Unmarshal([]byte(jsonData), &req)
	// If there was an error during unmarshalling, return nil and the error.
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling Request: %w", err)
	}
	// Otherwise, return a pointer to the req variable and nil for the error.
	return &req, nil
}

// UnmarshalAsset unmarshals a JSON string into an Asset object.
// THIS IS BROKEN MUST FIX LATER
func UnmarshalAsset(jsonData string) (*Asset, error) {
	var asset Asset
	err := json.Unmarshal([]byte(jsonData), &asset)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling Asset: %w", err)
	}
	return &asset, nil
}
