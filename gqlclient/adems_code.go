package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"

	"github.com/google/uuid"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/events"
	oam "github.com/owasp-amass/open-asset-model"
	oamContact "github.com/owasp-amass/open-asset-model/contact"
	fqdn "github.com/owasp-amass/open-asset-model/domain"
	oamNet "github.com/owasp-amass/open-asset-model/network"
	oamOrg "github.com/owasp-amass/open-asset-model/org"
	oamPeople "github.com/owasp-amass/open-asset-model/people"
	oamWHOIS "github.com/owasp-amass/open-asset-model/whois"
)

// Constants to represent the IPv4 and IPv6 types.
const (
	ipv4 = "IPv4"
	ipv6 = "IPv6"
)

// TODO:
// PUT THE REQUEST STRUCT AND ASSET STRUCT SO THE CLIENT AND SERVER DOES NOT HAVE DUOPLICATED CODE
// Send data to event scheduler & process it. I already have a function to put data into the event struct
// We just need to process it.

// please just look at my code and see if you can make it better and utilize it for your needs.
// I am not a go expert.

// Request struct to hold the configuration details.
type Request struct {
	Config *config.Config `json:"config,omitempty"`
}

// Asset struct to hold the details about an asset.
type Asset struct {
	Session uuid.UUID `json:"session_id,omitempty"`
	Event   string    `json:"event_name,omitempty"`
	Data    AssetData `json:"data,omitempty"`
}

type AssetData struct {
	OAMAsset oam.Asset     `json:"asset"`
	OAMType  oam.AssetType `json:"type"`
}

func adems_code_for_main_func() {
	// Define a command-line flag and parse the command-line arguments.
	cf := flag.String("cf", "", "config file to use")
	flag.Parse()

	// Populate the Request struct with the acquired configuration.
	Request := Request{
		Config: config.NewConfig(),
	}

	// Acquire the configuration from the specified file.
	err := config.AcquireConfig("", *cf, Request.Config)
	if err != nil {
		fmt.Println(err) // Handle any errors that occur during configuration acquisition.
	}

	// Convert the Request struct to a JSON object.
	sessionJSON, err := json.Marshal(Request)
	if err != nil {
		log.Fatalf("Error occurred during marshalling: %s", err) // Handle errors that occur during JSON marshalling.
	}

	// **DEBUG TO SHOW THE JSON STRING**
	jsonString := string(sessionJSON)
	fmt.Println(jsonString)

	// ***DEBUG*** Unmarshal the JSON string back into a Request object and handle any errors.
	// fmt.Println("Config address: ", &Request.Config, "\n")
	// request, err := UnmarshalRequest(jsonString)
	// if err != nil {
	// 	log.Fatalf("Error unmarshalling Request: %s", err)
	// }

	// *** DEBUG*** Print the unmarshalled Request object and its Config field.
	// fmt.Printf("Unmarshalled Request: %+v\n", request)
	// fmt.Printf("Config: %+v\n", request.Config)

	// ***DEBUG*** Print the Scope field of the Config object.
	// fmt.Printf("Scope: %+v\n", request.Config.Scope)

	// Convert the scopes in the configuration to assets.
	Assets := convertScopeToAssets(Request.Config.Scope)

	// Initialize the event scheduler.
	events.MainSchedulerInit()

	// Iterate over each asset, marshal it to JSON, and unmarshal it back to an Asset object.
	// for the client and the server, you still should run through the loop like i did here
	// but only utilized the code that applies to the client or server.
	i := 1
	for _, asset := range Assets {
		asset.Event = "asset#" + strconv.Itoa(i)
		i++
		assetJSON, err := json.Marshal(asset)
		if err != nil {
			log.Fatalf("Error occurred during marshalling: %s", err) // Handle marshalling errors.
		}

		// ***DEBUG*** PRINT THE ASSET JSON STRING
		assetString := string(assetJSON)
		fmt.Println("\n", assetString)

		// Unmarshal the asset JSON into an Asset object.
		unmarshalledAsset := &Asset{}
		err = json.Unmarshal(assetJSON, unmarshalledAsset)
		if err != nil {
			log.Fatalf("Error occurred during unmarshalling: %s", err) // Handle unmarshalling errors.
		}

		// ***DEBUG*** Print the unmarshalled Asset object.
		// fmt.Printf("Unmarshalled Asset: %+v\n", unmarshalledAsset)

		event2Send := unmarshalledAsset.asset2Event()
		// ***DEBUG*** Print the Event struct that was created from the Asset.
		// fmt.Printf("Event: %+v\n", event2Send)

		// Send the event to the event scheduler.
		err = events.MainSchedulerSchedule(event2Send)
		if err != nil {
			log.Fatalf("Error occurred during scheduling: %s", err) // Handle scheduling errors.
		}
	}
}

// asset2Event converts an Asset to an Event. with the event name and data
func (a *Asset) asset2Event() *events.Event {
	return &events.Event{
		Name: a.Event,
		Data: a.Data,
		Type: events.EventTypeSay,
	}
}

// convertScopeToAssets converts all items in a Scope to a slice of *Asset.
func convertScopeToAssets(scope *config.Scope) []*Asset {
	var assets []*Asset

	// Convert Domains to assets.
	for _, domain := range scope.Domains {
		fqdn := fqdn.FQDN{Name: domain}
		data := AssetData{
			OAMAsset: fqdn,
			OAMType:  fqdn.AssetType(),
		}
		asset := &Asset{
			Data: data,
		}
		assets = append(assets, asset)
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
			data := AssetData{
				OAMAsset: asset,
				OAMType:  asset.AssetType(),
			}
			assets = append(assets, &Asset{Data: data})
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
		data := AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &Asset{Data: data})
	}

	// Convert ASNs to assets.
	for _, asn := range scope.ASNs {
		asset := oamNet.AutonomousSystem{Number: asn}
		data := AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &Asset{Data: data})
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

// UnmarshalJSON is a custom unmarshaller for the Asset type, overriding the default JSON unmarshalling behavior.
// This method is automatically invoked when 'json.Unmarshal' is called with an 'Asset' type (or pointer),
// provided that the input JSON structure matches the Asset structure.
//
// The 'data' parameter holds the raw JSON data that is to be unmarshalled. This method's responsibility is to
// process (parse and decode) this data and populate the 'Asset' struct's fields accordingly.
//
// If the method encounters any issue during unmarshalling that prevents successful completion,
// it must return an error which will be propagated back through the call to 'json.Unmarshal'.
//
// This custom unmarshalling is particularly useful for handling complex scenarios during JSON decoding,
// such as when the structure of JSON data doesn't map cleanly to the structure of the Go type,
// or when some form of data transformation or validation is required during the unmarshalling process.
//
// Instead of having this here, we should implement this in the open-asset-model.
// That way, others dont have to re-invent the wheel.
func (d *AssetData) UnmarshalJSON(data []byte) error {
	// First, unmarshal to a temporary struct to get the AssetType without unmarshalling the asset itself
	var tmp struct {
		OAMType  oam.AssetType   `json:"type"`
		RawAsset json.RawMessage `json:"asset"` // Capture the asset as raw JSON
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	// Populate the known fields

	d.OAMType = tmp.OAMType

	// Based on the AssetType, we'll unmarshal the RawAsset into the appropriate struct
	switch tmp.OAMType {
	case oam.IPAddress:
		var asset oamNet.IPAddress
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Netblock:
		var asset oamNet.Netblock
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.ASN:
		var asset oamNet.AutonomousSystem
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.RIROrg:
		var asset oamNet.RIROrganization
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.FQDN:
		var asset fqdn.FQDN
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.WHOIS:
		var asset oamWHOIS.WHOIS
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Location:
		var asset oamContact.Location
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Phone:
		var asset oamContact.Phone
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Email:
		var asset oamContact.EmailAddress
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Person:
		var asset oamPeople.Person
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Organization, oam.Registrant:
		var asset oamOrg.Organization
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	case oam.Registrar:
		var asset oamWHOIS.Registrar
		if err := json.Unmarshal(tmp.RawAsset, &asset); err != nil {
			return err
		}
		d.OAMAsset = asset

	default:
		return fmt.Errorf("unknown or unsupported asset type: %s", tmp.OAMType)
	}

	return nil
}
