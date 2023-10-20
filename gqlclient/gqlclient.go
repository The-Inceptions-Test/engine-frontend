package main

import (
	"bytes"
//	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"io/ioutil"
)

type GraphQLClient struct {
	Endpoint string
}

func Initialize(endpoint string) *GraphQLClient {
	return &GraphQLClient{
		Endpoint: endpoint,
	}
}

func (c *GraphQLClient) SendData(query string) (map[string]interface{}, error) {
	// Create a JSON payload with the GraphQL query
	
	payload := map[string]interface{}{
		"query": query,
	}
	
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	//payload := "{\"query\":\"" +query+ "\"}"
	fmt.Println(payload)
	
	
	//payloadBytes := []byte(query)
	// Create an HTTP request with the JSON payload
	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Create an HTTP client
	client := &http.Client{}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("here")
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		fmt.Println(string(respBody))
		return nil, fmt.Errorf("Received a non-OK status code: %d from GraphQL server", resp.StatusCode)
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(respBody, &responseData); err != nil {
        fmt.Println("Error:", err)
        return nil, err
    }

	return responseData, nil
}

