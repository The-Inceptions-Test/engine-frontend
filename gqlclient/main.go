package main

import (

	"fmt"
	//"encoding/json"
	//"github.com/The-Inceptions-Test/config"
)




type Event struct {
	ID string `json:"id"`
}

type Session struct {
	Token string `json:"token"`
}

type Data struct {
    Session Session `json:"session"`
}


// Temp
type Config struct {

}

func main() {
	// Initialize the GraphQL client with your server's endpoint
	client := Initialize("http://localhost:8080/graphql")

	// Define your GraphQL query
	InitEngineSession(client)
	

	// Print the JSON response
	//fmt.Printf("Response: %+v\n", response)
}

// Returns a session token
func InitEngineSession(client *GraphQLClient/*Config config*/) (Session, error) {

	session := Session{}

	query := `
		mutation {
			createSession(input: {config: "x"}) {
				token
			}
		}
	`
	// Send the query and handle the response
	response, err := client.SendData(query)
	if err != nil {
		fmt.Printf("Error x: %v\n", err)
		//return session, fmt.Errorf("error sending graphql query: %v", err)
	}

	fmt.Println(response)

	/*
	var data Data
	if err := json.Unmarshal(response, &data); err != nil {
        fmt.Printf("Error: %v\n", err)
        return session, err
    }
	*/
	/*
	data, ok := response["data"]
	fmt.Println("data:",data)
	if !ok {
		fmt.Println("Response does not contain data field.")
		//return session, err
	}
*/
	
	
	/*
	responseData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Error encoding data: %v\n", err)
		return session, err
	}
*/
	//fmt.Printf("Response Data: %s\n", string(responseData))
	//return session, nil
/*
	if err := json.Unmarshal(jsonData, &root); err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

*/
//	 token := root.Data.Session.Token
//   fmt.Printf("Token: %s\n", token)

	return session, nil
}
