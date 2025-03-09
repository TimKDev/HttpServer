package httpparser

import (
	"fmt"
)

func PrintRequest(request *HttpRequest) {
	fmt.Println("HTTP Request:")
	fmt.Printf("Methode: %s\n", request.Method)
	fmt.Printf("Target: %s\n", request.Target)
	if len(request.Headers) != 0 {
		fmt.Println("Headers:")
	}
	for key, value := range request.Headers {
		fmt.Printf("%s : %s\n", key, value)
	}
	if request.Body != "" {
		fmt.Println("Body:")
		fmt.Println(request.Body)
	}
}

func PrintResponse(response *HttpResponse) {
	fmt.Println("HTTP Response:")
	fmt.Printf("Status: %s\n", response.Status)
	if len(response.Headers) != 0 {
		fmt.Println("Headers:")
	}
	for key, value := range response.Headers {
		fmt.Printf("%s : %s\n", key, value)
	}
	if response.Body != "" {
		fmt.Println("Body:")
		fmt.Println(response.Body)
	}
}
