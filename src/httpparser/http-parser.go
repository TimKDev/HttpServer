package httpparser

import (
	"errors"
	"fmt"
	"log"
	"strings"
)

type HttpMethod string

const (
	Get    HttpMethod = "GET"
	Post   HttpMethod = "POST"
	Put    HttpMethod = "PUT"
	Delete HttpMethod = "DELETE"
)

type HttpStatus string

const (
	Forbidden           HttpStatus = "403 Forbidden"
	Ok                  HttpStatus = "200 OK"
	Created             HttpStatus = "201 Created"
	NoContent           HttpStatus = "204 No Content"
	NotFound            HttpStatus = "404 Not Found"
	BadRequest          HttpStatus = "400 Bad Request"
	InternalServerError HttpStatus = "500 Internal Server Error"
)

type V1UnroutedHttpRequest struct {
	method  HttpMethod        //16 bytes = 8 bytes for pointer + 8 bytes for size (wie dynamic array in C)
	target  string            //16 bytes = 8 bytes for pointer + 8 bytes for size (wie dynamic array in C)
	headers map[string]string //8 bytes for pointer
	body    string            //16 bytes = 8 bytes for pointer + 8 bytes for size (wie dynamic array in C)
}

type V1HttpResponse struct {
	status  HttpStatus
	headers map[string]string
	body    string
}

func printRequest(request *V1UnroutedHttpRequest) {
	fmt.Println("HTTP Request:")
	fmt.Printf("Methode: %s\n", request.method)
	fmt.Printf("Target: %s\n", request.target)
	if len(request.headers) != 0 {
		fmt.Println("Headers:")
	}
	for key, value := range request.headers {
		fmt.Printf("%s : %s\n", key, value)
	}
	if request.body != "" {
		fmt.Println("Body:")
		fmt.Println(request.body)
	}
}
func printResponse(response *V1HttpResponse) {
	fmt.Println("HTTP Response:")
	fmt.Printf("Status: %s\n", response.status)
	if len(response.headers) != 0 {
		fmt.Println("Headers:")
	}
	for key, value := range response.headers {
		fmt.Printf("%s : %s\n", key, value)
	}
	if response.body != "" {
		fmt.Println("Body:")
		fmt.Println(response.body)
	}
}

func convertV1HttpResponse(response *V1HttpResponse) []byte {
	capacity := 128 + len(response.status) + len(response.body)
	for k, v := range response.headers {
		capacity += len(k) + len(v) + 4 // 4 for ": " and "\r\n"
	}

	result := make([]byte, 0, capacity)
	result = append(result, []byte("HTTP/1.1 "+string(response.status)+"\r\n")...)
	for key, value := range response.headers {
		line := key + ": " + value + "\r\n"
		result = append(result, []byte(line)...)
	}
	// Empty line always need to be set even if the request has no header
	result = append(result, []byte("\r\n")...)
	if response.body != "" {
		result = append(result, []byte(response.body)...)
	}
	//Every http request should end with an empty line. Otherwise you get something like a % in the response.
	result = append(result, []byte("\r\n")...)

	return result
}

func convertToHttpRequest(buf []byte) (*V1UnroutedHttpRequest, error) {
	if len(buf) == 0 {
		return nil, errors.New("empty request buffer")
	}
	bufSeparatedByNewLines := strings.Split(string(buf), "\r\n")
	startLine := strings.Split(bufSeparatedByNewLines[0], " ")
	if len(startLine) < 3 {
		return nil, errors.New("invalid startline")
	}

	method := HttpMethod(startLine[0])
	requestTarget := startLine[1]
	httpVersion := startLine[2]

	if !strings.Contains(httpVersion, "HTTP/1") {
		return nil, errors.New("only protocol version HTTP/1.1 is supported")
	}

	headers := make(map[string]string)
	bodyStartLine := 0
	for index, line := range bufSeparatedByNewLines {
		if index == 0 {
			continue
		}
		if line == "" || line == " " {
			bodyStartLine = index
			break
		}
		headerSplit := strings.SplitN(line, ":", 2)
		if len(headerSplit) < 2 {
			log.Printf("WARNING: Header %q is malformatted and is therefore ignored.", line)
			continue
		}
		headers[strings.TrimSpace(headerSplit[0])] = strings.TrimSpace(headerSplit[1])
	}

	var body string
	bodyStartIndex := bodyStartLine + 1
	if bodyStartIndex < len(bufSeparatedByNewLines) {
		bodyContent := bufSeparatedByNewLines[bodyStartIndex:]
		//Trim ist notwendig, da das initiale Buffer Array 1024 Bytes groß ist und daher viele Nullen am Ende stehen.
		body = strings.TrimRight(strings.Join(bodyContent, "\n"), "\x00\n\r\t ")
	}

	var httpRequest V1UnroutedHttpRequest
	httpRequest.method = method
	httpRequest.target = requestTarget
	httpRequest.headers = headers
	httpRequest.body = body

	// Hier sollte man lieber einen Pointer zu dem Struct zurückgeben als das Struct selbst, da es komplexer ist. Ungefähr bei mehr als 64 bytes
	//sollte ein Pointer verwendet werden.
	// Go schiebt den Pointer dann automatisch auf den Heap (nicht wie in C). Daher ist es Best Practise in Go kein New zu verwenden.
	return &httpRequest, nil
}
