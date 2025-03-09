package backend

import (
	"http-server/http-parser"
)

func HandleHttpRequest(request *httpparser.HttpRequest) (*httpparser.HttpResponse, error) {
	res := &httpparser.HttpResponse{
		Status:  httpparser.Ok,
		Headers: make(map[string]string),
		Body:    "Hello i am a Raw Socket Http Server in Go :)",
	}

	return res, nil
}
