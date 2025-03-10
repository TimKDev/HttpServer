package backend

import (
	"http-server/http-parser"
	"log"
	"os"
)

func HandleHttpRequest(request *httpparser.HttpRequest) (*httpparser.HttpResponse, error) {
	var body string
	if request.Target == "/index.js" {
		body = getFileContent("./exampleHtml/index.js")
	} else {
		body = getFileContent("./exampleHtml/index.html")
	}
	res := &httpparser.HttpResponse{
		Status:  httpparser.Ok,
		Headers: make(map[string]string),
		Body:    body,
	}

	return res, nil
}

func getFileContent(path string) string {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("File not found")
	}
	return string(file)
}
