package httpparser

import (
	"fmt"
	"log"
	"strings"
)

func ConvertToHttpRequest(buf []byte) (*HttpRequest, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("empty request buffer")
	}
	bufSeparatedByNewLines := strings.Split(string(buf), "\r\n")
	startLine := strings.Split(bufSeparatedByNewLines[0], " ")
	if len(startLine) < 3 {
		return nil, fmt.Errorf("invalid startline")
	}

	method := HttpMethod(startLine[0])
	requestTarget := startLine[1]
	httpVersion := startLine[2]

	if !strings.Contains(httpVersion, "HTTP/1") {
		return nil, fmt.Errorf("only protocol version HTTP/1.1 is supported")
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

	var httpRequest HttpRequest
	httpRequest.Method = method
	httpRequest.Target = requestTarget
	httpRequest.Headers = headers
	httpRequest.Body = body

	return &httpRequest, nil
}
