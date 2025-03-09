package httpreceiver

import (
	"fmt"
	"http-server/backend"
	"http-server/http-parser"
	"http-server/tcp-sender"
)

func HandleHttpRequest(session *tcpsender.TcpSession, requestAsBytes []byte) error {
	httpRequest, err := httpparser.ConvertToHttpRequest(requestAsBytes)
	if err != nil {
		return err
	}

	if !isRequestComplete(httpRequest) {
		return nil
	}

	fmt.Println("Received Http request:")
	httpparser.PrintRequest(httpRequest)
	httpRes, err := backend.HandleHttpRequest(httpRequest)

	if err != nil {
		return err
	}

	fmt.Println("Send Http response:")
	httpparser.PrintResponse(httpRes)
	httpResAsBytes := httpparser.ConvertHttpResponseToBytes(httpRes)

	session.SendTCPSegment(httpResAsBytes)

	return nil
}

func isRequestComplete(request *httpparser.HttpRequest) bool {
	if request.Method == httpparser.Get {
		return true
	}

	//For Post and other methods it must be checked if the body is complete by using e.g. the Content Length Header
	return false
}
