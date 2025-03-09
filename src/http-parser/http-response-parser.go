package httpparser

func ConvertHttpResponseToBytes(response *HttpResponse) []byte {
	capacity := 128 + len(response.Status) + len(response.Body)
	for k, v := range response.Headers {
		capacity += len(k) + len(v) + 4 // 4 for ": " and "\r\n"
	}

	result := make([]byte, 0, capacity)
	result = append(result, []byte("HTTP/1.1 "+string(response.Status)+"\r\n")...)
	for key, value := range response.Headers {
		line := key + ": " + value + "\r\n"
		result = append(result, []byte(line)...)
	}
	// Empty line always need to be set even if the request has no header
	result = append(result, []byte("\r\n")...)
	if response.Body != "" {
		result = append(result, []byte(response.Body)...)
	}
	//Every http request should end with an empty line. Otherwise you get something like a % in the response.
	result = append(result, []byte("\r\n")...)

	return result
}
