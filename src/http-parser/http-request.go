package httpparser

type HttpMethod string

const (
	Get    HttpMethod = "GET"
	Post   HttpMethod = "POST"
	Put    HttpMethod = "PUT"
	Delete HttpMethod = "DELETE"
)

type HttpRequest struct {
	Method  HttpMethod
	Target  string
	Headers map[string]string
	Body    string
}
