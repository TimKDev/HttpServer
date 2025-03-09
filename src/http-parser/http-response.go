package httpparser

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

type HttpResponse struct {
	Status  HttpStatus
	Headers map[string]string
	Body    string
}
