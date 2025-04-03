package utils

import (
	"bytes"
	"io"
	"net/http"
)

// CloneRequestBody reads and clones the request body, returning a new ReadCloser
// that can be used to re-read the request body
func CloneRequestBody(req *http.Request) (io.ReadCloser, error) {
	if req.Body == nil {
		return nil, nil
	}

	// Read the body
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	// Close the original body as we've consumed it
	req.Body.Close()

	// Create two readers: one for immediate use and one to replace the request body
	return CreateReadCloser(bodyBytes), nil
}

// CreateReadCloser creates a ReadCloser from a byte slice
func CreateReadCloser(body []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(body))
}
