package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
)

func CopyAndBindRequestBody(request *http.Request, result any) (err error) {
	dumpBytes, err := httputil.DumpRequest(request, true)
	if err != nil {
		return err
	}

	requestCopy, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(dumpBytes)))
	if err != nil {
		return err
	}

	bodyBytes, err := io.ReadAll(requestCopy.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(bodyBytes, &result)
}
