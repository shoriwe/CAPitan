package capture

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"github.com/h2non/filetype"
	"html/template"
	"io"
	"net/http"
	"regexp"
)

const (
	HTTPRequest  = "http-request"
	HTTPResponse = "http-response"
	PlainText    = "text/plain"
	Unknown      = "unknown"
)

var (
	HTTPRequestPattern    = regexp.MustCompile("(?m)^[A-Z]+\\s\\S+\\sHTTP/\\d+(\\.\\d)*")
	HTTPResponsePattern   = regexp.MustCompile("(?m)^HTTP/\\d+(\\.\\d)*\\s\\d+\\s[A-Z]+")
	PlainTextPattern      = regexp.MustCompile("([[:graph:]]|[[:space:]])+")
	ExtractRawContentType = regexp.MustCompile("[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+")
)

type Data struct {
	Type    string
	Content []byte
}

func NewData(t string, content []byte) Data {
	switch t {
	case HTTPRequest, HTTPResponse, PlainText:
		var output bytes.Buffer
		_ = template.Must(template.New("new").Parse("{{.Content}}")).Execute(&output, struct {
			Content string
		}{
			Content: string(content),
		})
		return Data{
			Type:    t,
			Content: output.Bytes(),
		}
	default:
		return Data{
			Type:    t,
			Content: content,
		}
	}
}

func detectBody(body []byte, encoding, contentType string) ([]Data, error) {
	var rawBody []byte
	switch encoding {
	case "":
		rawBody = body
	case "gzip":
		var unzipError error
		rawBody, unzipError = gzipUnzip(body)
		if unzipError != nil {
			return nil, unzipError
		}
	}
	if len(contentType) == 0 {
		return DetectChunkFormat(rawBody)
	}
	return []Data{
		NewData(ExtractRawContentType.FindString(contentType), rawBody),
	}, nil
}

func gzipUnzip(content []byte) ([]byte, error) {
	zReader, newError := gzip.NewReader(bytes.NewReader(content))
	if newError != nil {
		return nil, newError
	}
	return io.ReadAll(zReader)
}

func httpRequest(requestContent []byte) ([]Data, error) {
	// fmt.Println(string(requestContent))
	request, parseError := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(requestContent)))
	if parseError != nil {
		return nil, parseError
	}
	body, readError := io.ReadAll(request.Body)
	if readError != nil {
		return nil, readError
	}
	var result []Data
	if len(body) > 0 {
		detectedBody, detectionError := detectBody(body, request.Header.Get("Content-Encoding"), request.Header.Get("Content-Type"))
		if detectionError != nil {
			return nil, detectionError
		}
		index := bytes.Index(requestContent, body)
		if index == -1 {
			result = append(result,
				NewData(HTTPRequest, requestContent),
			)
			return append(result, detectedBody...), nil
		}
		result = append(result,
			NewData(HTTPRequest, requestContent[:index]),
		)
		return append(result, detectedBody...), nil
	} else {
		result = append(result,
			NewData(HTTPRequest, requestContent),
		)
	}
	return result, nil
}

func httpResponse(responseContent []byte) ([]Data, error) {
	request, _ := http.NewRequest(http.MethodGet, "/", nil)
	request.Header.Add("Accept-Encoding", "gzip")
	request.Close = true
	response, parseError := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(responseContent)), request)
	if parseError != nil {
		return nil, parseError
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil {
		return nil, readError
	}
	var result []Data
	if len(body) > 0 {
		detectedBody, detectionError := detectBody(body, response.Header.Get("Content-Encoding"), response.Header.Get("Content-Type"))
		if detectionError != nil {
			return nil, detectionError
		}
		index := bytes.Index(responseContent, body)
		if index == -1 {
			result = append(result,
				NewData(HTTPResponse, responseContent),
			)
			return append(result, detectedBody...), nil
		}
		result = append(result,
			NewData(HTTPResponse, responseContent[:index]),
		)
		return append(result, detectedBody...), nil
	} else {
		result = append(result,
			NewData(HTTPResponse, responseContent),
		)
	}
	return result, nil
}

func DetectChunkFormat(content []byte) ([]Data, error) {
	if HTTPRequestPattern.Match(content) {
		return httpRequest(content)
	} else if HTTPResponsePattern.Match(content) {
		return httpResponse(content)
	}

	contentType, matchError := filetype.Match(content)
	if matchError != nil {
		return nil, matchError
	}
	if contentType == filetype.Unknown {
		if len(PlainTextPattern.Find(content)) == len(content) {
			return []Data{
				NewData(PlainText, content),
			}, nil
		}
		return []Data{
			NewData(Unknown, content),
		}, nil
	}

	if contentType.MIME.Value == "application/gzip" {
		unzipContent, unzipError := gzipUnzip(content)
		if unzipError != nil {
			return nil, unzipError
		}
		return DetectChunkFormat(unzipContent)
	}

	return []Data{
		NewData(contentType.MIME.Value, content),
	}, nil
}
