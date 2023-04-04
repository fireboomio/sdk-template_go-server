package base

type Record[K comparable, T any] map[K]T

type BaseRequestBody struct {
	Wg BaseRequestBodyWg `json:"__wg"`
}

type BaseRequestBodyWg struct {
	ClientRequest *ClientRequest           `json:"clientRequest"`
	User          *WunderGraphUser[string] `json:"user"`
}

type ClientRequest struct {
	Method     string            `json:"method"`
	RequestURI string            `json:"requestURI"`
	Headers    map[string]string `json:"headers"`
}
