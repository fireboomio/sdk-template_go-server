package types

import "context"

type (
	OperationArgsWithInput[I any] struct {
		Input   I `json:"input"`
		Context context.Context
	}
	InternalClient struct {
		ExtraHeaders map[string]string
		*BaseRequestBodyWg
	}
)

func (i *InternalClient) WithHeaders(headers map[string]string) *InternalClient {
	if len(i.ExtraHeaders) == 0 {
		i.ExtraHeaders = headers
	} else {
		for k, v := range headers {
			i.ExtraHeaders[k] = v
		}
	}
	return i
}

func InternalClientFactoryCall(headers map[string]string, wg *BaseRequestBodyWg) *InternalClient {
	client := &InternalClient{
		BaseRequestBodyWg: wg,
		ExtraHeaders:      headers,
	}
	return client
}
