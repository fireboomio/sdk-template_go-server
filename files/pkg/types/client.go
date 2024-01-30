package types

import "context"

type (
	OperationArgsWithInput[I any] struct {
		Input   I `json:"input"`
		Context context.Context
	}
	InternalClient struct {
		ExtraHeaders RequestHeaders
		*BaseRequestBodyWg
	}
)

func NewEmptyInternalClient(user *User) *InternalClient {
	return &InternalClient{
		BaseRequestBodyWg: &BaseRequestBodyWg{
			ClientRequest: &WunderGraphRequest{Headers: RequestHeaders{}},
			User:          user,
		},
	}
}

func (i *InternalClient) WithHeaders(headers RequestHeaders) *InternalClient {
	if len(i.ExtraHeaders) == 0 {
		i.ExtraHeaders = headers
	} else {
		for k, v := range headers {
			i.ExtraHeaders[k] = v
		}
	}
	return i
}

func InternalClientFactoryCall(headers RequestHeaders, wg *BaseRequestBodyWg) *InternalClient {
	client := &InternalClient{
		BaseRequestBodyWg: wg,
		ExtraHeaders:      headers,
	}
	return client
}