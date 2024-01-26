package types

import "context"

type (
	OperationDefinitions          map[string]InternalRequestFunction
	OperationArgsWithInput[I any] struct {
		Input   I `json:"input"`
		Context context.Context
	}
)

type (
	InternalRequestFunction func(*InternalClientRequestContext, OperationArgsWithInput[any]) (any, error)
	InternalClientFactory   func(map[string]string, WunderGraphRequest) *InternalClient
	InternalClient          struct {
		Context   *InternalClientRequestContext
		Queries   OperationDefinitions
		Mutations OperationDefinitions
	}
	InternalClientRequestContext struct {
		ExtraHeaders map[string]string
		*BaseRequestBodyWg
	}
)

func (i *InternalClient) WithHeaders(headers map[string]string) *InternalClient {
	if len(i.Context.ExtraHeaders) == 0 {
		i.Context.ExtraHeaders = headers
	} else {
		for k, v := range headers {
			i.Context.ExtraHeaders[k] = v
		}
	}
	return i
}

func InternalClientFactoryCall(headers map[string]string, wg *BaseRequestBodyWg) *InternalClient {
	client := &InternalClient{
		Context: &InternalClientRequestContext{
			ExtraHeaders:      headers,
			BaseRequestBodyWg: wg,
		},
	}
	return client
}
