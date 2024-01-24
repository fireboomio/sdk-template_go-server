package types

type (
	OperationDefinitions          map[string]InternalRequestFunction
	OperationArgsWithInput[I any] struct {
		Input I `json:"input"`
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
	i.Context.ExtraHeaders = headers
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
