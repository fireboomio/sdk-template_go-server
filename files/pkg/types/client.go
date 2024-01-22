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
		WithHeaders func(map[string]string) *InternalClient
		Context     *InternalClientRequestContext
		Queries     OperationDefinitions
		Mutations   OperationDefinitions
	}
	InternalClientRequestContext struct {
		ExtraHeaders  map[string]string
		ClientRequest *WunderGraphRequest
		User          *User
	}
)

func InternalClientFactoryCall(headers map[string]string, clientRequest *WunderGraphRequest, user *User) *InternalClient {
	client := &InternalClient{
		Context: &InternalClientRequestContext{
			ExtraHeaders:  headers,
			ClientRequest: clientRequest,
			User:          user,
		},
	}
	client.WithHeaders = func(headers map[string]string) *InternalClient {
		client.Context.ExtraHeaders = headers
		return client
	}
	return client
}
