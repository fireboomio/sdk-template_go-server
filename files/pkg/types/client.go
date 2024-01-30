package types

import (
	"context"
	"github.com/google/uuid"
)

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

func NewEmptyInternalClient() *InternalClient {
	headerTraceId := string(InternalHeader_X_FB_Trace_Id)
	headerRequestId := string(InternalHeader_X_Request_Id)
	return &InternalClient{
		BaseRequestBodyWg: &BaseRequestBodyWg{
			ClientRequest: &WunderGraphRequest{Headers: RequestHeaders{}},
		},
		ExtraHeaders: RequestHeaders{
			headerTraceId:   uuid.New().String(),
			headerRequestId: uuid.New().String(),
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
