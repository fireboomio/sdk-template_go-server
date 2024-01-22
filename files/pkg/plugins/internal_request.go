package plugins

import (
	"bytes"
	"custom-go/pkg/types"
	"custom-go/pkg/utils"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"io"
	"net/http"
)

var DefaultInternalClient *types.InternalClient

func BuildDefaultInternalClient(queries types.OperationDefinitions, mutations types.OperationDefinitions) {
	DefaultInternalClient = &types.InternalClient{
		Context: &types.InternalClientRequestContext{
			ClientRequest: &types.WunderGraphRequest{
				Headers: map[string]string{},
			},
		},
		Queries:   queries,
		Mutations: mutations,
	}
	return
}

func BuildInternalRequest(logger echo.Logger, operationType types.OperationType) types.OperationDefinitions {
	internalOperations := operations[operationType]
	result := make(types.OperationDefinitions, len(internalOperations))
	for _, name := range internalOperations {
		url := fmt.Sprintf("%s/internal/operations/%s", types.PrivateNodeUrl, name)
		logger.Debugf(`Built internalRequest (%s)`, url)
		result[name] = func(ctx *types.InternalClientRequestContext, options types.OperationArgsWithInput[any]) (any, error) {
			return internalRequest(url, ctx, options)
		}
	}
	return result
}

func internalRequest(url string, clientCtx *types.InternalClientRequestContext, options types.OperationArgsWithInput[any]) (any, error) {
	jsonData, err := json.Marshal(map[string]interface{}{
		"input": options.Input,
		"__wg": map[string]interface{}{
			"clientRequest": &types.WunderGraphRequest{
				RequestURI: url,
				Method:     "POST",
				Headers:    clientCtx.ClientRequest.Headers,
			},
			"user": clientCtx.User,
		},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range clientCtx.ExtraHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(bodyBytes))
	}

	var res types.OperationBodyResponse[any]
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	if len(res.Errors) > 0 {
		return nil, errors.New(res.Errors[0].Message)
	}

	return res.Data, nil
}

func executeInternalRequest[I, OD any](context *types.InternalClientRequestContext, operationDefinitions types.OperationDefinitions, path string, input I) (result OD, err error) {
	execFunction := operationDefinitions[path]
	if nil == execFunction {
		return result, fmt.Errorf("not find internalRequest with (%s)", path)
	}

	args := types.OperationArgsWithInput[I]{Input: input}
	options := utils.ConvertType[types.OperationArgsWithInput[I], types.OperationArgsWithInput[any]](&args)
	execRes, err := execFunction(context, *options)
	if err != nil || execRes == nil {
		return result, err
	}

	return *utils.ConvertType[any, OD](&execRes), nil
}

var operations = make(map[types.OperationType][]string)

type Meta[I, O any] struct {
	Path string
	Type types.OperationType
}

func FetchSubscriptions() []string {
	return operations[types.OperationType_SUBSCRIPTION]
}

func NewOperationMeta[I, O any](path string, operationType types.OperationType) *Meta[I, O] {
	operations[operationType] = append(operations[operationType], path)
	return &Meta[I, O]{Path: path, Type: operationType}
}

func (m *Meta[I, O]) Execute(input I, context ...*types.InternalClientRequestContext) (O, error) {
	requestCtx := DefaultInternalClient.Context
	if len(context) > 0 {
		requestCtx = context[0]
	}

	operationDefinitions := DefaultInternalClient.Queries
	if m.Type == 1 {
		operationDefinitions = DefaultInternalClient.Mutations
	}

	return executeInternalRequest[I, O](requestCtx, operationDefinitions, m.Path, input)
}
