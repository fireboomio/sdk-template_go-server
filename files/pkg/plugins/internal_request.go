package plugins

import (
	"bytes"
	"custom-go/pkg/base"
	"custom-go/pkg/utils"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"io"
	"net/http"
)

var DefaultInternalClient *base.InternalClient

func BuildDefaultInternalClient(queries base.OperationDefinitions, mutations base.OperationDefinitions) {
	DefaultInternalClient = &base.InternalClient{
		Context: &base.InternalClientRequestContext{
			ClientRequest: &base.ClientRequest{
				Headers: map[string]string{},
			},
		},
		Queries:   queries,
		Mutations: mutations,
	}
	return
}

func BuildInternalRequest(logger echo.Logger, baseNodeUrl string, operationName []string) base.OperationDefinitions {
	result := make(base.OperationDefinitions, len(operationName))
	for _, name := range operationName {
		url := fmt.Sprintf("%s/internal/operations/%s", baseNodeUrl, name)
		logger.Debugf(`Built internalRequest (%s)`, url)
		result[base.OperationPath(name)] = func(ctx *base.InternalClientRequestContext, options base.OperationArgsWithInput[any]) (any, error) {
			return internalRequest(url, ctx, options)
		}
	}
	return result
}

func internalRequest(url string, clientCtx *base.InternalClientRequestContext, options base.OperationArgsWithInput[any]) (any, error) {
	jsonData, err := json.Marshal(map[string]interface{}{
		"input": options.Input,
		"__wg": map[string]interface{}{
			"clientRequest": &base.ClientRequest{
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

	var res base.OperationBodyResponse[any]
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	if len(res.Errors) > 0 {
		return nil, errors.New(res.Errors[0].Message)
	}

	return res.Data, nil
}

func ExecuteInternalRequestMutations[I, OD any](internalClient *base.InternalClient, path base.OperationMutationPath, input I) (result OD, err error) {
	return executeInternalRequest[I, OD](internalClient.Context, internalClient.Mutations, path, input)
}

func ExecuteInternalRequestQueries[I, OD any](internalClient *base.InternalClient, path base.OperationQueryPath, input I) (result OD, err error) {
	return executeInternalRequest[I, OD](internalClient.Context, internalClient.Queries, path, input)
}

func executeInternalRequest[I, OD any](context *base.InternalClientRequestContext, operationDefinitions base.OperationDefinitions, path base.OperationPath, input I) (result OD, err error) {
	execFunction := operationDefinitions[path]
	if nil == execFunction {
		return result, fmt.Errorf("not find internalRequest with (%s)", path)
	}

	args := base.OperationArgsWithInput[I]{Input: input}
	options := utils.ConvertType[base.OperationArgsWithInput[I], base.OperationArgsWithInput[any]](&args)
	execRes, err := execFunction(context, *options)
	if err != nil || execRes == nil {
		return result, err
	}

	return *utils.ConvertType[any, OD](&execRes), nil
}
