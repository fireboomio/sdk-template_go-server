package plugins

import (
	"bytes"
	"context"
	"custom-go/pkg/types"
	"custom-go/pkg/utils"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/tidwall/sjson"
	"golang.org/x/exp/maps"
	"io"
	"mime/multipart"
	"net/http"
	"reflect"
	"strings"
)

var DefaultInternalClient *types.InternalClient

func BuildDefaultInternalClient(queries types.OperationDefinitions, mutations types.OperationDefinitions) {
	DefaultInternalClient = &types.InternalClient{
		Context: &types.InternalClientRequestContext{
			BaseRequestBodyWg: &types.BaseRequestBodyWg{
				ClientRequest: &types.WunderGraphRequest{Headers: map[string]string{}},
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
		url := types.PrivateNodeUrl + strings.ReplaceAll(string(types.InternalEndpoint_internalRequest), "{path}", name)
		logger.Debugf(`Built internalRequest (%s)`, url)
		result[name] = func(ctx *types.InternalClientRequestContext, options types.OperationArgsWithInput[any]) (any, error) {
			return internalRequest(url, ctx, options)
		}
	}
	return result
}

func internalRequest(url string, clientCtx *types.InternalClientRequestContext, options types.OperationArgsWithInput[any]) (any, error) {
	var (
		bodyBuffer  *bytes.Buffer
		contentType string
	)
	baseBodyWg := &types.BaseRequestBodyWg{
		ClientRequest: &types.WunderGraphRequest{
			RequestURI: url,
			Method:     http.MethodPost,
			Headers:    clientCtx.ClientRequest.Headers,
		},
		User: clientCtx.User,
	}
	formData, ok := options.Context.Value(fileFormDataKey).(fileFormData)
	if ok {
		var err error
		optional := func(writer *multipart.Writer) {
			inputBytes, _ := json.Marshal(options.Input)
			for _, key := range maps.Keys(formData) {
				inputBytes, _ = sjson.DeleteBytes(inputBytes, key)
			}
			_ = writer.WriteField("input", string(inputBytes))
			baseBodyWgBytes, _ := json.Marshal(baseBodyWg)
			_ = writer.WriteField("__wg", string(baseBodyWgBytes))
		}
		if bodyBuffer, contentType, err = buildBodyWithFileFormData(formData, optional); err != nil {
			return nil, err
		}
	} else {
		jsonData, err := json.Marshal(types.OperationHookPayload{Input: options.Input, Wg: baseBodyWg})
		if err != nil {
			return nil, err
		}
		bodyBuffer, contentType = bytes.NewBuffer(jsonData), echo.MIMEApplicationJSON
	}

	req, err := http.NewRequest(http.MethodPost, url, bodyBuffer)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)
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

func executeInternalRequest[I, OD any](clientCtx *types.InternalClientRequestContext, operationDefinitions types.OperationDefinitions, path string, input I) (result OD, err error) {
	execFunction := operationDefinitions[path]
	if nil == execFunction {
		return result, fmt.Errorf("not find internalRequest with (%s)", path)
	}

	args := types.OperationArgsWithInput[I]{Input: input}
	inputValue := reflect.ValueOf(input)
	if inputValue.Kind() == reflect.Ptr {
		inputValue = inputValue.Elem()
	}
	inputType := inputValue.Type()
	formData := make(fileFormData)
	for i := 0; i < inputValue.NumField(); i++ {
		inputFieldValue := inputValue.Field(i)
		if !inputFieldValue.IsValid() || !inputFieldValue.CanInterface() || inputFieldValue.IsZero() {
			continue
		}

		var files []*types.UploadFile
		switch v := inputFieldValue.Interface().(type) {
		case *types.UploadFile:
			files = []*types.UploadFile{v}
		case []*types.UploadFile:
			files = v
		}
		if len(files) > 0 {
			inputFieldTag := inputType.Field(i).Tag.Get("json")
			formData[inputFieldTag] = files
		}
	}
	options := utils.ConvertType[types.OperationArgsWithInput[I], types.OperationArgsWithInput[any]](&args)
	options.Context = context.Background()
	if len(formData) > 0 {
		options.Context = context.WithValue(options.Context, fileFormDataKey, formData)
	}
	execRes, err := execFunction(clientCtx, *options)
	if err != nil || execRes == nil {
		return result, err
	}

	return *utils.ConvertType[any, OD](&execRes), nil
}

const fileFormDataKey = "fileFormData"

type fileFormData map[string][]*types.UploadFile

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

func (m *Meta[I, O]) Execute(input I, client ...*types.InternalClient) (O, error) {
	executeClient := DefaultInternalClient
	if len(client) > 0 && client[0] != nil {
		executeClient = client[0]
	}

	operationDefinitions := executeClient.Queries
	if m.Type == 1 {
		operationDefinitions = executeClient.Mutations
	}

	return executeInternalRequest[I, O](executeClient.Context, operationDefinitions, m.Path, input)
}

func ExecuteWithTransaction(client *types.InternalClient, execute func() error) error {
	transactionId := uuid.New().String()
	client.WithHeaders(types.RequestHeaders{
		string(types.TransactionHeader_X_Transaction_Manually): "true",
		string(types.TransactionHeader_X_Transaction_Id):       transactionId,
	})
	var body []byte
	if err := execute(); err != nil {
		body = []byte(fmt.Sprintf(`{"error": "%s"}`, err.Error()))
	}
	url := types.PrivateNodeUrl + string(types.InternalEndpoint_internalTransaction)
	_, err := utils.HttpPost(url, body, client.Context.ExtraHeaders)
	return err
}
