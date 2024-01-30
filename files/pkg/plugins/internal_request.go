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

func internalRequest[I, O any](client *types.InternalClient, path string, options types.OperationArgsWithInput[I]) (o O, err error) {
	if client == nil {
		err = errors.New("internal client is nil")
		return
	}
	var (
		bodyBuffer  *bytes.Buffer
		contentType string
	)
	url := fetchInternalRequestUrl(path)
	baseBodyWg := &types.BaseRequestBodyWg{
		ClientRequest: &types.WunderGraphRequest{
			RequestURI: url,
			Method:     http.MethodPost,
			Headers:    client.ClientRequest.Headers,
		},
		User: client.User,
	}
	formData, ok := options.Context.Value(fileFormDataKey).(fileFormData)
	if ok {
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
			return
		}
	} else {
		var jsonData []byte
		if jsonData, err = json.Marshal(types.OperationHookPayload{Input: options.Input, Wg: baseBodyWg}); err != nil {
			return
		}
		bodyBuffer, contentType = bytes.NewBuffer(jsonData), echo.MIMEApplicationJSON
	}

	req, err := http.NewRequest(http.MethodPost, url, bodyBuffer)
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", contentType)
	for k, v := range client.ExtraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		err = errors.New(string(bodyBytes))
		return
	}

	var res types.OperationBodyResponse[O]
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}

	if len(res.Errors) > 0 {
		err = errors.New(res.Errors[0].Message)
		return
	}

	o = res.Data
	return
}

func executeInternalRequest[I, OD any](client *types.InternalClient, path string, input I) (result OD, err error) {
	options := types.OperationArgsWithInput[I]{Input: input}
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
	options.Context = context.Background()
	if len(formData) > 0 {
		options.Context = context.WithValue(options.Context, fileFormDataKey, formData)
	}
	return internalRequest[I, OD](client, path, options)
}

const fileFormDataKey = "fileFormData"

var operations = make(map[types.OperationType][]string)

type (
	fileFormData   map[string][]*types.UploadFile
	Meta[I, O any] struct {
		Path string
		Type types.OperationType
	}
)

func FetchOperations(logger echo.Logger, operationType types.OperationType, printUrlRequired bool) []string {
	paths := operations[operationType]
	if printUrlRequired {
		for _, path := range paths {
			logger.Debugf(`Built internalRequest (%s)`, fetchInternalRequestUrl(path))
		}
	}
	return paths
}

func fetchInternalRequestUrl(path string) string {
	return types.PrivateNodeUrl + strings.ReplaceAll(string(types.InternalEndpoint_internalRequest), "{path}", path)
}

func NewOperationMeta[I, O any](path string, operationType types.OperationType) *Meta[I, O] {
	operations[operationType] = append(operations[operationType], path)
	return &Meta[I, O]{Path: path, Type: operationType}
}

func (m *Meta[I, O]) Execute(input I, client *types.InternalClient) (O, error) {
	return executeInternalRequest[I, O](client, m.Path, input)
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
	_, err := utils.HttpPost(url, body, client.ExtraHeaders)
	return err
}
