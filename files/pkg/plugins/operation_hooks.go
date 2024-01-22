package plugins

import (
	"custom-go/pkg/types"
	"custom-go/pkg/utils"
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
	"path"
	"strconv"
)

const (
	maximumRecursionLimit = 16
)

const (
	mockResolveKey         = "mockResolve"
	preResolveKey          = "preResolve"
	postResolveKey         = "postResolve"
	mutatingPreResolveKey  = "mutatingPreResolve"
	mutatingPostResolveKey = "mutatingPostResolve"
	customResolveKey       = "customResolve"
)

func ConvertBodyFunc[I, O any](oldFunc func(*types.HookRequest, *types.OperationBody[I, O]) (*types.OperationBody[I, O], error)) types.OperationHookFunction {
	return func(hook *types.HookRequest, body *types.OperationBody[any, any]) (res *types.OperationBody[any, any], err error) {
		// 将传入的 OperationBody 转换为需要的类型
		var input = utils.ConvertType[types.OperationBody[any, any], types.OperationBody[I, O]](body)
		// 调用旧函数获取结果
		oldRes, err := oldFunc(hook, input)
		if err != nil {
			return res, err
		}

		res = utils.ConvertType[types.OperationBody[I, O], types.OperationBody[any, any]](oldRes)
		return res, nil
	}
}

func RegisterOperationsHooks(e *echo.Echo, operations []string, operationHooksMap types.OperationHooks) {
	for _, operationPath := range operations {
		registerOperationHooks(e, operationPath, operationHooksMap)
	}
}

func registerOperationHooks(e *echo.Echo, operationPath string, operationHooksMap types.OperationHooks) {
	if operationHook, ok := operationHooksMap[operationPath]; ok {
		pathPrefix := path.Join("/operation", operationPath)
		if operationHook.MockResolve != nil {
			apiPath := path.Join(pathPrefix, mockResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, buildOperationHook(operationPath, mockResolveKey, operationHook.MockResolve, mockResolve))
		}

		if operationHook.PreResolve != nil {
			apiPath := path.Join(pathPrefix, preResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, buildOperationHook(operationPath, preResolveKey, operationHook.PreResolve, preResolve))
		}

		if operationHook.PostResolve != nil {
			apiPath := path.Join(pathPrefix, postResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, buildOperationHook(operationPath, postResolveKey, operationHook.PostResolve, postResolve))
		}

		if operationHook.MutatingPreResolve != nil {
			apiPath := path.Join(pathPrefix, mutatingPreResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, buildOperationHook(operationPath, mutatingPreResolveKey, operationHook.MutatingPreResolve, mutatingPreResolve))
		}

		if operationHook.MutatingPostResolve != nil {
			apiPath := path.Join(pathPrefix, mutatingPostResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, buildOperationHook(operationPath, mutatingPostResolveKey, operationHook.MutatingPostResolve, mutatingPostResolve))
		}

		if operationHook.CustomResolve != nil {
			apiPath := path.Join(pathPrefix, customResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, buildOperationHook(operationPath, customResolveKey, operationHook.CustomResolve, customResolve))
		}
	}
}

func requestContext(c echo.Context) (result *types.HookRequest, err error) {
	body := make(map[string]interface{})
	if err := c.Request().ParseForm(); err != nil {
		return result, err
	}

	result = c.(*types.HookRequest)
	for key, value := range c.Request().Form {
		body[key] = value[0]
	}
	if cycleCounter, ok := body["cycleCounter"].(int); ok {
		if cycleCounter > maximumRecursionLimit {
			return result, fmt.Errorf("maximum recursion limit reached (%d)", maximumRecursionLimit)
		}
		result.InternalClient = result.InternalClient.WithHeaders(map[string]string{"Wg-Cycle-Counter": strconv.Itoa(cycleCounter)})
	}
	return result, nil
}

func mockResolve(in, out *types.OperationBody[any, any]) {
	in.Response = out.Response
	in.SetClientRequestHeaders = out.SetClientRequestHeaders
}
func preResolve(in, out *types.OperationBody[any, any]) {
	in.SetClientRequestHeaders = out.SetClientRequestHeaders
}

func postResolve(in, out *types.OperationBody[any, any]) {
	in.SetClientRequestHeaders = out.SetClientRequestHeaders
}

func mutatingPreResolve(in, out *types.OperationBody[any, any]) {
	in.Input = out.Input
	in.SetClientRequestHeaders = out.SetClientRequestHeaders
}

func mutatingPostResolve(in, out *types.OperationBody[any, any]) {
	in.Response = out.Response
	in.SetClientRequestHeaders = out.SetClientRequestHeaders
	if in.Response != nil && in.Response.DataAny != nil {
		in.Response.Data = in.Response.DataAny
		in.Response.DataAny = nil
	}
}

func customResolve(in, out *types.OperationBody[any, any]) {
	in.Response = out.Response
	in.SetClientRequestHeaders = out.SetClientRequestHeaders
}

func buildOperationHook(operationName, hookName string, hookFunction types.OperationHookFunction, action func(in, out *types.OperationBody[any, any])) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
		c.Response().WriteHeader(http.StatusOK)

		var in types.OperationBody[any, any]
		err = c.Bind(&in)
		if err != nil {
			return
		}

		hookRequest, err := requestContext(c)
		if err != nil {
			return
		}

		in.Op = operationName
		in.Hook = hookName
		in.SetClientRequestHeaders = headersToObject(c.Request().Header)
		out, err := hookFunction(hookRequest, &in)
		if err != nil {
			return err
		}

		if out != nil {
			action(&in, out)
		}
		return c.JSON(http.StatusOK, &in)
	}
}

func headersToObject(headers http.Header) map[string]string {
	obj := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			obj[key] = values[0]
		}
	}
	return obj
}
