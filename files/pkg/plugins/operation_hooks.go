package plugins

import (
	"custom-go/pkg/base"
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

func ConvertBodyFunc[I, O any](oldFunc func(*base.HookRequest, *base.OperationBody[I, O]) (*base.OperationBody[I, O], error)) base.OperationHookFunction {
	return func(hook *base.HookRequest, body *base.OperationBody[any, any]) (res *base.OperationBody[any, any], err error) {
		// 将传入的 OperationBody 转换为需要的类型
		var input = utils.ConvertType[base.OperationBody[any, any], base.OperationBody[I, O]](body)
		// 调用旧函数获取结果
		oldRes, err := oldFunc(hook, input)
		if err != nil {
			return res, err
		}

		res = utils.ConvertType[base.OperationBody[I, O], base.OperationBody[any, any]](oldRes)
		return res, nil
	}
}

func RegisterOperationsHooks(e *echo.Echo, operations []string, operationHooksMap base.OperationHooks) {
	for _, operationPath := range operations {
		registerOperationHooks(e, operationPath, operationHooksMap)
	}
}

func registerOperationHooks(e *echo.Echo, operationPath string, operationHooksMap base.OperationHooks) {
	if operationHook, ok := operationHooksMap[operationPath]; ok {
		pathPrefix := path.Join("/operation", operationPath)
		routeConfig := &base.HooksRouteConfig{OperationName: operationPath, Kind: "hook"}
		if operationHook.MockResolve != nil {
			apiPath := path.Join(pathPrefix, mockResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, mockResolve(operationPath, operationHook.MockResolve, routeConfig))
		}

		if operationHook.PreResolve != nil {
			apiPath := path.Join(pathPrefix, preResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, preResolve(operationPath, operationHook.PreResolve, routeConfig))
		}

		if operationHook.PostResolve != nil {
			apiPath := path.Join(pathPrefix, postResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, postResolve(operationPath, operationHook.PostResolve, routeConfig))
		}

		if operationHook.MutatingPreResolve != nil {
			apiPath := path.Join(pathPrefix, mutatingPreResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, mutatingPreResolve(operationPath, operationHook.MutatingPreResolve, routeConfig))
		}

		if operationHook.MutatingPostResolve != nil {
			apiPath := path.Join(pathPrefix, mutatingPostResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, mutatingPostResolve(operationPath, operationHook.MutatingPostResolve, routeConfig))
		}

		if operationHook.CustomResolve != nil {
			apiPath := path.Join(pathPrefix, customResolveKey)
			e.Logger.Debugf(`Registered operationHook [%s]`, apiPath)
			e.POST(apiPath, customResolve(operationPath, operationHook.CustomResolve, routeConfig))
		}
	}
}

func requestContext(c echo.Context) (result *base.HookRequest, err error) {
	body := make(map[string]interface{})
	if err := c.Request().ParseForm(); err != nil {
		return result, err
	}

	result = c.(*base.HookRequest)
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

func mockResolve(operationName string, hookFunction base.OperationHookFunction, routeConfig *base.HooksRouteConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
		c.Response().WriteHeader(http.StatusOK)

		var param base.OperationBody[any, any]
		err := c.Bind(&param)
		if err != nil {
			return buildEchoJsonError(c, operationName, mockResolveKey, err)
		}

		hookRequest, err := requestContext(c)
		if err != nil {
			return buildEchoJsonError(c, operationName, mockResolveKey, err)
		}

		param.Op = operationName
		param.Hook = mockResolveKey
		param.Config = routeConfig
		param.SetClientRequestHeaders = headersToObject(c.Request().Header)
		mutated, err := hookFunction(hookRequest, &param)
		if err != nil {
			return buildEchoJsonError(c, operationName, mockResolveKey, err)
		}

		if nil != mutated {
			param.Response = mutated.Response
		}
		return c.JSON(http.StatusOK, &param)
	}
}

func preResolve(operationName string, hookFunction base.OperationHookFunction, routeConfig *base.HooksRouteConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
		c.Response().WriteHeader(http.StatusOK)

		var param base.OperationBody[any, any]
		err := c.Bind(&param)
		if err != nil {
			return buildEchoJsonError(c, operationName, preResolveKey, err)
		}

		hookRequest, err := requestContext(c)
		if err != nil {
			return buildEchoJsonError(c, operationName, preResolveKey, err)
		}

		param.Op = operationName
		param.Hook = preResolveKey
		param.Config = routeConfig
		param.SetClientRequestHeaders = headersToObject(c.Request().Header)
		_, err = hookFunction(hookRequest, &param)
		if err != nil {
			return buildEchoJsonError(c, operationName, preResolveKey, err)
		}

		return c.JSON(http.StatusOK, &param)
	}
}

func postResolve(operationName string, hookFunction base.OperationHookFunction, routeConfig *base.HooksRouteConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
		c.Response().WriteHeader(http.StatusOK)

		var param base.OperationBody[any, any]
		err := c.Bind(&param)
		if err != nil {
			return buildEchoJsonError(c, operationName, postResolveKey, err)
		}

		hookRequest, err := requestContext(c)
		if err != nil {
			return buildEchoJsonError(c, operationName, postResolveKey, err)
		}

		param.Op = operationName
		param.Hook = postResolveKey
		param.Config = routeConfig
		param.SetClientRequestHeaders = headersToObject(c.Request().Header)
		_, err = hookFunction(hookRequest, &param)
		if err != nil {
			return buildEchoJsonError(c, operationName, postResolveKey, err)
		}

		return c.JSON(http.StatusOK, &param)
	}
}

func mutatingPreResolve(operationName string, hookFunction base.OperationHookFunction, routeConfig *base.HooksRouteConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
		c.Response().WriteHeader(http.StatusOK)

		var param base.OperationBody[any, any]
		err := c.Bind(&param)
		if err != nil {
			return buildEchoJsonError(c, operationName, mutatingPreResolveKey, err)
		}

		hookRequest, err := requestContext(c)
		if err != nil {
			return buildEchoJsonError(c, operationName, mutatingPreResolveKey, err)
		}

		param.Op = operationName
		param.Hook = mutatingPreResolveKey
		param.Config = routeConfig
		param.SetClientRequestHeaders = headersToObject(c.Request().Header)
		mutatedInput, err := hookFunction(hookRequest, &param)
		if err != nil {
			return buildEchoJsonError(c, operationName, mutatingPreResolveKey, err)
		}

		if mutatedInput != nil {
			param.Input = mutatedInput.Input
		}
		return c.JSON(http.StatusOK, &param)
	}
}

func mutatingPostResolve(operationName string, hookFunction base.OperationHookFunction, routeConfig *base.HooksRouteConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
		c.Response().WriteHeader(http.StatusOK)

		var param base.OperationBody[any, any]
		err := c.Bind(&param)
		if err != nil {
			return buildEchoJsonError(c, operationName, mutatingPostResolveKey, err)
		}

		hookRequest, err := requestContext(c)
		if err != nil {
			return buildEchoJsonError(c, operationName, mutatingPostResolveKey, err)
		}

		param.Op = operationName
		param.Hook = mutatingPostResolveKey
		param.Config = routeConfig
		param.SetClientRequestHeaders = headersToObject(c.Request().Header)
		mutatedResponse, err := hookFunction(hookRequest, &param)
		if err != nil {
			return buildEchoJsonError(c, operationName, mutatingPostResolveKey, err)
		}

		if nil != mutatedResponse {
			param.Response = mutatedResponse.Response
		}
		return c.JSON(http.StatusOK, &param)
	}
}

func customResolve(operationName string, hookFunction base.OperationHookFunction, routeConfig *base.HooksRouteConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
		c.Response().WriteHeader(http.StatusOK)

		var param base.OperationBody[any, any]
		err := c.Bind(&param)
		if err != nil {
			return buildEchoJsonError(c, operationName, customResolveKey, err)
		}

		hookRequest, err := requestContext(c)
		if err != nil {
			return buildEchoJsonError(c, operationName, customResolveKey, err)
		}

		param.Op = operationName
		param.Hook = customResolveKey
		param.Config = routeConfig
		param.SetClientRequestHeaders = headersToObject(c.Request().Header)
		out, err := hookFunction(hookRequest, &param)
		if err != nil {
			return buildEchoJsonError(c, operationName, customResolveKey, err)
		}

		if out != nil {
			param.Response = out.Response
		}
		return c.JSON(http.StatusOK, &param)
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

func buildEchoJsonError(c echo.Context, operationName, hookName string, err error) error {
	c.Logger().Error(err)
	return c.JSON(http.StatusInternalServerError, map[string]interface{}{
		"op":    operationName,
		"hook":  hookName,
		"error": err.Error(),
	})
}
