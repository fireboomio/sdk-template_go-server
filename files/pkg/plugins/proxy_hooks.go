package plugins

import (
	"custom-go/pkg/base"
	"custom-go/pkg/consts"
	"custom-go/pkg/wgpb"
	"encoding/json"
	"github.com/labstack/echo/v4"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

type httpProxyHookFunction func(*base.HttpTransportHookRequest, *HttpTransportBody) (*base.ClientResponse, error)

func RegisterProxyHook(httpMethod string, hookFunc httpProxyHookFunction, authRequired bool,
	authorizationConfig *wgpb.OperationAuthorizationConfig) {

	callerName := GetCallerName(consts.PROXY)
	apiPrefixPath := "/" + consts.PROXY
	apiPath := path.Join(apiPrefixPath, callerName)

	base.AddEchoRouterFunc(func(e *echo.Echo) {
		e.Logger.Debugf(`Registered hookFunction [%s]`, apiPath)
		e.Add(httpMethod, apiPath, buildProxyHook(hookFunc))
	})

	base.AddHealthFunc(func(e *echo.Echo, s string, report *base.HealthReport) {
		// 生成 operation 声明文件  proxy/xxx.json
		operation := &wgpb.Operation{
			Name:                 callerName,
			AuthenticationConfig: &wgpb.OperationAuthenticationConfig{AuthRequired: authRequired},
			AuthorizationConfig:  authorizationConfig,
			Path:                 apiPath,
		}

		operationBytes, err := json.Marshal(operation)
		if err != nil {
			e.Logger.Errorf("json marshal failed, err: %v", err.Error())
			return
		}
		err = os.WriteFile(filepath.Join(consts.PROXY, callerName)+consts.JSON_EXT, operationBytes, 0644)
		if err != nil {
			e.Logger.Errorf("write file failed, err: %v", err.Error())
			return
		}

		report.Proxies = append(report.Proxies, callerName)
	})
}

func buildProxyHook(proxyHook httpProxyHookFunction) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		brc := c.(*base.HttpTransportHookRequest)

		var reqBody HttpTransportBody
		err = c.Bind(&reqBody)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		newResp, err := proxyHook(brc, &reqBody)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		resp := map[string]interface{}{
			"op":       reqBody.Name,
			"hook":     "proxyHook",
			"response": map[string]interface{}{},
		}
		if newResp != nil {
			resp["response"].(map[string]interface{})["response"] = newResp
		}
		return c.JSON(http.StatusOK, resp)
	}
}
