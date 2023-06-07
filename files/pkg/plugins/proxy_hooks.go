package plugins

import (
	"custom-go/pkg/base"
	"github.com/labstack/echo/v4"
	"net/http"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

type (
	httpProxyHookFunction func(*base.HttpTransportHookRequest, *HttpTransportBody) (*base.ClientResponse, error)
	httpProxyHook         struct {
		requiredRoles []string
		hookFunction  httpProxyHookFunction
	}
)

var httpProxyHookMap map[string]*httpProxyHook

func init() {
	httpProxyHookMap = make(map[string]*httpProxyHook, 0)
}

func AddProxyHook(hookFunc httpProxyHookFunction, requiredRoles ...string) {
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		return
	}

	file = filepath.ToSlash(file)
	_, after, found := strings.Cut(file, "/proxys/")
	if !found {
		return
	}

	after = strings.TrimSuffix(after, ".go")
	httpProxyHookMap[after] = &httpProxyHook{
		requiredRoles: requiredRoles,
		hookFunction:  hookFunc,
	}
}

func RegisterProxyHooks(e *echo.Echo) {
	apiPrefixPath := "/proxy"
	for name, proxyHook := range httpProxyHookMap {
		apiPath := path.Join(apiPrefixPath, name)
		e.Logger.Debugf(`Registered proxyHook [%s]`, apiPath)
		e.POST(apiPath, func(c echo.Context) error {
			brc := c.(*base.HttpTransportHookRequest)
			var reqBody HttpTransportBody
			err := c.Bind(&reqBody)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, err.Error())
			}

			newResp, err := proxyHook.hookFunction(brc, &reqBody)
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
		})
	}
}
