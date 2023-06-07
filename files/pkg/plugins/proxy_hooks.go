package plugins

import (
	"custom-go/pkg/base"
	"github.com/labstack/echo/v4"
	"net/http"
	"path"
)

type httpProxyHookFunction func(*base.HttpTransportHookRequest, *HttpTransportBody) (*base.ClientResponse, error)

var httpProxyHookMap map[string]httpProxyHookFunction

func init() {
	httpProxyHookMap = make(map[string]httpProxyHookFunction, 0)
}

func AddProxyHook(name string, hookFunc httpProxyHookFunction) {
	httpProxyHookMap[name] = hookFunc
}

func RegisterProxyHooks(e *echo.Echo) {
	apiPrefixPath := "/proxy"
	for name, function := range httpProxyHookMap {
		apiPath := path.Join(apiPrefixPath, name)
		e.Logger.Debugf(`Registered proxyHook [%s]`, apiPath)
		e.POST(apiPath, func(c echo.Context) error {
			brc := c.(*base.HttpTransportHookRequest)
			var reqBody HttpTransportBody
			err := c.Bind(&reqBody)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, err.Error())
			}

			newResp, err := function(brc, &reqBody)
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
