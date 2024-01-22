package plugins

import (
	"custom-go/pkg/types"
	"errors"
	"github.com/labstack/echo/v4"
	"net/http"
	"path"
)

type AuthenticationResponse struct {
	Message string      `json:"message"`
	Status  string      `json:"status"`
	User    *types.User `json:"user"`
}

type AuthenticationConfiguration struct {
	PostAuthentication         func(hook *types.AuthenticationHookRequest) error
	MutatingPostAuthentication func(hook *types.AuthenticationHookRequest) (*AuthenticationResponse, error)
	RevalidateAuthentication   func(hook *types.AuthenticationHookRequest) (*AuthenticationResponse, error)
	PostLogout                 func(hook *types.AuthenticationHookRequest) error
}

func RegisterAuthHooks(e *echo.Echo, authHooks AuthenticationConfiguration) {
	authPrefix := "/authentication"
	auth := e.Group(authPrefix)
	// preHandler hook - check user context
	auth.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			brc := c.(*types.AuthenticationHookRequest)
			if brc.User == nil {
				return errors.New("user context doesn't exist")
			}
			return next(brc)
		}
	})

	// authentication routes
	if authHooks.PostAuthentication != nil {
		apiPath := "/postAuthentication"
		e.Logger.Debugf(`Registered authHook [%s]`, path.Join(authPrefix, apiPath))
		auth.POST(apiPath, func(c echo.Context) error {
			brc := c.(*types.AuthenticationHookRequest)
			err := authHooks.PostAuthentication(brc)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			return c.JSON(http.StatusOK, map[string]interface{}{
				"hook": "postAuthentication",
			})
		})
	}

	if authHooks.MutatingPostAuthentication != nil {
		apiPath := "/mutatingPostAuthentication"
		e.Logger.Debugf(`Registered authHook [%s]`, path.Join(authPrefix, apiPath))
		auth.POST(apiPath, func(c echo.Context) error {
			brc := c.(*types.AuthenticationHookRequest)
			out, err := authHooks.MutatingPostAuthentication(brc)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			return c.JSON(http.StatusOK, map[string]interface{}{
				"hook":                    "mutatingPostAuthentication",
				"response":                out,
				"setClientRequestHeaders": headersToObject(brc.Request().Header),
			})
		})
	}

	if authHooks.RevalidateAuthentication != nil {
		apiPath := "/revalidateAuthentication"
		e.Logger.Debugf(`Registered authHook [%s]`, path.Join(authPrefix, apiPath))
		auth.POST(apiPath, func(c echo.Context) error {
			brc := c.(*types.AuthenticationHookRequest)
			out, err := authHooks.RevalidateAuthentication(brc)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			return c.JSON(http.StatusOK, map[string]interface{}{
				"hook":                    "revalidateAuthentication",
				"response":                out,
				"setClientRequestHeaders": headersToObject(brc.Request().Header),
			})
		})
	}

	if authHooks.PostLogout != nil {
		apiPath := "/postLogout"
		e.Logger.Debugf(`Registered authHook [%s]`, path.Join(authPrefix, apiPath))
		auth.POST(apiPath, func(c echo.Context) error {
			brc := c.(*types.AuthenticationHookRequest)
			err := authHooks.PostLogout(brc)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
			}

			return c.JSON(http.StatusOK, map[string]interface{}{
				"hook":                    "postLogout",
				"setClientRequestHeaders": headersToObject(brc.Request().Header),
			})
		})
	}
}
