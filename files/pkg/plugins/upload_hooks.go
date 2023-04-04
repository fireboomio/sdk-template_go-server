package plugins

import (
	"custom-go/pkg/base"
	"github.com/labstack/echo/v4"
	"net/http"
	"path"
)

type UploadHooks = base.Record[string, UploadHooksProfile]

type UploadBody[M any] struct {
	File base.WunderGraphFile `json:"file"`
	Meta M                    `json:"meta"`
}

type uploadFunction func(request *base.PreUploadHookRequest, body *UploadBody[any]) (*base.UploadHookResponse, error)
type UploadHooksProfile struct {
	PreUpload  uploadFunction
	PostUpload uploadFunction
}

func RegisterUploadsHooks(e *echo.Echo, uploadHooksMap map[string]UploadHooks) {
	for providerName, provider := range uploadHooksMap {
		for profileName, profile := range provider {
			if profile.PreUpload != nil {
				preUpload(e, providerName, profileName, profile.PreUpload)
			}
			if profile.PostUpload != nil {
				postUpload(e, providerName, profileName, profile.PostUpload)
			}
		}
	}
}

func preUpload(e *echo.Echo, providerName, profileName string, handler uploadFunction) {
	apiPath := path.Join("/upload", providerName, profileName, "preUpload")
	e.Logger.Debugf(`Registered uploadHook [%s]`, apiPath)
	e.POST(apiPath, func(c echo.Context) error {
		pur := c.(*base.PreUploadHookRequest)
		var param UploadBody[any]
		err := c.Bind(&param)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}

		result, err := handler(pur, &param)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}

		return c.JSON(http.StatusOK, result)
	})
}

func postUpload(e *echo.Echo, providerName, profileName string, handler uploadFunction) {
	apiPath := path.Join("/upload", providerName, profileName, "postUpload")
	e.Logger.Debugf(`Registered uploadHook [%s]`, apiPath)
	e.POST(apiPath, func(c echo.Context) error {
		pur := c.(*base.PostUploadHookRequest)
		var param UploadBody[any]
		err := c.Bind(&param)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}

		result, err := handler(pur, &param)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}

		return c.JSON(http.StatusOK, result)
	})
}
