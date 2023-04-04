package types

import (
	"custom-go/pkg/base"
	"custom-go/pkg/plugins"
)

type HooksConfiguration struct {
	Global         plugins.GlobalConfiguration
	Authentication plugins.AuthenticationConfiguration
	Queries        base.OperationHooks
	Mutations      base.OperationHooks
	Subscriptions  base.OperationHooks
	Uploads        map[string]plugins.UploadHooks
}
