package types

import (
	"custom-go/pkg/utils"
	"custom-go/pkg/wgpb"
	"github.com/joho/godotenv"
	"golang.org/x/exp/slices"
	"path/filepath"
)

var WdgGraphConfig WunderGraphConfiguration
var configJsonPath = filepath.Join("generated", "fireboom.config.json")

func init() {
	_ = utils.ReadStructAndCacheFile(configJsonPath, &WdgGraphConfig)
	_ = godotenv.Overload(WdgGraphConfig.Api.NodeOptions.OsEnvFilePath)
}

type WunderGraphConfiguration struct {
	Api                              *UserDefinedApiSdk `json:"api,omitempty"`
	ApiId                            string             `json:"apiId,omitempty"`
	EnvironmentIds                   []string           `json:"environmentIds,omitempty"`
	DangerouslyEnableGraphQLEndpoint bool               `json:"dangerouslyEnableGraphQLEndpoint,omitempty"`
	DeploymentName                   string             `json:"deploymentName,omitempty"`
	ApiName                          string             `json:"apiName,omitempty"`
}

type UserDefinedApiSdk struct {
	EngineConfiguration   *wgpb.EngineConfiguration     `json:"engineConfiguration,omitempty"`
	EnableGraphqlEndpoint bool                          `json:"enableGraphqlEndpoint,omitempty"`
	Operations            []*OperationStruct            `json:"operations"`
	CorsConfiguration     *wgpb.CorsConfiguration       `json:"corsConfiguration,omitempty"`
	AuthenticationConfig  *wgpb.ApiAuthenticationConfig `json:"authenticationConfig,omitempty"`
	S3UploadConfiguration []*wgpb.S3UploadConfiguration `json:"s3UploadConfiguration,omitempty"`
	AllowedHostNames      []*wgpb.ConfigurationVariable `json:"allowedHostNames,omitempty"`
	Webhooks              []*wgpb.WebhookConfiguration  `json:"webhooks"`
	ServerOptions         *wgpb.ServerOptions           `json:"serverOptions,omitempty"`
	NodeOptions           *wgpb.NodeOptions             `json:"nodeOptions,omitempty"`
}

type OperationStruct struct {
	Name          string             `json:"name"`
	Path          string             `json:"path"`
	OperationType wgpb.OperationType `json:"operationType"`
}

func GetS3ConfigByProvider(provider string) *wgpb.S3UploadConfiguration {
	s3Arr := WdgGraphConfig.Api.S3UploadConfiguration
	if index := slices.IndexFunc(s3Arr, func(s3Config *wgpb.S3UploadConfiguration) bool {
		return provider == s3Config.Name
	}); index != -1 {
		return s3Arr[index]
	}
	return nil
}
