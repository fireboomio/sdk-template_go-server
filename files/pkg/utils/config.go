package utils

import (
	"custom-go/pkg/wgpb"
	"github.com/tidwall/gjson"
	"os"
	"regexp"
)

func GetConfigurationVal(val *wgpb.ConfigurationVariable) (result string) {
	if val == nil {
		return
	}

	switch val.Kind {
	case wgpb.ConfigurationVariableKind_STATIC_CONFIGURATION_VARIABLE:
		result = val.StaticVariableContent
	case wgpb.ConfigurationVariableKind_ENV_CONFIGURATION_VARIABLE:
		result = os.Getenv(val.EnvironmentVariableName)
		if result == "" && val.EnvironmentVariableDefaultValue != "" {
			result = val.EnvironmentVariableDefaultValue
		}
	case wgpb.ConfigurationVariableKind_PLACEHOLDER_CONFIGURATION_VARIABLE:
	default:
		result = val.StaticVariableContent
	}
	return
}

var placeholderRegexp = regexp.MustCompile(`\${([^}]+)}`)

func ReplacePlaceholder(jsonStr, str string) string {
	return placeholderRegexp.ReplaceAllStringFunc(str, func(s string) string {
		return gjson.Get(jsonStr, s[2:len(s)-1]).Str
	})

}
