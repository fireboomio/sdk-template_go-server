package types

import (
	"os"
)

func GetConfigurationVal(val *ConfigurationVariable) (result string) {
	if val == nil {
		return
	}

	switch val.Kind {
	case ConfigurationVariableKind_STATIC_CONFIGURATION_VARIABLE:
		result = val.StaticVariableContent
	case ConfigurationVariableKind_ENV_CONFIGURATION_VARIABLE:
		result = os.Getenv(val.EnvironmentVariableName)
		if result == "" && val.EnvironmentVariableDefaultValue != "" {
			result = val.EnvironmentVariableDefaultValue
		}
	case ConfigurationVariableKind_PLACEHOLDER_CONFIGURATION_VARIABLE:
	default:
		result = val.StaticVariableContent
	}
	return
}
