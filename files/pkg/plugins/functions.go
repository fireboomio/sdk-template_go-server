package plugins

import (
	"custom-go/pkg/types"
	"custom-go/pkg/utils"
	"encoding/json"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/invopop/jsonschema"
	"github.com/labstack/echo/v4"
	"github.com/tidwall/sjson"
	"os"
	"path/filepath"
	"strings"
)

const (
	schemaRefPrefix       = "#/$defs/"
	swaggerRefPrefix      = "#/definitions/"
	definitionRefProperty = "definitions"
	jsonExtension         = ".json"
)

func RegisterFunction[I, O any](hookFunc func(*types.HookRequest, *types.OperationBody[I, O]) (*types.OperationBody[I, O], error), operationType ...types.OperationType) {
	callerName := utils.GetCallerName(string(types.HookParent_function))
	apiPath := strings.ReplaceAll(string(types.Endpoint_function), "{path}", callerName)

	types.AddEchoRouterFunc(func(e *echo.Echo) {
		e.Logger.Debugf(`Registered hookFunction [%s]`, apiPath)
		e.POST(apiPath, buildOperationHook(callerName, types.MiddlewareHook(types.HookParent_function), ConvertBodyFunc[I, O](hookFunc), func(in, out *types.OperationBody[any, any]) {
			in.Response = out.Response
		}))
	})

	types.AddHealthFunc(func(e *echo.Echo, report *types.HealthReportLock) {
		operationJsonPath := filepath.Join(string(types.HookParent_function), callerName) + jsonExtension
		operation := &types.Operation{}

		// 读文件，保留原有配置，只需更新schema
		if !utils.NotExistFile(operationJsonPath) {
			_ = utils.ReadStructAndCacheFile(operationJsonPath, operation)
		} else {
			operation.Name = callerName
			operation.Path = apiPath
			operation.OperationType = types.OperationType_MUTATION
		}

		if operationType != nil && len(operationType) > 0 {
			operation.OperationType = operationType[0]
		}

		var (
			i I
			o O
		)
		// 解析入参和出参
		inputSchema := jsonschema.Reflect(i)
		outputSchema := jsonschema.Reflect(o)

		operation.VariablesSchema = BuildSchema(inputSchema)
		operation.ResponseSchema = BuildSchema(outputSchema)

		operationBytes, err := json.Marshal(operation)
		if err != nil {
			e.Logger.Errorf("json marshal failed, err: %v", err.Error())
			return
		}

		err = os.WriteFile(operationJsonPath, operationBytes, 0644)
		if err != nil {
			e.Logger.Errorf("write file failed, err: %v", err.Error())
			return
		}

		report.Lock()
		defer report.Unlock()
		report.Functions = append(report.Functions, callerName)
	})
}

func BuildSchema(schema *jsonschema.Schema) string {
	defs := make(openapi3.Schemas)
	for name, internalSchema := range schema.Definitions {
		defs[name] = parseJsonschemaToSwaggerSchema(internalSchema)
	}

	refStr := strings.TrimPrefix(schema.Ref, "#/$defs/")
	schemaRef := defs[refStr]
	delete(defs, refStr)

	bytes, _ := json.Marshal(schemaRef)

	res := string(bytes)

	if len(defs) == 0 {
		return res
	}
	res, _ = sjson.Set(res, definitionRefProperty, defs)
	return res
}

func FetchSimpleSchema(schema *jsonschema.Schema) (schemaRef *openapi3.SchemaRef) {
	defs := make(openapi3.Schemas)
	for name, internalSchema := range schema.Definitions {
		defs[name] = parseJsonschemaToSwaggerSchema(internalSchema)
	}

	refStr := strings.TrimPrefix(schema.Ref, "#/$defs/")
	schemaRef = defs[refStr]
	delete(defs, refStr)
	fillSchemaRef(schemaRef, defs)
	return
}

func fillSchemaRef(schemaRef *openapi3.SchemaRef, definitions openapi3.Schemas) {
	if schemaRef.Ref != "" {
		schemaRef.Value = definitions[strings.TrimPrefix(schemaRef.Ref, "#/$defs/")].Value
	}

	for _, v := range schemaRef.Value.AllOf {
		fillSchemaRef(v, definitions)
	}
	for _, v := range schemaRef.Value.AnyOf {
		fillSchemaRef(v, definitions)
	}
	for _, v := range schemaRef.Value.OneOf {
		fillSchemaRef(v, definitions)
	}
	for _, v := range schemaRef.Value.Properties {
		fillSchemaRef(v, definitions)
	}
}

func parseJsonschemaToSwaggerSchema(schema *jsonschema.Schema) (result *openapi3.SchemaRef) {
	if schema.Ref != "" {
		result = openapi3.NewSchemaRef(strings.ReplaceAll(schema.Ref, schemaRefPrefix, swaggerRefPrefix), nil)
		return
	}

	result = &openapi3.SchemaRef{Value: &openapi3.Schema{
		Type:     schema.Type,
		Format:   schema.Format,
		Default:  schema.Default,
		Title:    schema.Title,
		Required: schema.Required,
	}}

	if enum := schema.Enum; enum != nil {
		result.Value.Enum = enum
		return
	}

	if schema.Items != nil {
		result.Value.Items = parseJsonschemaToSwaggerSchema(schema.Items)
		return
	}

	for _, item := range schema.OneOf {
		result.Value.OneOf = append(result.Value.OneOf, parseJsonschemaToSwaggerSchema(item))
	}
	for _, item := range schema.AnyOf {
		result.Value.AnyOf = append(result.Value.AnyOf, parseJsonschemaToSwaggerSchema(item))
	}
	for _, item := range schema.AllOf {
		result.Value.AllOf = append(result.Value.AllOf, parseJsonschemaToSwaggerSchema(item))
	}

	if properties := schema.Properties; properties != nil {
		result.Value.Properties = make(openapi3.Schemas)
		for _, key := range properties.Keys() {
			itemSchema, _ := properties.Get(key)
			result.Value.Properties[key] = parseJsonschemaToSwaggerSchema(itemSchema.(*jsonschema.Schema))
		}
	}
	return
}
