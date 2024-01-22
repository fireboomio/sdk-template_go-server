package types

import (
	"time"
)

type HealthReport struct {
	Customizes []string  `json:"customizes"`
	Functions  []string  `json:"functions"`
	Proxys     []string  `json:"proxys"`
	Time       time.Time `json:"time"`
}

type UploadHookPayload_error struct {
	Message string `json:"message"`
	Name    string `json:"name"`
}

type PostResolveGetTransformation struct {
	DateTimeFormat string   `json:"dateTimeFormat"`
	From           []string `json:"from"`
	To             []string `json:"to"`
}

type StatusCodeTypeMapping struct {
	InjectStatusCodeIntoBody bool   `json:"injectStatusCodeIntoBody"`
	StatusCode               int64  `json:"statusCode"`
	TypeName                 string `json:"typeName"`
}

type RESTSubscriptionConfiguration struct {
	Enabled                 bool  `json:"enabled"`
	PollingIntervalMillis   int64 `json:"pollingIntervalMillis"`
	SkipPublishSameResponse bool  `json:"skipPublishSameResponse"`
}

type DataSourceCustom_REST_Rewriter struct {
	Rewriters []*DataSourceRESTRewriter `json:"rewriters"`
}

type ApiAuthenticationHooks struct {
	MutatingPostAuthentication bool `json:"mutatingPostAuthentication"`
	PostAuthentication         bool `json:"postAuthentication"`
	PostLogout                 bool `json:"postLogout"`
	RevalidateAuthentication   bool `json:"revalidateAuthentication"`
}

type OpenIDConnectQueryParameter struct {
	Name  *ConfigurationVariable `json:"name"`
	Value *ConfigurationVariable `json:"value"`
}

type GraphQLFederationConfiguration struct {
	Enabled    bool   `json:"enabled"`
	ServiceSdl string `json:"serviceSdl"`
}

type JwksBasedAuthentication struct {
	Providers []*JwksAuthProvider `json:"providers"`
}

type XML struct {
	Attribute bool   `json:"attribute,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	Wrapped   bool   `json:"wrapped,omitempty"`
}

type RequestError struct {
	Locations []*Location `json:"locations,omitempty"`
	Message   string      `json:"message"`
	Path      *ErrorPath  `json:"path"`
}

type CorsConfiguration struct {
	AllowCredentials bool                     `json:"allowCredentials"`
	AllowedHeaders   []string                 `json:"allowedHeaders"`
	AllowedMethods   []string                 `json:"allowedMethods"`
	AllowedOrigins   []*ConfigurationVariable `json:"allowedOrigins"`
	ExposedHeaders   []string                 `json:"exposedHeaders"`
	MaxAge           int64                    `json:"maxAge"`
}

type OperationTransaction struct {
	IsolationLevel int64 `json:"isolationLevel"`
	MaxWaitSeconds int64 `json:"maxWaitSeconds"`
	TimeoutSeconds int64 `json:"timeoutSeconds"`
}

type User_customClaims map[string]any

type URLQueryConfiguration struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DataSourceConfiguration_customRestRequestRewriterMap map[string]*DataSourceCustom_REST_Rewriter

type NodeLogging struct {
	Level *ConfigurationVariable `json:"level"`
}

type DataSourceCustom_REST struct {
	DefaultTypeName        string                         `json:"defaultTypeName"`
	Fetch                  *FetchConfiguration            `json:"fetch"`
	RequestRewriters       []*DataSourceRESTRewriter      `json:"requestRewriters,omitempty"`
	ResponseRewriters      []*DataSourceRESTRewriter      `json:"responseRewriters,omitempty"`
	StatusCodeTypeMappings []*StatusCodeTypeMapping       `json:"statusCodeTypeMappings"`
	Subscription           *RESTSubscriptionConfiguration `json:"subscription"`
}

type FieldConfiguration struct {
	ArgumentsConfiguration     []*ArgumentConfiguration `json:"argumentsConfiguration"`
	DisableDefaultFieldMapping bool                     `json:"disableDefaultFieldMapping"`
	FieldName                  string                   `json:"fieldName"`
	Path                       []string                 `json:"path"`
	RequiresFields             []string                 `json:"requiresFields"`
	TypeName                   string                   `json:"typeName"`
	UnescapeResponseJson       bool                     `json:"unescapeResponseJson"`
}

type CustomClaim struct {
	JsonPathComponents []string  `json:"jsonPathComponents"`
	Name               string    `json:"name"`
	Required           bool      `json:"required"`
	Type               ValueType `json:"type"`
}

type OperationsConfig_graphql_operation_files map[string]*GraphqlOperationFile

type WunderGraphResponse struct {
	Body       any            `json:"body,omitempty"`
	Headers    RequestHeaders `json:"headers"`
	Method     string         `json:"method"`
	OriginBody []byte         `json:"originBody,omitempty"`
	RequestURI string         `json:"requestURI"`
	Status     string         `json:"status"`
	StatusCode int64          `json:"statusCode"`
}

type UploadHookPayload struct {
	Wg    *BaseRequestBodyWg      `json:"__wg"`
	Error UploadHookPayload_error `json:"error"`
	File  *HookFile               `json:"file"`
	Meta  any                     `json:"meta"`
}

type FetchConfiguration struct {
	BaseUrl                *ConfigurationVariable    `json:"baseUrl"`
	Body                   *ConfigurationVariable    `json:"body"`
	Header                 FetchConfiguration_header `json:"header"`
	MTLS                   *MTLSConfiguration        `json:"mTLS"`
	Method                 HTTPMethod                `json:"method"`
	Path                   *ConfigurationVariable    `json:"path"`
	Query                  []*URLQueryConfiguration  `json:"query"`
	RequestContentType     string                    `json:"requestContentType"`
	ResponseContentType    string                    `json:"responseContentType"`
	UpstreamAuthentication *UpstreamAuthentication   `json:"upstreamAuthentication"`
	Url                    *ConfigurationVariable    `json:"url"`
	UrlEncodeBody          bool                      `json:"urlEncodeBody"`
}

type WebhookVerifier struct {
	Kind                  WebhookVerifierKind    `json:"kind"`
	Secret                *ConfigurationVariable `json:"secret"`
	SignatureHeader       string                 `json:"signatureHeader"`
	SignatureHeaderPrefix string                 `json:"signatureHeaderPrefix"`
}

type ErrorPath struct {
}

type OperationAuthenticationConfig struct {
	AuthRequired bool `json:"authRequired"`
}

type OpenIDConnectAuthProviderConfig struct {
	ClientId        *ConfigurationVariable         `json:"clientId"`
	ClientSecret    *ConfigurationVariable         `json:"clientSecret"`
	Issuer          *ConfigurationVariable         `json:"issuer"`
	QueryParameters []*OpenIDConnectQueryParameter `json:"queryParameters"`
}

type S3UploadProfileHooksConfiguration struct {
	PostUpload bool `json:"postUpload"`
	PreUpload  bool `json:"preUpload"`
}

type CookieBasedAuthentication struct {
	AuthorizedRedirectUriRegexes []*ConfigurationVariable `json:"authorizedRedirectUriRegexes"`
	AuthorizedRedirectUris       []*ConfigurationVariable `json:"authorizedRedirectUris"`
	BlockKey                     *ConfigurationVariable   `json:"blockKey"`
	CsrfSecret                   *ConfigurationVariable   `json:"csrfSecret"`
	HashKey                      *ConfigurationVariable   `json:"hashKey"`
	Providers                    []*AuthProvider          `json:"providers"`
}

type OperationMultipartForm struct {
	FieldName string `json:"fieldName"`
	IsArray   bool   `json:"isArray"`
}

type VariableWhereInput struct {
	Filter *VariableWhereInputFilter `json:"filter"`
	Not    *VariableWhereInput       `json:"not"`
}

type OperationRoleConfig struct {
	DenyMatchAll    []string `json:"denyMatchAll"`
	DenyMatchAny    []string `json:"denyMatchAny"`
	RequireMatchAll []string `json:"requireMatchAll"`
	RequireMatchAny []string `json:"requireMatchAny"`
}

type OperationsConfig struct {
	Definitions              Schemas                                   `json:"definitions"`
	Function_operation_files OperationsConfig_function_operation_files `json:"function_operation_files"`
	Graphql_operation_files  OperationsConfig_graphql_operation_files  `json:"graphql_operation_files"`
	Invalids                 []string                                  `json:"invalids,omitempty"`
	Proxy_operation_files    OperationsConfig_proxy_operation_files    `json:"proxy_operation_files"`
}

type SchemaRefs []*SchemaRef

type BaseRequestBody struct {
	Wg *BaseRequestBodyWg `json:"__wg"`
}

type OnWsConnectionInitHookPayload struct {
	DataSourceId string              `json:"dataSourceId"`
	Request      *WunderGraphRequest `json:"request"`
}

type OperationHookPayload_response struct {
	Data   any             `json:"data"`
	Errors []*RequestError `json:"errors"`
}

type DataSourceCustom_GraphQL struct {
	CustomScalarTypeFields []*SingleTypeField                   `json:"customScalarTypeFields"`
	Federation             *GraphQLFederationConfiguration      `json:"federation"`
	Fetch                  *FetchConfiguration                  `json:"fetch"`
	HooksConfiguration     *GraphQLDataSourceHooksConfiguration `json:"hooksConfiguration"`
	Subscription           *GraphQLSubscriptionConfiguration    `json:"subscription"`
	UpstreamSchema         string                               `json:"upstreamSchema"`
}

type WebhookConfiguration struct {
	FilePath string           `json:"filePath"`
	Name     string           `json:"name"`
	Verifier *WebhookVerifier `json:"verifier"`
}

type MutatingPostAuthenticationResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	User    *User  `json:"user"`
}

type DataSourceCustom_Database struct {
	CloseTimeoutSeconds int64                  `json:"closeTimeoutSeconds"`
	DatabaseURL         *ConfigurationVariable `json:"databaseURL"`
	GraphqlSchema       string                 `json:"graphqlSchema"`
	JsonInputVariables  []string               `json:"jsonInputVariables"`
	JsonTypeFields      []*SingleTypeField     `json:"jsonTypeFields"`
	PrismaSchema        string                 `json:"prismaSchema"`
}

type GraphQLSubscriptionConfiguration struct {
	Enabled bool                   `json:"enabled"`
	Url     *ConfigurationVariable `json:"url"`
	UseSSE  bool                   `json:"useSSE"`
}

type OnWsConnectionInitHookResponse struct {
	Payload any `json:"payload"`
}

type ConfigurationVariable struct {
	EnvironmentVariableDefaultValue string                    `json:"environmentVariableDefaultValue,omitempty"`
	EnvironmentVariableName         string                    `json:"environmentVariableName,omitempty"`
	Kind                            ConfigurationVariableKind `json:"kind"`
	PlaceholderVariableName         string                    `json:"placeholderVariableName,omitempty"`
	StaticVariableContent           string                    `json:"staticVariableContent,omitempty"`
}

type OperationLiveQueryConfig struct {
	Enabled                bool  `json:"enabled"`
	PollingIntervalSeconds int64 `json:"pollingIntervalSeconds"`
}

type ExtensionOperationFile struct {
	Authorization_config *OperationAuthorizationConfig `json:"authorization_config"`
	File_path            string                        `json:"file_path"`
	Internal_variables   *SchemaRef                    `json:"internal_variables,omitempty"`
	Module_path          string                        `json:"module_path"`
	Operation_name       string                        `json:"operation_name"`
	Operation_type       OperationType                 `json:"operation_type"`
	Response             *SchemaRef                    `json:"response"`
	Variables            *SchemaRef                    `json:"variables"`
	Variables_refs       []string                      `json:"variables_refs"`
}

type Discriminator struct {
	Mapping      Discriminator_mapping `json:"mapping,omitempty"`
	PropertyName string                `json:"propertyName"`
}

type S3UploadConfiguration struct {
	AccessKeyID     *ConfigurationVariable               `json:"accessKeyID"`
	BucketLocation  *ConfigurationVariable               `json:"bucketLocation"`
	BucketName      *ConfigurationVariable               `json:"bucketName"`
	Endpoint        *ConfigurationVariable               `json:"endpoint"`
	Name            string                               `json:"name"`
	SecretAccessKey *ConfigurationVariable               `json:"secretAccessKey"`
	UploadProfiles  S3UploadConfiguration_uploadProfiles `json:"uploadProfiles"`
	UseSSL          bool                                 `json:"useSSL"`
}

type DataSourceRESTRewriter_valueRewrites map[string]string

type VariableInjectionConfiguration struct {
	DateFormat              string             `json:"dateFormat"`
	DateOffset              *DateOffset        `json:"dateOffset"`
	EnvironmentVariableName string             `json:"environmentVariableName"`
	FromHeaderName          string             `json:"fromHeaderName"`
	VariableKind            InjectVariableKind `json:"variableKind"`
	VariablePathComponents  []string           `json:"variablePathComponents"`
}

type VariableWhereInputScalarFilter struct {
	Insensitive bool                               `json:"insensitive"`
	Type        VariableWhereInputScalarFilterType `json:"type"`
}

type OnRequestHookResponse struct {
	Cancel  bool                `json:"cancel"`
	Request *WunderGraphRequest `json:"request"`
	Skip    bool                `json:"skip"`
}

type EngineConfiguration struct {
	DatasourceConfigurations []*DataSourceConfiguration `json:"datasourceConfigurations"`
	DefaultFlushInterval     int64                      `json:"defaultFlushInterval"`
	FieldConfigurations      []*FieldConfiguration      `json:"fieldConfigurations"`
	GraphqlSchema            string                     `json:"graphqlSchema"`
	TypeConfigurations       []*TypeConfiguration       `json:"typeConfigurations"`
}

type VariableWhereInputFilter struct {
	Field    string                            `json:"field"`
	Relation *VariableWhereInputRelationFilter `json:"relation"`
	Scalar   *VariableWhereInputScalarFilter   `json:"scalar"`
}

type RequestHeaders map[string]string

type Operation_datasourceQuotes map[string]*DatasourceQuote

type ClaimConfig struct {
	ClaimType              ClaimType               `json:"claimType"`
	Custom                 *CustomClaim            `json:"custom"`
	RemoveIfNoneMatch      *ClaimRemoveIfNoneMatch `json:"removeIfNoneMatch"`
	VariablePathComponents []string                `json:"variablePathComponents"`
}

type ServerLogging struct {
	Level *ConfigurationVariable `json:"level"`
}

type DataSourceRESTSubObject struct {
	Fields []*DataSourceRESTSubfield `json:"fields"`
	Name   string                    `json:"name"`
}

type UploadHookResponse struct {
	Error   string `json:"error"`
	FileKey string `json:"fileKey"`
}

type SchemaRef struct {
	Ref   string  `json:"Ref"`
	Value *Schema `json:"Value"`
}

type ExternalDocs struct {
	Description string `json:"description,omitempty"`
	Url         string `json:"url,omitempty"`
}

type OnResponseHookPayload struct {
	OperationName string               `json:"operationName"`
	OperationType string               `json:"operationType"`
	Response      *WunderGraphResponse `json:"response"`
}

type OperationVariablesConfiguration struct {
	InjectVariables []*VariableInjectionConfiguration  `json:"injectVariables"`
	WhereInputs     []*VariableWhereInputConfiguration `json:"whereInputs"`
}

type Schema struct {
	AdditionalProperties *AdditionalProperties `json:"additionalProperties,omitempty"`
	AllOf                SchemaRefs            `json:"allOf,omitempty"`
	AllowEmptyValue      bool                  `json:"allowEmptyValue,omitempty"`
	AnyOf                SchemaRefs            `json:"anyOf,omitempty"`
	Default              any                   `json:"default,omitempty"`
	Deprecated           bool                  `json:"deprecated,omitempty"`
	Description          string                `json:"description,omitempty"`
	Discriminator        *Discriminator        `json:"discriminator,omitempty"`
	Enum                 []any                 `json:"enum,omitempty"`
	Example              any                   `json:"example,omitempty"`
	ExclusiveMaximum     bool                  `json:"exclusiveMaximum,omitempty"`
	ExclusiveMinimum     bool                  `json:"exclusiveMinimum,omitempty"`
	ExternalDocs         *ExternalDocs         `json:"externalDocs,omitempty"`
	Format               string                `json:"format,omitempty"`
	Items                *SchemaRef            `json:"items,omitempty"`
	MaxItems             int64                 `json:"maxItems,omitempty"`
	MaxLength            int64                 `json:"maxLength,omitempty"`
	MaxProperties        int64                 `json:"maxProperties,omitempty"`
	Maximum              float64               `json:"maximum,omitempty"`
	MinItems             int64                 `json:"minItems,omitempty"`
	MinLength            int64                 `json:"minLength,omitempty"`
	MinProperties        int64                 `json:"minProperties,omitempty"`
	Minimum              float64               `json:"minimum,omitempty"`
	MultipleOf           float64               `json:"multipleOf,omitempty"`
	Not                  *SchemaRef            `json:"not,omitempty"`
	Nullable             bool                  `json:"nullable,omitempty"`
	OneOf                SchemaRefs            `json:"oneOf,omitempty"`
	Pattern              string                `json:"pattern,omitempty"`
	Properties           Schemas               `json:"properties,omitempty"`
	ReadOnly             bool                  `json:"readOnly,omitempty"`
	Required             []string              `json:"required,omitempty"`
	Title                string                `json:"title,omitempty"`
	Type                 string                `json:"type,omitempty"`
	UniqueItems          bool                  `json:"uniqueItems,omitempty"`
	WriteOnly            bool                  `json:"writeOnly,omitempty"`
	Xml                  *XML                  `json:"xml,omitempty"`
}

type CustomizeHookPayload struct {
	Wg            *BaseRequestBodyWg             `json:"__wg"`
	OperationName string                         `json:"operationName"`
	Query         string                         `json:"query"`
	Variables     CustomizeHookPayload_variables `json:"variables"`
}

type AdditionalProperties struct {
	Has    bool       `json:"Has"`
	Schema *SchemaRef `json:"Schema"`
}

type BaseRequestBodyWg struct {
	ClientRequest *WunderGraphRequest `json:"clientRequest"`
	User          *User               `json:"user"`
}

type OperationHooksConfiguration struct {
	CustomResolve              bool                          `json:"customResolve"`
	HttpTransportAfterResponse bool                          `json:"httpTransportAfterResponse"`
	HttpTransportBeforeRequest bool                          `json:"httpTransportBeforeRequest"`
	HttpTransportOnRequest     bool                          `json:"httpTransportOnRequest"`
	HttpTransportOnResponse    bool                          `json:"httpTransportOnResponse"`
	MockResolve                *MockResolveHookConfiguration `json:"mockResolve"`
	MutatingPostResolve        bool                          `json:"mutatingPostResolve"`
	MutatingPreResolve         bool                          `json:"mutatingPreResolve"`
	OnConnectionInit           bool                          `json:"onConnectionInit"`
	PostResolve                bool                          `json:"postResolve"`
	PreResolve                 bool                          `json:"preResolve"`
}

type VariableWhereInputRelationFilter struct {
	Type  VariableWhereInputRelationFilterType `json:"type"`
	Where *VariableWhereInput                  `json:"where"`
}

type VariableWhereInputConfiguration struct {
	VariablePathComponents []string            `json:"variablePathComponents"`
	WhereInput             *VariableWhereInput `json:"whereInput"`
}

type DateOffset struct {
	Previous bool           `json:"previous"`
	Unit     DateOffsetUnit `json:"unit"`
	Value    int64          `json:"value"`
}

type DataSourceConfiguration struct {
	ChildNodes                    []*TypeField                                          `json:"childNodes"`
	CustomDatabase                *DataSourceCustom_Database                            `json:"customDatabase"`
	CustomGraphql                 *DataSourceCustom_GraphQL                             `json:"customGraphql"`
	CustomRest                    *DataSourceCustom_REST                                `json:"customRest"`
	CustomRestMap                 DataSourceConfiguration_customRestMap                 `json:"customRestMap,omitempty"`
	CustomRestRequestRewriterMap  DataSourceConfiguration_customRestRequestRewriterMap  `json:"customRestRequestRewriterMap,omitempty"`
	CustomRestResponseRewriterMap DataSourceConfiguration_customRestResponseRewriterMap `json:"customRestResponseRewriterMap,omitempty"`
	CustomStatic                  *DataSourceCustom_Static                              `json:"customStatic"`
	Directives                    []*DirectiveConfiguration                             `json:"directives"`
	Id                            string                                                `json:"id"`
	Kind                          DataSourceKind                                        `json:"kind"`
	OverrideFieldPathFromAlias    bool                                                  `json:"overrideFieldPathFromAlias"`
	RequestTimeoutSeconds         int64                                                 `json:"requestTimeoutSeconds"`
	RootNodes                     []*TypeField                                          `json:"rootNodes"`
}

type OperationsConfig_proxy_operation_files map[string]*ExtensionOperationFile

type UserDefinedApi struct {
	AllowedHostNames      []*ConfigurationVariable `json:"allowedHostNames"`
	AuthenticationConfig  *ApiAuthenticationConfig `json:"authenticationConfig"`
	CorsConfiguration     *CorsConfiguration       `json:"corsConfiguration"`
	EnableGraphqlEndpoint bool                     `json:"enableGraphqlEndpoint"`
	EngineConfiguration   *EngineConfiguration     `json:"engineConfiguration"`
	InvalidOperationNames []string                 `json:"invalidOperationNames"`
	NodeOptions           *NodeOptions             `json:"nodeOptions"`
	Operations            []*Operation             `json:"operations"`
	S3UploadConfiguration []*S3UploadConfiguration `json:"s3UploadConfiguration"`
	ServerOptions         *ServerOptions           `json:"serverOptions"`
	Webhooks              []*WebhookConfiguration  `json:"webhooks"`
}

type FetchConfiguration_header map[string]*HTTPHeader

type Discriminator_mapping map[string]string

type DataSourceRESTRewriter_applySubCommonFieldValues map[string]string

type GraphqlOperationFile struct {
	Authorization_config *OperationAuthorizationConfig `json:"authorization_config"`
	File_path            string                        `json:"file_path"`
	Internal             bool                          `json:"internal"`
	Internal_variables   *SchemaRef                    `json:"internal_variables,omitempty"`
	Operation_name       string                        `json:"operation_name"`
	Operation_type       OperationType                 `json:"operation_type"`
	Response             *SchemaRef                    `json:"response"`
	Variables            *SchemaRef                    `json:"variables"`
	Variables_refs       []string                      `json:"variables_refs"`
}

type OnRequestHookPayload struct {
	ArgsAllowList []string            `json:"argsAllowList"`
	OperationName string              `json:"operationName"`
	OperationType OperationTypeString `json:"operationType"`
	Request       *WunderGraphRequest `json:"request"`
}

type WunderGraphConfiguration struct {
	Api                              *UserDefinedApi `json:"api"`
	ApiId                            string          `json:"apiId"`
	ApiName                          string          `json:"apiName"`
	DangerouslyEnableGraphQLEndpoint bool            `json:"dangerouslyEnableGraphQLEndpoint"`
	DeploymentName                   string          `json:"deploymentName"`
	EnvironmentIds                   []string        `json:"environmentIds"`
}

type JwtUpstreamAuthenticationWithAccessTokenExchange struct {
	AccessTokenExchangeEndpoint *ConfigurationVariable `json:"accessTokenExchangeEndpoint"`
	Secret                      *ConfigurationVariable `json:"secret"`
	SigningMethod               SigningMethod          `json:"signingMethod"`
}

type AuthProvider struct {
	GithubConfig *GithubAuthProviderConfig        `json:"githubConfig"`
	Id           string                           `json:"id"`
	Kind         AuthProviderKind                 `json:"kind"`
	OidcConfig   *OpenIDConnectAuthProviderConfig `json:"oidcConfig"`
}

type GraphQLDataSourceHooksConfiguration struct {
	OnWSTransportConnectionInit bool `json:"onWSTransportConnectionInit"`
}

type NodeOptions struct {
	DefaultRequestTimeoutSeconds int64                  `json:"defaultRequestTimeoutSeconds"`
	Listen                       *ListenerOptions       `json:"listen"`
	Logger                       *NodeLogging           `json:"logger"`
	NodeUrl                      *ConfigurationVariable `json:"nodeUrl"`
	PublicNodeUrl                *ConfigurationVariable `json:"publicNodeUrl"`
}

type Location struct {
	Column int64 `json:"column"`
	Line   int64 `json:"line"`
}

type MockResolveHookConfiguration struct {
	Enabled                           bool  `json:"enabled"`
	SubscriptionPollingIntervalMillis int64 `json:"subscriptionPollingIntervalMillis"`
}

type DataSourceConfiguration_customRestMap map[string]*DataSourceCustom_REST

type S3UploadConfiguration_uploadProfiles map[string]*S3UploadProfile

type OperationAuthorizationConfig struct {
	Claims     []*ClaimConfig       `json:"claims"`
	RoleConfig *OperationRoleConfig `json:"roleConfig"`
}

type JwksAuthProvider struct {
	JwksJson                *ConfigurationVariable `json:"jwksJson"`
	JwksUrl                 *ConfigurationVariable `json:"jwksUrl"`
	UserInfoCacheTtlSeconds int64                  `json:"userInfoCacheTtlSeconds"`
	UserInfoEndpoint        *ConfigurationVariable `json:"userInfoEndpoint"`
}

type TypeConfiguration struct {
	RenameTo string `json:"renameTo"`
	TypeName string `json:"typeName"`
}

type ApiAuthenticationConfig struct {
	CookieBased  *CookieBasedAuthentication `json:"cookieBased"`
	Hooks        *ApiAuthenticationHooks    `json:"hooks"`
	JwksBased    *JwksBasedAuthentication   `json:"jwksBased"`
	PublicClaims []string                   `json:"publicClaims"`
}

type TypeField_quotes map[string]*QuoteField

type MiddlewareHookResponse struct {
	Error                   string         `json:"error,omitempty"`
	Hook                    string         `json:"hook"`
	Input                   any            `json:"input"`
	Op                      string         `json:"op"`
	Response                any            `json:"response"`
	SetClientRequestHeaders RequestHeaders `json:"setClientRequestHeaders"`
}

type CustomizeHookPayload_variables map[string]any

type OperationsConfig_function_operation_files map[string]*ExtensionOperationFile

type OnResponseHookResponse struct {
	Cancel   bool                 `json:"cancel"`
	Response *WunderGraphResponse `json:"response"`
	Skip     bool                 `json:"skip"`
}

type ArgumentConfiguration struct {
	Name                string                      `json:"name"`
	RenameTypeTo        string                      `json:"renameTypeTo"`
	RenderConfiguration ArgumentRenderConfiguration `json:"renderConfiguration"`
	SourcePath          []string                    `json:"sourcePath"`
	SourceType          ArgumentSource              `json:"sourceType"`
}

type DataSourceRESTSubfield struct {
	Name string `json:"name"`
	Type int64  `json:"type"`
}

type TypeField struct {
	FieldNames []string         `json:"fieldNames"`
	Quotes     TypeField_quotes `json:"quotes,omitempty"`
	TypeName   string           `json:"typeName"`
}

type SingleTypeField struct {
	FieldName string `json:"fieldName"`
	TypeName  string `json:"typeName"`
}

type DataSourceConfiguration_customRestResponseRewriterMap map[string]*DataSourceCustom_REST_Rewriter

type ListenerOptions struct {
	Host *ConfigurationVariable `json:"host"`
	Port *ConfigurationVariable `json:"port"`
}

type HookFile struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Size     int64  `json:"size"`
	Type     string `json:"type"`
}

type User struct {
	AccessToken       any               `json:"accessToken,omitempty"`
	BirthDate         string            `json:"birthDate,omitempty"`
	CustomAttributes  []string          `json:"customAttributes,omitempty"`
	CustomClaims      User_customClaims `json:"customClaims,omitempty"`
	Email             string            `json:"email,omitempty"`
	EmailVerified     bool              `json:"emailVerified,omitempty"`
	Etag              string            `json:"etag,omitempty"`
	FirstName         string            `json:"firstName,omitempty"`
	FromCookie        bool              `json:"fromCookie,omitempty"`
	Gender            string            `json:"gender,omitempty"`
	IdToken           any               `json:"idToken,omitempty"`
	LastName          string            `json:"lastName,omitempty"`
	Locale            string            `json:"locale,omitempty"`
	Location          string            `json:"location,omitempty"`
	MiddleName        string            `json:"middleName,omitempty"`
	Name              string            `json:"name,omitempty"`
	NickName          string            `json:"nickName,omitempty"`
	Picture           string            `json:"picture,omitempty"`
	PreferredUsername string            `json:"preferredUsername,omitempty"`
	Profile           string            `json:"profile,omitempty"`
	Provider          string            `json:"provider,omitempty"`
	ProviderId        string            `json:"providerId,omitempty"`
	RawAccessToken    string            `json:"rawAccessToken,omitempty"`
	RawIdToken        string            `json:"rawIdToken,omitempty"`
	Roles             []string          `json:"roles"`
	UserId            string            `json:"userId,omitempty"`
	Website           string            `json:"website,omitempty"`
	ZoneInfo          string            `json:"zoneInfo,omitempty"`
}

type ClaimRemoveIfNoneMatch struct {
	Name string                     `json:"name"`
	Type ClaimRemoveIfNoneMatchType `json:"type"`
}

type Operation struct {
	AuthenticationConfig         *OperationAuthenticationConfig   `json:"authenticationConfig"`
	AuthorizationConfig          *OperationAuthorizationConfig    `json:"authorizationConfig"`
	CacheConfig                  *OperationCacheConfig            `json:"cacheConfig"`
	Content                      string                           `json:"content"`
	DatasourceQuotes             Operation_datasourceQuotes       `json:"datasourceQuotes"`
	Engine                       OperationExecutionEngine         `json:"engine"`
	HooksConfiguration           *OperationHooksConfiguration     `json:"hooksConfiguration"`
	InjectedVariablesSchema      string                           `json:"injectedVariablesSchema,omitempty"`
	Internal                     bool                             `json:"internal"`
	InternalVariablesSchema      string                           `json:"internalVariablesSchema,omitempty"`
	InterpolationVariablesSchema string                           `json:"interpolationVariablesSchema,omitempty"`
	LiveQueryConfig              *OperationLiveQueryConfig        `json:"liveQueryConfig"`
	MultipartForms               []*OperationMultipartForm        `json:"multipartForms"`
	Name                         string                           `json:"name"`
	OperationType                OperationType                    `json:"operationType"`
	Path                         string                           `json:"path"`
	PostResolveTransformations   []*PostResolveTransformation     `json:"postResolveTransformations"`
	RateLimit                    *OperationRateLimit              `json:"rateLimit"`
	ResponseSchema               string                           `json:"responseSchema,omitempty"`
	Transaction                  *OperationTransaction            `json:"transaction"`
	VariablesConfiguration       *OperationVariablesConfiguration `json:"variablesConfiguration"`
	VariablesSchema              string                           `json:"variablesSchema,omitempty"`
}

type UpstreamAuthentication struct {
	JwtConfig                        *JwtUpstreamAuthenticationConfig                  `json:"jwtConfig"`
	JwtWithAccessTokenExchangeConfig *JwtUpstreamAuthenticationWithAccessTokenExchange `json:"jwtWithAccessTokenExchangeConfig"`
	Kind                             UpstreamAuthenticationKind                        `json:"kind"`
}

type OperationRateLimit struct {
	Enabled   bool  `json:"enabled"`
	PerSecond int64 `json:"perSecond"`
	Requests  int64 `json:"requests"`
}

type S3UploadProfile struct {
	AllowedFileExtensions     []string                           `json:"allowedFileExtensions"`
	AllowedMimeTypes          []string                           `json:"allowedMimeTypes"`
	Hooks                     *S3UploadProfileHooksConfiguration `json:"hooks"`
	MaxAllowedFiles           int64                              `json:"maxAllowedFiles"`
	MaxAllowedUploadSizeBytes int64                              `json:"maxAllowedUploadSizeBytes"`
	MetadataJSONSchema        string                             `json:"metadataJSONSchema"`
	RequireAuthentication     bool                               `json:"requireAuthentication"`
}

type Schemas map[string]*SchemaRef

type DataSourceCustom_Static struct {
	Data *ConfigurationVariable `json:"data"`
}

type OperationCacheConfig struct {
	Enabled              bool  `json:"enabled"`
	MaxAge               int64 `json:"maxAge"`
	Public               bool  `json:"public"`
	StaleWhileRevalidate int64 `json:"staleWhileRevalidate"`
}

type DirectiveConfiguration struct {
	DirectiveName string `json:"directiveName"`
	RenameTo      string `json:"renameTo"`
}

type OperationHookPayload struct {
	Wg                      *BaseRequestBodyWg            `json:"__wg"`
	Hook                    MiddlewareHook                `json:"hook"`
	Input                   any                           `json:"input"`
	Op                      string                        `json:"op"`
	Response                OperationHookPayload_response `json:"response"`
	SetClientRequestHeaders RequestHeaders                `json:"setClientRequestHeaders"`
}

type DatasourceQuote struct {
	Fields []string `json:"fields"`
}

type QuoteField struct {
	Indexes []int64 `json:"indexes"`
}

type GithubAuthProviderConfig struct {
	ClientId     *ConfigurationVariable `json:"clientId"`
	ClientSecret *ConfigurationVariable `json:"clientSecret"`
}

type JwtUpstreamAuthenticationConfig struct {
	Secret        *ConfigurationVariable `json:"secret"`
	SigningMethod int64                  `json:"signingMethod"`
}

type HTTPHeader struct {
	Values []*ConfigurationVariable `json:"values"`
}

type PostResolveTransformation struct {
	Depth int64                         `json:"depth"`
	Get   *PostResolveGetTransformation `json:"get"`
	Kind  PostResolveTransformationKind `json:"kind"`
}

type ServerOptions struct {
	Listen    *ListenerOptions       `json:"listen"`
	Logger    *ServerLogging         `json:"logger"`
	ServerUrl *ConfigurationVariable `json:"serverUrl"`
}

type WunderGraphRequest struct {
	Body       any            `json:"body,omitempty"`
	Headers    RequestHeaders `json:"headers"`
	Method     string         `json:"method"`
	OriginBody []byte         `json:"originBody,omitempty"`
	RequestURI string         `json:"requestURI"`
}

type Health struct {
	Report *HealthReport `json:"report"`
	Status string        `json:"status"`
}

type DataSourceRESTRewriter struct {
	ApplySubCommonField       string                                           `json:"applySubCommonField,omitempty"`
	ApplySubCommonFieldValues DataSourceRESTRewriter_applySubCommonFieldValues `json:"applySubCommonFieldValues,omitempty"`
	ApplySubFieldTypes        []*DataSourceRESTSubfield                        `json:"applySubFieldTypes,omitempty"`
	ApplySubObjects           []*DataSourceRESTSubObject                       `json:"applySubObjects,omitempty"`
	CustomEnumField           string                                           `json:"customEnumField,omitempty"`
	CustomObjectName          string                                           `json:"customObjectName,omitempty"`
	FieldRewriteTo            string                                           `json:"fieldRewriteTo,omitempty"`
	PathComponents            []string                                         `json:"pathComponents"`
	QuoteObjectName           string                                           `json:"quoteObjectName,omitempty"`
	Type                      int64                                            `json:"type"`
	ValueRewrites             DataSourceRESTRewriter_valueRewrites             `json:"valueRewrites,omitempty"`
}

type MTLSConfiguration struct {
	Cert               *ConfigurationVariable `json:"cert"`
	InsecureSkipVerify bool                   `json:"insecureSkipVerify"`
	Key                *ConfigurationVariable `json:"key"`
}

type ArgumentRenderConfiguration int64

const (
	ArgumentRenderConfiguration_RENDER_ARGUMENT_DEFAULT          ArgumentRenderConfiguration = 0
	ArgumentRenderConfiguration_RENDER_ARGUMENT_AS_GRAPHQL_VALUE ArgumentRenderConfiguration = 1
	ArgumentRenderConfiguration_RENDER_ARGUMENT_AS_ARRAY_CSV     ArgumentRenderConfiguration = 2
	ArgumentRenderConfiguration_RENDER_ARGUMENT_AS_JSON_VALUE    ArgumentRenderConfiguration = 3
)

type ArgumentSource int64

const (
	ArgumentSource_OBJECT_FIELD   ArgumentSource = 0
	ArgumentSource_FIELD_ARGUMENT ArgumentSource = 1
)

type AuthProviderKind int64

const (
	AuthProviderKind_AuthProviderGithub AuthProviderKind = 0
	AuthProviderKind_AuthProviderOIDC   AuthProviderKind = 1
	AuthProviderKind_AuthProviderAuth0  AuthProviderKind = 2
)

type ClaimRemoveIfNoneMatchType int64

const (
	ClaimRemoveIfNoneMatchType_Header      ClaimRemoveIfNoneMatchType = 0
	ClaimRemoveIfNoneMatchType_Environment ClaimRemoveIfNoneMatchType = 1
)

type ClaimType int64

const (
	ClaimType_ISSUER             ClaimType = 0
	ClaimType_USERID             ClaimType = 1
	ClaimType_WEBSITE            ClaimType = 10
	ClaimType_EMAIL              ClaimType = 11
	ClaimType_EMAIL_VERIFIED     ClaimType = 12
	ClaimType_GENDER             ClaimType = 13
	ClaimType_BIRTH_DATE         ClaimType = 14
	ClaimType_ZONE_INFO          ClaimType = 15
	ClaimType_LOCALE             ClaimType = 16
	ClaimType_LOCATION           ClaimType = 17
	ClaimType_ROLES              ClaimType = 18
	ClaimType_NAME               ClaimType = 2
	ClaimType_GIVEN_NAME         ClaimType = 3
	ClaimType_FAMILY_NAME        ClaimType = 4
	ClaimType_MIDDLE_NAME        ClaimType = 5
	ClaimType_NICKNAME           ClaimType = 6
	ClaimType_PREFERRED_USERNAME ClaimType = 7
	ClaimType_PROFILE            ClaimType = 8
	ClaimType_PICTURE            ClaimType = 9
	ClaimType_CUSTOM             ClaimType = 999
)

type ConfigurationVariableKind int64

const (
	ConfigurationVariableKind_STATIC_CONFIGURATION_VARIABLE      ConfigurationVariableKind = 0
	ConfigurationVariableKind_ENV_CONFIGURATION_VARIABLE         ConfigurationVariableKind = 1
	ConfigurationVariableKind_PLACEHOLDER_CONFIGURATION_VARIABLE ConfigurationVariableKind = 2
)

type DataSourceKind int64

const (
	DataSourceKind_STATIC     DataSourceKind = 0
	DataSourceKind_REST       DataSourceKind = 1
	DataSourceKind_GRAPHQL    DataSourceKind = 2
	DataSourceKind_POSTGRESQL DataSourceKind = 3
	DataSourceKind_MYSQL      DataSourceKind = 4
	DataSourceKind_SQLSERVER  DataSourceKind = 5
	DataSourceKind_MONGODB    DataSourceKind = 6
	DataSourceKind_SQLITE     DataSourceKind = 7
	DataSourceKind_PRISMA     DataSourceKind = 8
)

type DateOffsetUnit int64

const (
	DateOffsetUnit_YEAR   DateOffsetUnit = 0
	DateOffsetUnit_MONTH  DateOffsetUnit = 1
	DateOffsetUnit_DAY    DateOffsetUnit = 2
	DateOffsetUnit_HOUR   DateOffsetUnit = 3
	DateOffsetUnit_MINUTE DateOffsetUnit = 4
	DateOffsetUnit_SECOND DateOffsetUnit = 5
)

type HTTPMethod int64

const (
	HTTPMethod_GET     HTTPMethod = 0
	HTTPMethod_POST    HTTPMethod = 1
	HTTPMethod_PUT     HTTPMethod = 2
	HTTPMethod_DELETE  HTTPMethod = 3
	HTTPMethod_OPTIONS HTTPMethod = 4
	HTTPMethod_CONNECT HTTPMethod = 5
	HTTPMethod_HEAD    HTTPMethod = 6
	HTTPMethod_PATCH   HTTPMethod = 7
	HTTPMethod_TRACE   HTTPMethod = 8
)

type InjectVariableKind int64

const (
	InjectVariableKind_UUID                 InjectVariableKind = 0
	InjectVariableKind_DATE_TIME            InjectVariableKind = 1
	InjectVariableKind_ENVIRONMENT_VARIABLE InjectVariableKind = 2
	InjectVariableKind_FROM_HEADER          InjectVariableKind = 3
)

type MiddlewareHook string

const (
	MiddlewareHook_preResolve                 MiddlewareHook = "preResolve"
	MiddlewareHook_mutatingPreResolve         MiddlewareHook = "mutatingPreResolve"
	MiddlewareHook_mockResolve                MiddlewareHook = "mockResolve"
	MiddlewareHook_customResolve              MiddlewareHook = "customResolve"
	MiddlewareHook_postResolve                MiddlewareHook = "postResolve"
	MiddlewareHook_mutatingPostResolve        MiddlewareHook = "mutatingPostResolve"
	MiddlewareHook_postAuthentication         MiddlewareHook = "postAuthentication"
	MiddlewareHook_mutatingPostAuthentication MiddlewareHook = "mutatingPostAuthentication"
	MiddlewareHook_revalidateAuthentication   MiddlewareHook = "revalidateAuthentication"
	MiddlewareHook_postLogout                 MiddlewareHook = "postLogout"
	MiddlewareHook_beforeOriginRequest        MiddlewareHook = "beforeOriginRequest"
	MiddlewareHook_afterOriginResponse        MiddlewareHook = "afterOriginResponse"
	MiddlewareHook_onOriginRequest            MiddlewareHook = "onOriginRequest"
	MiddlewareHook_onOriginResponse           MiddlewareHook = "onOriginResponse"
	MiddlewareHook_onConnectionInit           MiddlewareHook = "onConnectionInit"
)

type OperationExecutionEngine int64

const (
	OperationExecutionEngine_ENGINE_GRAPHQL  OperationExecutionEngine = 0
	OperationExecutionEngine_ENGINE_FUNCTION OperationExecutionEngine = 1
	OperationExecutionEngine_ENGINE_PROXY    OperationExecutionEngine = 2
)

type OperationType int64

const (
	OperationType_QUERY        OperationType = 0
	OperationType_MUTATION     OperationType = 1
	OperationType_SUBSCRIPTION OperationType = 2
)

type PostResolveTransformationKind int64

const (
	PostResolveTransformationKind_GET_POST_RESOLVE_TRANSFORMATION PostResolveTransformationKind = 0
)

type SigningMethod int64

const (
	SigningMethod_SigningMethodHS256 SigningMethod = 0
)

type UploadHook string

const (
	UploadHook_preUpload  UploadHook = "preUpload"
	UploadHook_postUpload UploadHook = "postUpload"
)

type UpstreamAuthenticationKind int64

const (
	UpstreamAuthenticationKind_UpstreamAuthenticationJWT                        UpstreamAuthenticationKind = 0
	UpstreamAuthenticationKind_UpstreamAuthenticationJWTWithAccessTokenExchange UpstreamAuthenticationKind = 1
)

type ValueType int64

const (
	ValueType_STRING  ValueType = 0
	ValueType_INT     ValueType = 1
	ValueType_FLOAT   ValueType = 2
	ValueType_BOOLEAN ValueType = 3
	ValueType_ARRAY   ValueType = 4
)

type VariableWhereInputRelationFilterType int64

const (
	VariableWhereInputRelationFilterType_is    VariableWhereInputRelationFilterType = 0
	VariableWhereInputRelationFilterType_isNot VariableWhereInputRelationFilterType = 1
	VariableWhereInputRelationFilterType_some  VariableWhereInputRelationFilterType = 2
	VariableWhereInputRelationFilterType_every VariableWhereInputRelationFilterType = 3
	VariableWhereInputRelationFilterType_none  VariableWhereInputRelationFilterType = 4
)

type VariableWhereInputScalarFilterType int64

const (
	VariableWhereInputScalarFilterType_equals     VariableWhereInputScalarFilterType = 0
	VariableWhereInputScalarFilterType_in         VariableWhereInputScalarFilterType = 1
	VariableWhereInputScalarFilterType_notIn      VariableWhereInputScalarFilterType = 2
	VariableWhereInputScalarFilterType_lt         VariableWhereInputScalarFilterType = 3
	VariableWhereInputScalarFilterType_lte        VariableWhereInputScalarFilterType = 4
	VariableWhereInputScalarFilterType_gt         VariableWhereInputScalarFilterType = 5
	VariableWhereInputScalarFilterType_gte        VariableWhereInputScalarFilterType = 6
	VariableWhereInputScalarFilterType_contains   VariableWhereInputScalarFilterType = 7
	VariableWhereInputScalarFilterType_startsWith VariableWhereInputScalarFilterType = 8
	VariableWhereInputScalarFilterType_endsWith   VariableWhereInputScalarFilterType = 9
)

type WebhookVerifierKind int64

const (
	WebhookVerifierKind_HMAC_SHA256 WebhookVerifierKind = 0
)

type CustomizeFlag string

const (
	CustomizeFlag_graphqlEndpoint CustomizeFlag = "${graphqlEndpoint}"
	CustomizeFlag___schema        CustomizeFlag = "__schema"
	CustomizeFlag_subscription    CustomizeFlag = "subscription"
)

type Endpoint string

const (
	Endpoint_mutatingPostAuthentication Endpoint = "/authentication/mutatingPostAuthentication"
	Endpoint_postAuthentication         Endpoint = "/authentication/postAuthentication"
	Endpoint_postLogout                 Endpoint = "/authentication/postLogout"
	Endpoint_revalidateAuthentication   Endpoint = "/authentication/revalidateAuthentication"
	Endpoint_function                   Endpoint = "/function/{path}"
	Endpoint_afterOriginResponse        Endpoint = "/global/httpTransport/afterOriginResponse"
	Endpoint_beforeOriginRequest        Endpoint = "/global/httpTransport/beforeOriginRequest"
	Endpoint_onOriginRequest            Endpoint = "/global/httpTransport/onOriginRequest"
	Endpoint_onOriginResponse           Endpoint = "/global/httpTransport/onOriginResponse"
	Endpoint_onConnectionInit           Endpoint = "/global/wsTransport/onConnectionInit"
	Endpoint_customize                  Endpoint = "/gqls/{name}/graphql"
	Endpoint_health                     Endpoint = "/health"
	Endpoint__internalRequest           Endpoint = "/internal/operations/{path}"
	Endpoint_customResolve              Endpoint = "/operation/{path}/customResolve"
	Endpoint_mockResolve                Endpoint = "/operation/{path}/mockResolve"
	Endpoint_mutatingPostResolve        Endpoint = "/operation/{path}/mutatingPostResolve"
	Endpoint_mutatingPreResolve         Endpoint = "/operation/{path}/mutatingPreResolve"
	Endpoint_postResolve                Endpoint = "/operation/{path}/postResolve"
	Endpoint_preResolve                 Endpoint = "/operation/{path}/preResolve"
	Endpoint_proxy                      Endpoint = "/proxy/{path}"
	Endpoint_postUpload                 Endpoint = "/upload/{provider}/{profile}/postUpload"
	Endpoint_preUpload                  Endpoint = "/upload/{provider}/{profile}/preUpload"
)

type HookParent string

const (
	HookParent_authentication HookParent = "authentication"
	HookParent_customize      HookParent = "customize"
	HookParent_fragment       HookParent = "fragment"
	HookParent_function       HookParent = "function"
	HookParent_generated      HookParent = "generated"
	HookParent_global         HookParent = "global"
	HookParent_operation      HookParent = "operation"
	HookParent_proxy          HookParent = "proxy"
	HookParent_storage        HookParent = "storage"
)

type OperationField string

const (
	OperationField_operationType   OperationField = "operationType"
	OperationField_path            OperationField = "path"
	OperationField_responseSchema  OperationField = "responseSchema"
	OperationField_variablesSchema OperationField = "variablesSchema"
)

type OperationTypeString string

const (
	OperationTypeString_mutation     OperationTypeString = "mutation"
	OperationTypeString_query        OperationTypeString = "query"
	OperationTypeString_subscription OperationTypeString = "subscription"
)

type RateLimitHeader string

const (
	RateLimitHeader_x_rateLimit_perSecond RateLimitHeader = "x-rateLimit-perSecond"
	RateLimitHeader_x_rateLimit_requests  RateLimitHeader = "x-rateLimit-requests"
	RateLimitHeader_x_rateLimit_uniqueKey RateLimitHeader = "x-rateLimit-uniqueKey"
)

type RbacHeader string

const (
	RbacHeader_x_rbac_denyMatchAll    RbacHeader = "x-rbac-denyMatchAll"
	RbacHeader_x_rbac_denyMatchAny    RbacHeader = "x-rbac-denyMatchAny"
	RbacHeader_x_rbac_requireMatchAll RbacHeader = "x-rbac-requireMatchAll"
	RbacHeader_x_rbac_requireMatchAny RbacHeader = "x-rbac-requireMatchAny"
)

type TransactionHeader string

const (
	TransactionHeader_X_Transaction_Id       TransactionHeader = "X-Transaction-Id"
	TransactionHeader_X_Transaction_Manually TransactionHeader = "X-Transaction-Manually"
)
