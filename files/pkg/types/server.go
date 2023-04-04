package types

import "custom-go/pkg/plugins"

type WunderGraphHooksAndServerConfig struct {
	Webhooks       WebhooksConfig
	Hooks          HooksConfiguration
	GraphqlServers []plugins.GraphQLServerConfig
	Options        ServerOptions
}

type WebhooksConfig map[string]WebhookConfiguration

type WebhookConfiguration struct {
	Verifier
}

type WebhookVerifierKind int

type Verifier struct {
	kind                  WebhookVerifierKind
	secret                EnvironmentVariable[string]
	signatureHeader       string
	signatureHeaderPrefix string
}

type EnvironmentVariable[DefaultValue string] struct {
	Name         string
	DefaultValue DefaultValue
}

type ServerOptions struct {
	ServerUrl InputVariable
	Listen    ListenOptions
	Logger    ServerLogger
}

type ListenOptions struct {
	Host InputVariable
	Port InputVariable
}

type ServerLogger struct {
	Level InputVariable
}

type PlaceHolder struct {
	Name       string
	Identifier string
}

type InputVariable any
