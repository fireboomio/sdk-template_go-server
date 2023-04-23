package plugins

import (
	"bytes"
	"custom-go/pkg/base"
	"fmt"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"
	"github.com/labstack/echo/v4"
	sse "github.com/r3labs/sse/v2"
	"net/http"
	"os"
)

type GraphQLServerConfig struct {
	ServerName            string
	Schema                graphql.Schema
	ApiNamespace          string
	EnableGraphQLEndpoint bool
	RouteUrl              string
	ContextFactory        func(struct{})
	SkipRenameRootFields  []string
	customResolverFactory func(struct{})
}

type graphqlBody struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables"`
	OperationName string                 `json:"operationName"`
	Extensions    map[string]any         `json:"extensions"`
}

var htmlBytesMap = make(map[string][]byte, 0)

func RegisterGraphql(e *echo.Echo, gqlServer GraphQLServerConfig) {
	if !gqlServer.EnableGraphQLEndpoint {
		return
	}

	routeUrl := fmt.Sprintf(`/gqls/%s/graphql`, gqlServer.ServerName)
	e.Logger.Debugf(`Registered gqlServer (%s)`, routeUrl)
	e.GET(routeUrl, echo.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var htmlBytes []byte
		if val, ok := htmlBytesMap[routeUrl]; ok {
			htmlBytes = val
		} else {
			filePath := "helix.html"
			fileBytes, err := os.ReadFile(filePath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			htmlBytes = bytes.ReplaceAll(fileBytes, []byte("${graphqlEndpoint}"), []byte(routeUrl))
			htmlBytesMap[routeUrl] = htmlBytes
		}
		_, _ = w.Write(htmlBytes)
	})))

	e.POST(routeUrl, func(c echo.Context) error {
		var body graphqlBody
		err := c.Bind(&body)
		if err != nil {
			return buildEchoGraphqlError(c, err)
		}

		brc := c.(*base.BaseRequestContext)
		param := graphql.Params{
			Schema:         gqlServer.Schema,
			OperationName:  body.OperationName,
			RequestString:  body.Query,
			VariableValues: body.Variables,
			Context: &base.GraphqlRequestContext{
				Context:        c.Request().Context(),
				User:           brc.User,
				InternalClient: brc.InternalClient,
				Logger:         brc.Logger(),
			},
		}
		result := graphql.Do(param)
		if rc, ok := result.Data.(chan []byte); ok {
			return handleSSE(c, rc)
		}
		return c.JSON(http.StatusOK, result)
	})
}

func handleSSE(c echo.Context, rc chan []byte) error {
	stream := sse.New()

	// 定义 SSE 事件回调函数，每秒钟发送一个 SSE 事件
	go func() {
		for {
			select {
			case result := <-rc:
				event := &sse.Event{
					Data: result,
				}
				stream.Publish("", event)
			case <-c.Request().Context().Done():
				return
			}
		}
	}()

	// 设置 SSE 响应头
	c.Response().Header().Set(echo.HeaderContentType, "text/event-stream")
	c.Response().WriteHeader(http.StatusOK)

	// 将 SSE 事件流附加到响应体中
	stream.ServeHTTP(c.Response(), c.Request())
	return nil
}

func buildEchoGraphqlError(c echo.Context, err error) error {
	c.Logger().Error(err)
	return c.JSON(http.StatusInternalServerError, graphql.Result{
		Errors: []gqlerrors.FormattedError{{Message: err.Error()}},
	})
}

func GetGraphqlContext(params graphql.ResolveParams) *base.GraphqlRequestContext {
	return params.Context.(*base.GraphqlRequestContext)
}
