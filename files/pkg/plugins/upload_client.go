package plugins

import (
	"bytes"
	"custom-go/pkg/types"
	"encoding/json"
	"fmt"
	"github.com/labstack/echo/v4"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

type (
	UploadProfile   string
	UploadMetadata  interface{}
	UploadParameter struct {
		Directory string
		Profile   UploadProfile
		Metadata  UploadMetadata
		Files     []*UploadFile
	}
	UploadFile struct {
		Reader io.Reader
		Name   string
	}
	UploadResponse []struct {
		Key string `json:"key"`
	}
	UploadClient types.S3UploadConfiguration
)

func NewUploadClient(Name string) *UploadClient {
	client := &UploadClient{Name: Name}
	types.AddRegisteredHook(func(_ echo.Logger) {
		for _, v := range types.WdgGraphConfig.Api.S3UploadConfiguration {
			if v.Name == Name {
				client.UseSSL = v.UseSSL
				client.Endpoint = v.Endpoint
				client.BucketName = v.BucketName
				break
			}
		}
	})
	return client
}

var uploadHttpClient = http.Client{Timeout: 30 * time.Second}

func (u *UploadClient) Upload(parameter *UploadParameter) (uploadResp UploadResponse, err error) {
	body := new(bytes.Buffer)

	writer := multipart.NewWriter(body)
	for _, item := range parameter.Files {
		var formFile io.Writer
		formFile, err = writer.CreateFormFile("file", item.Name)
		if err != nil {
			return
		}

		if _, err = io.Copy(formFile, item.Reader); err != nil {
			return
		}
	}

	if err = writer.Close(); err != nil {
		return
	}

	uploadPath := types.PrivateNodeUrl + fmt.Sprintf("/s3/%s/upload", u.Name)
	if len(parameter.Directory) > 0 {
		uploadPath += "?directory=" + parameter.Directory
	}
	req, err := http.NewRequest("POST", uploadPath, body)
	if err != nil {
		return
	}

	req.Header.Add("Content-Type", writer.FormDataContentType())
	if len(parameter.Profile) > 0 {
		req.Header.Add("X-Upload-Profile", string(parameter.Profile))
	}
	if parameter.Metadata != nil {
		metadataBytes, _ := json.Marshal(parameter.Metadata)
		req.Header.Add("X-Metadata", string(metadataBytes))
	}

	resp, err := uploadHttpClient.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("%d: %s", resp.StatusCode, string(content))
		return
	}

	err = json.Unmarshal(content, &uploadResp)
	return
}

func (u *UploadClient) GetOssUrl(key string) string {
	var ssl string
	if u.UseSSL {
		ssl = "s"
	}
	return fmt.Sprintf("http%s://%s.%s/%s", ssl, u.BucketName, u.Endpoint, key)
}
