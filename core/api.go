package core

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"pplx2api/config"
	"pplx2api/logger"
	"pplx2api/model"
	"pplx2api/utils"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/imroc/req/v3"
)

// Client represents a Perplexity API client
type Client struct {
	sessionToken string
	client       *req.Client
	Model        string
	Attachments  []string
	OpenSerch    bool
}

// Perplexity API structures
type PerplexityRequest struct {
	Params   PerplexityParams `json:"params"`
	QueryStr string           `json:"query_str"`
}

type PerplexityParams struct {
	Attachments           []string      `json:"attachments"`
	Language              string        `json:"language"`
	Timezone              string        `json:"timezone"`
	SearchFocus           string        `json:"search_focus"`
	Sources               []string      `json:"sources"`
	SearchRecencyFilter   interface{}   `json:"search_recency_filter"`
	FrontendUUID          string        `json:"frontend_uuid"`
	Mode                  string        `json:"mode"`
	ModelPreference       string        `json:"model_preference"`
	IsRelatedQuery        bool          `json:"is_related_query"`
	IsSponsored           bool          `json:"is_sponsored"`
	VisitorID             string        `json:"visitor_id"`
	UserNextauthID        string        `json:"user_nextauth_id"`
	FrontendContextUUID   string        `json:"frontend_context_uuid"`
	PromptSource          string        `json:"prompt_source"`
	QuerySource           string        `json:"query_source"`
	BrowserHistorySummary []interface{} `json:"browser_history_summary"`
	IsIncognito           bool          `json:"is_incognito"`
	TimeFromFirstType     float64       `json:"time_from_first_type"` // Simulate human typing time: 700ms - 900ms (aligned with cURL capture ~780ms)
	// This is critical for behavioral fingerprinting
	LocalSearchEnabled              bool        `json:"local_search_enabled"`
	UseSchematizedAPI               bool        `json:"use_schematized_api"`
	SendBackTextInStreamingAPI      bool        `json:"send_back_text_in_streaming_api"` // Renamed from SendBackTextInStreaming
	SupportedBlockUseCases          []string    `json:"supported_block_use_cases"`
	ClientCoordinates               interface{} `json:"client_coordinates"`
	Mentions                        []string    `json:"mentions"`
	DslQuery                        string      `json:"dsl_query"` // New: Required
	SkipSearchEnabled               bool        `json:"skip_search_enabled"`
	IsNavSuggestionsDisabled        bool        `json:"is_nav_suggestions_disabled"`
	Source                          string      `json:"source"`
	AlwaysSearchOverride            bool        `json:"always_search_override"`
	OverrideNoSearch                bool        `json:"override_no_search"`
	ShouldAskForMcpToolConfirmation bool        `json:"should_ask_for_mcp_tool_confirmation"`
	BrowserAgentAllowOnceFromToggle bool        `json:"browser_agent_allow_once_from_toggle"`
	ForceEnableBrowserAgent         bool        `json:"force_enable_browser_agent"`
	SupportedFeatures               []string    `json:"supported_features"`
	Version                         string      `json:"version"`
}

// Response structures
type PerplexityResponse struct {
	Blocks       []Block `json:"blocks"`
	Status       string  `json:"status"`
	DisplayModel string  `json:"display_model"`
}

type Block struct {
	MarkdownBlock      *MarkdownBlock      `json:"markdown_block,omitempty"`
	ReasoningPlanBlock *ReasoningPlanBlock `json:"reasoning_plan_block,omitempty"`
	WebResultBlock     *WebResultBlock     `json:"web_result_block,omitempty"`
	ImageModeBlock     *ImageModeBlock     `json:"image_mode_block,omitempty"`
}

type MarkdownBlock struct {
	Chunks []string `json:"chunks"`
}

type ReasoningPlanBlock struct {
	Goals []Goal `json:"goals"`
}

type Goal struct {
	Description string `json:"description"`
}

type WebResultBlock struct {
	WebResults []WebResult `json:"web_results"`
}

type WebResult struct {
	Name    string `json:"name"`
	Snippet string `json:"snippet"`
	URL     string `json:"url"`
}

type ImageModeBlock struct {
	AnswerModeType string `json:"answer_mode_type"`
	Progress       string `json:"progress"`
	MediaItems     []struct {
		Medium    string `json:"medium"`
		Image     string `json:"image"`
		URL       string `json:"url"`
		Name      string `json:"name"`
		Source    string `json:"source"`
		Thumbnail string `json:"thumbnail"`
	} `json:"media_items"`
}

// NewClient 使用你抓取的“原子级”指纹进行初始化
func NewClient(fullCookie string, proxy string, model string, openSerch bool) *Client {
	// 1. 模拟 Chrome 131+ 的 TLS 和 H2 指纹
	client := req.C().ImpersonateChrome().SetTimeout(time.Minute * 10)
	if proxy != "" {
		client.SetProxyURL(proxy)
	}

	// 2. 预生成本次请求的 UUID
	reqID := uuid.New().String()

	// 3. 按照你提供的抓包顺序【像素级对齐】Header
	// 注意：req 会自动处理 :authority 等伪头
	headers := map[string]string{
		"accept":                      "text/event-stream",
		"accept-language":             "en,zh-CN;q=0.9,zh-TW;q=0.8,zh;q=0.7,bn;q=0.6",
		"content-type":                "application/json",
		"dnt":                         "1",
		"origin":                      "https://www.perplexity.ai",
		"priority":                    "u=1, i",
		"referer":                     "https://www.perplexity.ai/",
		"sec-ch-ua":                   `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
		"sec-ch-ua-arch":              `"arm"`,
		"sec-ch-ua-bitness":           `"64"`,
		"sec-ch-ua-full-version":      `"143.0.7499.193"`,
		"sec-ch-ua-full-version-list": `"Google Chrome";v="143.0.7499.193", "Chromium";v="143.0.7499.193", "Not A(Brand";v="24.0.0.0"`,
		"sec-ch-ua-mobile":            "?0",
		"sec-ch-ua-model":             `""`,
		"sec-ch-ua-platform":          `"macOS"`,
		"sec-ch-ua-platform-version":  `"26.2.0"`,
		"sec-fetch-dest":              "empty",
		"sec-fetch-mode":              "cors",
		"sec-fetch-site":              "same-origin",
		"sec-gpc":                     "1",
		"user-agent":                  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		"x-perplexity-request-reason": "perplexity-query-state-provider",
		"x-request-id":                reqID, // 必须与 Payload 一致
	}

	for k, v := range headers {
		client.SetCommonHeader(k, v)
	}

	// 4. 注入全量 Cookie
	// 这里直接解析你抓到的整段 Cookie 字符串
	if fullCookie != "" {
		cookies := strings.Split(fullCookie, "; ")
		for _, c := range cookies {
			parts := strings.SplitN(c, "=", 2)
			if len(parts) == 2 {
				client.SetCommonCookies(&http.Cookie{
					Name:   parts[0],
					Value:  parts[1],
					Domain: ".perplexity.ai",
				})
			}
		}
	}

	return &Client{client: client, Model: model, OpenSerch: openSerch}
}

func (c *Client) SendMessage(message string, stream bool, is_incognito bool, gc *gin.Context) (int, error) {
	// 获取刚才在 NewClient 里设置的 x-request-id
	reqID := c.client.Headers.Get("x-request-id")

	// 构造完全对齐的 Payload
	requestBody := PerplexityRequest{
		Params: PerplexityParams{
			Attachments:                     []string{},
			Language:                        "en-US",
			Timezone:                        "America/Toronto",
			SearchFocus:                     "internet",
			Sources:                         []string{"web"},
			SearchRecencyFilter:             nil,
			FrontendUUID:                    reqID, // 核心对齐
			Mode:                            "copilot",
			ModelPreference:                 "experimental",
			IsRelatedQuery:                  false,
			IsSponsored:                     false,
			FrontendContextUUID:             uuid.New().String(),
			PromptSource:                    "user",
			QuerySource:                     "home",
			IsIncognito:                     is_incognito,
			TimeFromFirstType:               780.5,
			LocalSearchEnabled:              false,
			UseSchematizedAPI:               true,
			SendBackTextInStreamingAPI:      false,
			SupportedBlockUseCases:          []string{"answer_modes", "media_items", "knowledge_cards", "inline_entity_cards", "place_widgets", "finance_widgets", "prediction_market_widgets", "sports_widgets", "flight_status_widgets", "news_widgets", "shopping_widgets", "jobs_widgets", "search_result_widgets", "inline_images", "inline_assets", "placeholder_cards", "diff_blocks", "inline_knowledge_cards", "entity_group_v2", "refinement_filters", "canvas_mode", "maps_preview", "answer_tabs", "price_comparison_widgets", "preserve_latex", "generic_onboarding_widgets", "in_context_suggestions"},
			ClientCoordinates:               nil,
			Mentions:                        []string{},
			DslQuery:                        message,
			SkipSearchEnabled:               true,
			IsNavSuggestionsDisabled:        false,
			Source:                          "default",
			AlwaysSearchOverride:            false,
			OverrideNoSearch:                false,
			ShouldAskForMcpToolConfirmation: true,
			BrowserAgentAllowOnceFromToggle: false,
			ForceEnableBrowserAgent:         false,
			SupportedFeatures:               []string{"browser_agent_permission_banner_v1.1"},
			Version:                         "2.18",
		},
		QueryStr: message,
	}
	if c.OpenSerch {
		requestBody.Params.SearchFocus = "internet"
		requestBody.Params.Sources = append(requestBody.Params.Sources, "web")
	}
	logger.Info(fmt.Sprintf("Perplexity request body: %v", requestBody))
	// Make the request
	resp, err := c.client.R().DisableAutoReadResponse().
		SetBody(requestBody).
		Post("https://www.perplexity.ai/rest/sse/perplexity_ask")

	if err != nil {
		logger.Error(fmt.Sprintf("Error sending request: %v", err))
		return 500, fmt.Errorf("request failed: %w", err)
	}

	logger.Info(fmt.Sprintf("Perplexity response status code: %d", resp.StatusCode))

	if resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		return http.StatusTooManyRequests, fmt.Errorf("rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		logger.Error(fmt.Sprintf("Unexpected return data: %s", resp.String()))
		resp.Body.Close()
		return resp.StatusCode, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return 200, c.HandleResponse(resp.Body, stream, gc)
}

func (c *Client) HandleResponse(body io.ReadCloser, stream bool, gc *gin.Context) error {
	defer body.Close()
	if stream {
		gc.Writer.Header().Set("Content-Type", "text/event-stream")
		gc.Writer.Header().Set("Cache-Control", "no-cache")
		gc.Writer.Header().Set("Connection", "keep-alive")
		gc.Writer.WriteHeader(http.StatusOK)
		gc.Writer.Flush()
	}

	scanner := bufio.NewScanner(body)
	clientDone := gc.Request.Context().Done()
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// --- 终极状态追踪器 ---
	var full_text string
	var currentReasoning string // 记录完整的推理历史
	var currentMarkdown string  // 记录完整的正文历史
	var hasThinkOpen bool

	// --- 新增状态变量 ---
	var hasValidData bool = false // 标记是否收到了有效数据
	var firstFewLines []string    // 用于记录非 SSE 的错误内容（前几行）

	for scanner.Scan() {
		select {
		case <-clientDone:
			logger.Info("Client connection closed")
			return nil
		default:
		}

		line := scanner.Text()

		// --- 修改判断逻辑 ---
		if line == "" {
			continue
		}

		if !strings.HasPrefix(line, "data: ") {
			// 如果还没收到过有效数据，就记录下这些“垃圾”行，看看是不是 HTML
			if !hasValidData && len(firstFewLines) < 10 {
				firstFewLines = append(firstFewLines, line)
			}
			continue
		}

		// 只要进来了这里，说明确实是 SSE 流
		hasValidData = true

		data := line[6:]
		var response PerplexityResponse
		if err := json.Unmarshal([]byte(data), &response); err != nil {
			continue
		}

		// --- 专家级：多块增量去重算法 ---
		for _, block := range response.Blocks {
			// 1. 处理推理块
			if block.ReasoningPlanBlock != nil {
				var sb strings.Builder
				for _, goal := range block.ReasoningPlanBlock.Goals {
					if goal.Description != "" && goal.Description != "Beginning analysis" && goal.Description != "Wrapping up analysis" {
						sb.WriteString(goal.Description)
					}
				}
				newTotal := sb.String()
				// 只有当新内容确实包含了旧内容且更长时，才提取增量
				if len(newTotal) > len(currentReasoning) && strings.HasPrefix(newTotal, currentReasoning) {
					delta := newTotal[len(currentReasoning):]
					currentReasoning = newTotal // 更新完整历史

					res := ""
					if !hasThinkOpen {
						res += "<think>"
						hasThinkOpen = true
					}
					res += delta
					full_text += res
					if stream {
						model.ReturnOpenAIResponse(res, stream, gc)
					}
				}
			}

			// 2. 处理正文块
			if block.MarkdownBlock != nil {
				var sb strings.Builder
				for _, chunk := range block.MarkdownBlock.Chunks {
					sb.WriteString(chunk)
				}
				newTotal := sb.String()
				// 核心：精准前缀对齐去重
				if len(newTotal) > len(currentMarkdown) && strings.HasPrefix(newTotal, currentMarkdown) {
					delta := newTotal[len(currentMarkdown):]
					currentMarkdown = newTotal // 更新完整历史

					res := ""
					if hasThinkOpen {
						res += "</think>\n\n"
						hasThinkOpen = false
					}
					res += delta
					full_text += res
					if stream {
						model.ReturnOpenAIResponse(res, stream, gc)
					}
				}
			}
		}

		// 3. 处理完成与元数据
		if response.Status == "COMPLETED" {
			// 1. 强制关闭思考标签 (兜底)
			if hasThinkOpen {
				closeTag := "</think>\n\n"
				full_text += closeTag
				if stream {
					model.ReturnOpenAIResponse(closeTag, stream, gc)
				}
				hasThinkOpen = false
			}

			// 2. 处理图片
			for _, block := range response.Blocks {
				if block.ImageModeBlock != nil && block.ImageModeBlock.Progress == "DONE" && len(block.ImageModeBlock.MediaItems) > 0 {
					var imgText string
					var modelList []string
					for i, result := range block.ImageModeBlock.MediaItems {
						imgText += utils.ImageShow(i, result.Name, result.Image)
						modelList = append(modelList, result.Name)
					}
					if len(modelList) > 0 {
						imgText += "\n\n---\n" + strings.Join(modelList, ", ")
					}
					full_text += imgText
					if stream {
						model.ReturnOpenAIResponse(imgText, stream, gc)
					}
				}
			}

			// 3. 处理搜索结果
			for _, block := range response.Blocks {
				if !config.ConfigInstance.IgnoreSerchResult && block.WebResultBlock != nil && len(block.WebResultBlock.WebResults) > 0 {
					webText := "\n\n---\n"
					for i, result := range block.WebResultBlock.WebResults {
						webText += "\n\n" + utils.SearchShow(i, result.Name, result.URL, result.Snippet)
					}
					full_text += webText
					if stream {
						model.ReturnOpenAIResponse(webText, stream, gc)
					}
				}
			}

			// 4. 处理实际模型监控
			if !config.ConfigInstance.IgnoreModelMonitoring && response.DisplayModel != c.Model {
				monText := "\n\n---\n" + fmt.Sprintf("Display Model: %s\n", config.ModelReverseMapGet(response.DisplayModel, response.DisplayModel))
				full_text += monText
				if stream {
					model.ReturnOpenAIResponse(monText, stream, gc)
				}
			}
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	// 【新增核心检查】如果跑完了循环，却一行有效数据都没收到
	if !hasValidData {
		// 拼接前几行错误日志
		errorContent := strings.Join(firstFewLines, "\n")
		logger.Error(fmt.Sprintf("Upstream returned non-SSE content (Likely WAF/Cloudflare): \n%s", errorContent))

		// 抛出错误，而不是返回空成功
		return fmt.Errorf("upstream blocked request or returned invalid format. First few lines: %s", errorContent)
	}

	// 4. 发送结束标记或最终全量内容
	if !stream {
		model.ReturnOpenAIResponse(full_text, stream, gc)
	} else {
		gc.Writer.Write([]byte("data: [DONE]\n\n"))
		gc.Writer.Flush()
	}

	return nil
}

// UploadURLResponse represents the response from the create_upload_url endpoint
type UploadURLResponse struct {
	S3BucketURL string               `json:"s3_bucket_url"`
	S3ObjectURL string               `json:"s3_object_url"`
	Fields      CloudinaryUploadInfo `json:"fields"`
	RateLimited bool                 `json:"rate_limited"`
}

type CloudinaryUploadInfo struct {
	Timestamp         int    `json:"timestamp"`
	UniqueFilename    string `json:"unique_filename"`
	Folder            string `json:"folder"`
	UseFilename       string `json:"use_filename"`
	PublicID          string `json:"public_id"`
	Transformation    string `json:"transformation"`
	Moderation        string `json:"moderation"`
	ResourceType      string `json:"resource_type"`
	APIKey            string `json:"api_key"`
	CloudName         string `json:"cloud_name"`
	Signature         string `json:"signature"`
	AWSAccessKeyId    string `json:"AWSAccessKeyId"`
	Key               string `json:"key"`
	Tagging           string `json:"tagging"`
	Policy            string `json:"policy"`
	Xamzsecuritytoken string `json:"x-amz-security-token"`
	ACL               string `json:"acl"`
}

// UploadFile is a placeholder for file upload functionality
func (c *Client) createUploadURL(filename string, contentType string) (*UploadURLResponse, error) {
	requestBody := map[string]interface{}{
		"filename":     filename,
		"content_type": contentType,
		"source":       "default",
		"file_size":    12000,
		"force_image":  false,
	}
	resp, err := c.client.R().
		SetBody(requestBody).
		Post("https://www.perplexity.ai/rest/uploads/create_upload_url?version=2.18&source=default")
	if err != nil {
		logger.Error(fmt.Sprintf("Error creating upload URL: %v", err))
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		logger.Error(fmt.Sprintf("Image Upload with status code %d: %s", resp.StatusCode, resp.String()))
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	var uploadURLResponse UploadURLResponse
	logger.Info(fmt.Sprintf("Create upload with status code %d: %s", resp.StatusCode, resp.String()))
	if err := json.Unmarshal(resp.Bytes(), &uploadURLResponse); err != nil {
		logger.Error(fmt.Sprintf("Error unmarshalling upload URL response: %v", err))
		return nil, err
	}
	if uploadURLResponse.RateLimited {
		logger.Error("Rate limit exceeded for upload URL")
		return nil, fmt.Errorf("rate limit exceeded")
	}
	return &uploadURLResponse, nil

}

func (c *Client) UploadImage(img_list []string) error {
	logger.Info(fmt.Sprintf("Uploading %d images to Cloudinary", len(img_list)))

	// Upload images to Cloudinary
	for _, img := range img_list {
		filename := utils.RandomString(5) + ".jpg"
		// Create upload URL
		uploadURLResponse, err := c.createUploadURL(filename, "image/jpeg")
		if err != nil {
			logger.Error(fmt.Sprintf("Error creating upload URL: %v", err))
			return err
		}
		logger.Info(fmt.Sprintf("Upload URL response: %v", uploadURLResponse))
		// Upload image to Cloudinary
		err = c.UloadFileToCloudinary(uploadURLResponse.Fields, "img", img, filename)
		if err != nil {
			logger.Error(fmt.Sprintf("Error uploading image: %v", err))
			return err
		}
	}
	return nil
}

func (c *Client) UloadFileToCloudinary(uploadInfo CloudinaryUploadInfo, contentType string, filedata string, filename string) error {
	// 更新为 AWS S3 上传
	if len(filedata) > 100 {
		logger.Info(fmt.Sprintf("filedata: %s ……", filedata[:50]))
	}
	// Add form fields
	logger.Info(fmt.Sprintf("Uploading file %s to Cloudinary", filename))
	var formFields map[string]string
	if contentType == "img" {
		formFields = map[string]string{
			// "timestamp": fmt.Sprintf("%d", uploadInfo.Timestamp),
			// "unique_filename":      uploadInfo.UniqueFilename,
			// "folder":               uploadInfo.Folder,
			// "use_filename":         uploadInfo.UseFilename,
			// "public_id":            uploadInfo.PublicID,
			// "transformation":       uploadInfo.Transformation,
			// "moderation":           uploadInfo.Moderation,
			// "resource_type":        uploadInfo.ResourceType,
			// "api_key":              uploadInfo.APIKey,
			// "cloud_name":           uploadInfo.CloudName,
			"signature": uploadInfo.Signature,
			// "type":                 "private",
			"key":                  uploadInfo.Key,
			"tagging":              uploadInfo.Tagging,
			"AWSAccessKeyId":       uploadInfo.AWSAccessKeyId,
			"policy":               uploadInfo.Policy,
			"x-amz-security-token": uploadInfo.Xamzsecuritytoken,
			"acl":                  uploadInfo.ACL,
			"Content-Type":         "image/jpeg", // Assuming image/jpeg for images
		}
	} else {
		formFields = map[string]string{
			"acl":                  uploadInfo.ACL,
			"Content-Type":         "text/plain",
			"tagging":              uploadInfo.Tagging,
			"key":                  uploadInfo.Key,
			"AWSAccessKeyId":       uploadInfo.AWSAccessKeyId,
			"x-amz-security-token": uploadInfo.Xamzsecuritytoken,
			"policy":               uploadInfo.Policy,
			"signature":            uploadInfo.Signature,
		}
	}
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	for key, value := range formFields {
		if err := writer.WriteField(key, value); err != nil {
			logger.Error(fmt.Sprintf("Error writing form field %s: %v", key, err))
			return err
		}
	}

	// Add the file,filedata 是base64编码的字符串
	decodedData, err := base64.StdEncoding.DecodeString(filedata)
	if err != nil {
		logger.Error(fmt.Sprintf("Error decoding base64 data: %v", err))
		return err
	}

	// 创建一个文件部分
	part, err := writer.CreateFormFile("file", filename) // 替换 filename.ext 为实际文件名
	if err != nil {
		logger.Error(fmt.Sprintf("Error creating form file: %v", err))
		return err
	}

	// 将解码后的数据写入文件部分
	if _, err := part.Write(decodedData); err != nil {
		logger.Error(fmt.Sprintf("Error writing file data: %v", err))
		return err
	}
	// Close the writer to finalize the form
	if err := writer.Close(); err != nil {
		logger.Error(fmt.Sprintf("Error closing writer: %v", err))
		return err
	}

	// Create the upload request
	// var uploadURL string
	// if contentType == "img" {
	// 	uploadURL = fmt.Sprintf("https://api.cloudinary.com/v1_1/%s/image/upload", uploadInfo.CloudName)
	// } else {
	var uploadURL = "https://ppl-ai-file-upload.s3.amazonaws.com/"
	// }

	resp, err := c.client.R().
		SetHeader("Content-Type", writer.FormDataContentType()).
		SetBodyBytes(requestBody.Bytes()).
		Post(uploadURL)

	if err != nil {
		logger.Error(fmt.Sprintf("Error uploading file: %v", err))
		return err
	}
	logger.Info(fmt.Sprintf("Image Upload with status code %d: %s", resp.StatusCode, resp.String()))
	// if contentType == "img" {
	// 	var uploadResponse map[string]interface{}
	// 	if err := json.Unmarshal(resp.Bytes(), &uploadResponse); err != nil {
	// 		return err
	// 	}
	// 	imgUrl := uploadResponse["secure_url"].(string)
	// 	imgUrl = "https://pplx-res.cloudinary.com/image/private" + imgUrl[strings.Index(imgUrl, "/user_uploads"):]
	// 	c.Attachments = append(c.Attachments, imgUrl)
	// } else {
	c.Attachments = append(c.Attachments, "https://ppl-ai-file-upload.s3.amazonaws.com/"+uploadInfo.Key)
	// }
	return nil
}

// SetBigContext is a placeholder for setting context
func (c *Client) UploadText(context string) error {
	logger.Info("Uploading txt to AWS")
	filedata := base64.StdEncoding.EncodeToString([]byte(context))
	filename := utils.RandomString(5) + ".txt"
	// Upload images to Cloudinary
	uploadURLResponse, err := c.createUploadURL(filename, "text/plain")
	if err != nil {
		logger.Error(fmt.Sprintf("Error creating upload URL: %v", err))
		return err
	}
	logger.Info(fmt.Sprintf("Upload URL response: %v", uploadURLResponse))
	// Upload txt to Cloudinary
	err = c.UloadFileToCloudinary(uploadURLResponse.Fields, "txt", filedata, filename)
	if err != nil {
		logger.Error(fmt.Sprintf("Error uploading image: %v", err))
		return err
	}

	return nil
}

func (c *Client) GetNewCookie() (string, error) {
	resp, err := c.client.R().Get("https://www.perplexity.ai/api/auth/session")
	if err != nil {
		logger.Error(fmt.Sprintf("Error getting session cookie: %v", err))
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		logger.Error(fmt.Sprintf("Error getting session cookie: %s", resp.String()))
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "__Secure-next-auth.session-token" {
			return cookie.Value, nil
		}
	}
	return "", fmt.Errorf("session cookie not found")
}
