package config

var ModelReverseMap = map[string]string{}

// 核心映射表：[MCP请求名] -> [PPLX真实内部名]
var ModelMap = map[string]string{
	"gpt-5.2":                 "gpt52",
	"gpt-5.1":                 "gpt51",
	"claude-4.5-sonnet":       "claude45sonnet",
	"claude-4.5-sonnet-think": "claude45sonnetthinking",
	"gemini-3-pro":            "gemini30pro",
	"gemini-3-flash":          "gemini3flash",
	"kimi-k2":                 "kimik2thinking",
	"grok-4.1":                "grok41",
	"sonar":                   "turbo",
}

// 既然不用 Max 订阅模型，将其清空
var MaxModelMap = map[string]string{}

func ModelMapGet(key string, defaultValue string) string {
	if value, exists := ModelMap[key]; exists {
		return value
	}
	return defaultValue
}

func ModelReverseMapGet(key string, defaultValue string) string {
	if value, exists := ModelReverseMap[key]; exists {
		return value
	}
	return defaultValue
}

var ResponseModels []map[string]string

func init() {
	for k, v := range ModelMap {
		ModelReverseMap[v] = k
	}
	buildResponseModels()
}

func buildResponseModels() {
	ResponseModels = make([]map[string]string, 0, len(ModelMap)*2)
	for modelID := range ModelMap {
		ResponseModels = append(ResponseModels, map[string]string{"id": modelID})
		// 添加带有 -search 后缀的模型，用于触发联网逻辑
		ResponseModels = append(ResponseModels, map[string]string{"id": modelID + "-search"})
	}
}
