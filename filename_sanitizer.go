package unzip

import (
	"path/filepath"
	"regexp"
	"strings"
)

// FilenameSanitizer 文件名安全化处理器
type FilenameSanitizer struct {
	// 危险字符映射表
	dangerousChars map[string]string
	// 非法字符正则表达式
	illegalPattern *regexp.Regexp
}

// NewFilenameSanitizer 创建文件名安全化处理器
func NewFilenameSanitizer() *FilenameSanitizer {
	return &FilenameSanitizer{
		dangerousChars: map[string]string{
			// 全角符号替换为半角
			"：": ":", // 全角冒号 → 半角冒号
			"？": "_", // 全角问号 → 下划线
			"｜": "_", // 全角竖线 → 下划线
			"＊": "_", // 全角星号 → 下划线
			"＜": "_", // 全角小于号 → 下划线
			"＞": "_", // 全角大于号 → 下划线
			"｢": "_", // 全角左引号 → 下划线
			"｣": "_", // 全角右引号 → 下划线
			"「": "_", // 日文左引号 → 下划线
			"」": "_", // 日文右引号 → 下划线
			
			// 其他可能的问题字符
			"\\": "_", // 反斜杠
			"/":  "_", // 正斜杠（在文件名中）
			"*":  "_", // 星号
			"?":  "_", // 问号
			"<":  "_", // 小于号
			">":  "_", // 大于号
			"|":  "_", // 竖线
			"\"": "_", // 双引号
			
			// 特殊情况
			"..": "_", // 双点（防止路径遍历）
		},
		illegalPattern: regexp.MustCompile(`[<>:"/\\|?*]`), // 标准非法字符
	}
}

// SanitizeFilename 安全化文件名
func (fs *FilenameSanitizer) SanitizeFilename(filename string) string {
	if filename == "" {
		return "unnamed_file"
	}
	
	// 处理路径分隔符，只保留文件名部分
	filename = filepath.Base(filename)
	
	// 替换危险字符
	sanitized := filename
	for dangerous, safe := range fs.dangerousChars {
		sanitized = strings.ReplaceAll(sanitized, dangerous, safe)
	}
	
	// 使用正则表达式处理剩余的非法字符
	sanitized = fs.illegalPattern.ReplaceAllString(sanitized, "_")
	
	// 去除首尾空格和点
	sanitized = strings.Trim(sanitized, " .")
	
	// 确保不为空
	if sanitized == "" {
		sanitized = "unnamed_file"
	}
	
	// 限制长度（防止文件名过长）
	if len(sanitized) > 255 {
		ext := filepath.Ext(sanitized)
		nameWithoutExt := strings.TrimSuffix(sanitized, ext)
		if len(nameWithoutExt) > 255-len(ext) {
			nameWithoutExt = nameWithoutExt[:255-len(ext)]
		}
		sanitized = nameWithoutExt + ext
	}
	
	return sanitized
}

