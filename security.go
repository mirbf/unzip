package unzip

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// SecurityValidator 安全验证器接口
type SecurityValidator interface {
	// ValidatePath 验证路径安全性
	ValidatePath(path, baseDir string) error
	
	// ValidateFileSize 验证文件大小
	ValidateFileSize(size, maxSize int64) error
	
	// ValidateTotalSize 验证总大小
	ValidateTotalSize(currentSize, additionalSize, maxSize int64) error
	
	// ValidateDepth 验证递归深度
	ValidateDepth(currentDepth, maxDepth int) error
	
	// SanitizePath 清理路径
	SanitizePath(path string) string
}

// defaultSecurityValidator 默认安全验证器实现
type defaultSecurityValidator struct {
	allowAbsolutePaths bool
	allowSymlinks     bool
	maxPathLength     int
}

// NewSecurityValidator 创建新的安全验证器
func NewSecurityValidator() SecurityValidator {
	return &defaultSecurityValidator{
		allowAbsolutePaths: false,
		allowSymlinks:     false,
		maxPathLength:     260, // Windows路径长度限制
	}
}

// NewSecurityValidatorWithOptions 创建带选项的安全验证器
func NewSecurityValidatorWithOptions(allowAbsolute, allowSymlinks bool, maxPathLen int) SecurityValidator {
	return &defaultSecurityValidator{
		allowAbsolutePaths: allowAbsolute,
		allowSymlinks:     allowSymlinks,
		maxPathLength:     maxPathLen,
	}
}

// ValidatePath 验证路径安全性
func (v *defaultSecurityValidator) ValidatePath(path, baseDir string) error {
	if path == "" {
		return NewExtractError(ErrInvalidPath, "路径不能为空", path, nil)
	}
	
	// 检查路径长度
	if len(path) > v.maxPathLength {
		return NewExtractError(ErrInvalidPath, 
			fmt.Sprintf("路径长度超过限制 (%d > %d)", len(path), v.maxPathLength), 
			path, nil)
	}
	
	// 清理路径
	cleanPath := v.SanitizePath(path)
	
	// 检查绝对路径
	if filepath.IsAbs(cleanPath) && !v.allowAbsolutePaths {
		return NewExtractError(ErrPathTraversal, "不允许绝对路径", path, nil)
	}
	
	// 检查路径遍历
	if err := v.checkPathTraversal(cleanPath, baseDir); err != nil {
		return err
	}
	
	// 检查危险字符
	if err := v.checkDangerousCharacters(cleanPath); err != nil {
		return err
	}
	
	// 检查保留名称（Windows）
	if err := v.checkReservedNames(cleanPath); err != nil {
		return err
	}
	
	return nil
}

// ValidateFileSize 验证文件大小
func (v *defaultSecurityValidator) ValidateFileSize(size, maxSize int64) error {
	// 基础验证
	if size < 0 {
		return NewExtractError(ErrInvalidPath, "文件大小不能为负数", "", nil)
	}
	
	// 绝对大小限制 (10GB)
	if size > 10*1024*1024*1024 {
		return NewExtractError(ErrFileTooLarge, "文件大小不能超过10GB", "", nil)
	}
	
	// 用户指定的大小限制
	if maxSize > 0 && size > maxSize {
		return NewExtractError(ErrFileTooLarge, 
			fmt.Sprintf("文件大小超过限制 (%d > %d)", size, maxSize), 
			"", nil)
	}
	
	return nil
}

// ValidateTotalSize 验证总大小
func (v *defaultSecurityValidator) ValidateTotalSize(currentSize, additionalSize, maxSize int64) error {
	if maxSize <= 0 {
		return nil // 不限制大小
	}
	
	totalSize := currentSize + additionalSize
	if totalSize > maxSize {
		return NewExtractError(ErrFileTooLarge, 
			fmt.Sprintf("总大小超过限制 (%d > %d)", totalSize, maxSize), 
			"", nil)
	}
	
	return nil
}

// ValidateDepth 验证递归深度
func (v *defaultSecurityValidator) ValidateDepth(currentDepth, maxDepth int) error {
	// 基础验证
	if currentDepth < 0 {
		return NewExtractError(ErrInvalidPath, "递归深度不能为负数", "", nil)
	}
	
	// 绝对深度限制
	if currentDepth > 10 {
		return NewExtractError(ErrMaxDepthExceeded, "递归深度不能超过10", "", nil)
	}
	
	// 用户指定的深度限制
	if maxDepth > 0 && currentDepth > maxDepth {
		return NewExtractError(ErrMaxDepthExceeded, 
			fmt.Sprintf("递归深度超过限制 (%d > %d)", currentDepth, maxDepth), 
			"", nil)
	}
	
	return nil
}

// SanitizePath 清理路径
func (v *defaultSecurityValidator) SanitizePath(path string) string {
	// 标准化路径分隔符
	path = filepath.ToSlash(path)
	
	// 移除多余的斜杠
	path = strings.ReplaceAll(path, "//", "/")
	
	// 移除开头的斜杠（除非允许绝对路径）
	if !v.allowAbsolutePaths && strings.HasPrefix(path, "/") {
		path = strings.TrimPrefix(path, "/")
	}
	
	// 清理路径
	path = filepath.Clean(path)
	
	// 移除控制字符
	path = v.removeControlCharacters(path)
	
	return path
}

// checkPathTraversal 检查路径遍历攻击
func (v *defaultSecurityValidator) checkPathTraversal(path, baseDir string) error {
	// 检查明显的路径遍历模式
	dangerousPatterns := []string{
		"..", "...", "....",
		"../", "..\\",
		"/.", "\\.",
		"/..", "\\..",
	}
	
	for _, pattern := range dangerousPatterns {
		if strings.Contains(path, pattern) {
			return NewExtractError(ErrPathTraversal, 
				fmt.Sprintf("检测到路径遍历攻击模式: %s", pattern), 
				path, nil)
		}
	}
	
	// 如果提供了基础目录，检查解析后的路径
	if baseDir != "" {
		absBase, err := filepath.Abs(baseDir)
		if err != nil {
			return NewExtractError(ErrInvalidPath, "无法解析基础目录", baseDir, err)
		}
		
		absPath, err := filepath.Abs(filepath.Join(baseDir, path))
		if err != nil {
			return NewExtractError(ErrInvalidPath, "无法解析目标路径", path, err)
		}
		
		// 检查目标路径是否在基础目录内
		relPath, err := filepath.Rel(absBase, absPath)
		if err != nil || strings.HasPrefix(relPath, "..") {
			return NewExtractError(ErrPathTraversal, 
				"目标路径超出基础目录范围", path, nil)
		}
	}
	
	return nil
}

// checkDangerousCharacters 检查危险字符
func (v *defaultSecurityValidator) checkDangerousCharacters(path string) error {
	// Windows保留字符
	dangerousChars := []rune{'<', '>', ':', '"', '|', '*'}  // 移除 '?' 因为它可能来自编码转换
	
	for _, char := range path {
		// 检查控制字符（但忽略替换字符U+FFFD，它可能来自编码转换）
		if unicode.IsControl(char) && char != '\uFFFD' {
			return NewExtractError(ErrInvalidPath, 
				fmt.Sprintf("路径包含控制字符: U+%04X", char), 
				path, nil)
		}
		
		// 检查危险字符
		for _, dangerous := range dangerousChars {
			if char == dangerous {
				return NewExtractError(ErrInvalidPath, 
					fmt.Sprintf("路径包含危险字符: %c", char), 
					path, nil)
			}
		}
	}
	
	return nil
}

// checkReservedNames 检查Windows保留名称
func (v *defaultSecurityValidator) checkReservedNames(path string) error {
	reservedNames := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}
	
	// 检查路径中的每个组件
	components := strings.Split(path, "/")
	for _, component := range components {
		// 移除扩展名
		name := strings.ToUpper(component)
		if dotIndex := strings.LastIndex(name, "."); dotIndex > 0 {
			name = name[:dotIndex]
		}
		
		// 检查是否为保留名称
		for _, reserved := range reservedNames {
			if name == reserved {
				return NewExtractError(ErrInvalidPath, 
					fmt.Sprintf("路径包含Windows保留名称: %s", reserved), 
					path, nil)
			}
		}
	}
	
	return nil
}

// removeControlCharacters 移除控制字符
func (v *defaultSecurityValidator) removeControlCharacters(path string) string {
	var result strings.Builder
	for _, char := range path {
		if !unicode.IsControl(char) {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// PathSafeJoin 安全地连接路径
func PathSafeJoin(base, path string) (string, error) {
	validator := NewSecurityValidator()
	
	// 验证路径安全性
	if err := validator.ValidatePath(path, base); err != nil {
		return "", err
	}
	
	// 清理路径
	cleanPath := validator.SanitizePath(path)
	
	// 安全连接
	result := filepath.Join(base, cleanPath)
	
	// 最终验证
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	
	absResult, err := filepath.Abs(result)
	if err != nil {
		return "", err
	}
	
	relPath, err := filepath.Rel(absBase, absResult)
	if err != nil || strings.HasPrefix(relPath, "..") {
		return "", NewExtractError(ErrPathTraversal, 
			"路径连接后超出基础目录", path, nil)
	}
	
	return result, nil
}



// ValidateTimeout 验证超时时间
func ValidateTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return NewExtractError(ErrInvalidPath, "超时时间必须大于0", "", nil)
	}
	if timeout > 24*time.Hour {
		return NewExtractError(ErrInvalidPath, "超时时间不能超过24小时", "", nil)
	}
	return nil
}



// ValidateExtractConfig 验证解压配置
func ValidateExtractConfig(config extractConfig) error {
	if config.MaxDepth < 0 {
		return NewExtractError(ErrInvalidPath, "最大深度不能为负数", "", nil)
	}
	
	if config.MaxFileSize < 0 {
		return NewExtractError(ErrInvalidPath, "最大文件大小不能为负数", "", nil)
	}
	
	if config.MaxTotalSize < 0 {
		return NewExtractError(ErrInvalidPath, "最大总大小不能为负数", "", nil)
	}
	
	if config.Timeout < 0 {
		return NewExtractError(ErrInvalidPath, "超时时间不能为负数", "", nil)
	}
	
	// 使用新的验证函数
	if err := ValidateTimeout(config.Timeout); err != nil {
		return err
	}
	
	return nil
}