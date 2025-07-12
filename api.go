package unzip

import (
	"path/filepath"
	"strings"
	"time"
)

// ProgressCallback 解压进度回调函数
// current: 当前进度, total: 总进度, filename: 当前处理的文件名
type ProgressCallback func(current, total int64, filename string)

// ExtractResult 解压结果
type ExtractResult struct {
	// 基本信息
	Success      bool     `json:"success"`       // 是否成功
	ExtractedTo  string   `json:"extracted_to"`  // 解压到的目录
	FilesCount   int      `json:"files_count"`   // 解压的文件数量
	TotalSize    int64    `json:"total_size"`    // 总大小(字节)
	ProcessTime  time.Duration `json:"process_time"`  // 处理时间
	
	// 密码信息
	PasswordUsed string   `json:"password_used"` // 使用的密码(如果有)
	
	// 附加信息
	Warnings     []string `json:"warnings"`      // 警告信息
	NestedCount  int      `json:"nested_count"`  // 嵌套压缩包数量
	CleanedCount int      `json:"cleaned_count"` // 清理的中间压缩包数量
}

// ExtractOptions 解压选项
type ExtractOptions struct {
	// 基本设置
	OutputDir      string           `json:"output_dir"`      // 输出目录(空则使用默认)
	Passwords      []string         `json:"passwords"`       // 尝试的密码列表
	ProgressCallback ProgressCallback `json:"-"`             // 进度回调
	
	// 高级设置(可选)
	MaxDepth       int              `json:"max_depth"`       // 最大递归深度(默认5)
	MaxFileSize    int64            `json:"max_file_size"`   // 最大文件大小(默认100MB)
	Timeout        time.Duration    `json:"timeout"`         // 超时时间(默认30分钟)
	Overwrite      bool             `json:"overwrite"`       // 覆盖现有文件(默认false)
	AutoRename     bool             `json:"auto_rename"`     // 自动重命名重复文件(默认true)
	CleanNested    bool             `json:"clean_nested"`    // 清理递归解压产生的中间压缩包文件(默认true)
}

// Extract 解压压缩包 - 主要入口点
//
// 参数:
//   archivePath: 压缩包路径
//   options: 解压选项(可以为nil使用默认设置)
//
// 返回:
//   ExtractResult: 解压结果
//   error: 错误信息
//
// 功能:
//   - 自动检测压缩包格式(ZIP/RAR/7Z/TAR/TAR.GZ/TAR.BZ2)
//   - 自动处理密码(尝试提供的密码+常用密码)
//   - 自动处理嵌套压缩包
//   - 提供进度回调
//   - 输出目录默认为压缩包同目录
func Extract(archivePath string, options *ExtractOptions) (*ExtractResult, error) {
	// 处理默认选项
	if options == nil {
		options = &ExtractOptions{
			AutoRename:  true, // 默认启用自动重命名
			CleanNested: true, // 默认启用清理功能
		}
	}
	// 注意：由于Go的零值语义，用户提供options时bool字段默认为false
	// 如果用户想要true的行为，需要明确设置
	
	// 设置默认输出目录
	if options.OutputDir == "" {
		dir := filepath.Dir(archivePath)
		base := filepath.Base(archivePath)
		// 移除扩展名作为目录名
		name := strings.TrimSuffix(base, filepath.Ext(base))
		// 处理复合扩展名
		if strings.HasSuffix(name, ".tar") {
			name = strings.TrimSuffix(name, ".tar")
		}
		options.OutputDir = filepath.Join(dir, name)
	}
	
	// 设置默认值
	if options.MaxDepth == 0 {
		options.MaxDepth = 5
	}
	if options.MaxFileSize == 0 {
		options.MaxFileSize = 10 * 1024 * 1024 * 1024 // 10GB
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Minute
	}
	if len(options.Passwords) == 0 {
		options.Passwords = []string{} // 空列表，将使用默认密码
	}
	
	// 转换为内部配置
	config := extractConfig{
		Passwords:         options.Passwords,
		MaxDepth:          options.MaxDepth,
		MaxFileSize:       options.MaxFileSize,
		Timeout:           options.Timeout,
		OverwriteExisting: options.Overwrite,
		AutoRename:        options.AutoRename,    // 直接使用用户设置，默认false
		CleanNested:       options.CleanNested,   // 传递清理选项，默认true
		PreservePath:      true,
		SkipHidden:        false,
	}
	
	// 记录开始时间
	startTime := time.Now()
	
	// 执行解压 - 使用内部函数
	result, err := extractWithSmartPasswordTries(archivePath, options.OutputDir, config)
	if err != nil {
		return &ExtractResult{
			Success:     false,
			ExtractedTo: options.OutputDir,
			ProcessTime: time.Since(startTime),
			Warnings:    []string{err.Error()},
		}, err
	}
	
	// 构建简化结果
	extractResult := &ExtractResult{
		Success:      true,
		ExtractedTo:  options.OutputDir,
		FilesCount:   result.TotalFiles,
		TotalSize:    result.TotalSize,
		ProcessTime:  time.Since(startTime),
		Warnings:     result.Warnings,
		NestedCount:  len(result.NestedArchives),
		CleanedCount: result.CleanedCount,
	}
	
	// 获取使用的密码
	if len(result.NestedArchives) > 0 && result.NestedArchives[0].PasswordUsed != "" {
		extractResult.PasswordUsed = result.NestedArchives[0].PasswordUsed
	}
	
	return extractResult, nil
}

// QuickExtract 快速解压 - 最简单的接口
//
// 参数:
//   archivePath: 压缩包路径
//
// 返回:
//   string: 解压到的目录
//   error: 错误信息
//
// 功能:
//   - 使用默认设置解压
//   - 自动处理密码
//   - 解压到压缩包同目录
func QuickExtract(archivePath string) (string, error) {
	return quickExtractInternal(archivePath)
}

// ExtractWithProgress 带进度回调的解压
//
// 参数:
//   archivePath: 压缩包路径
//   outputDir: 输出目录(空则使用默认)
//   callback: 进度回调函数
//
// 返回:
//   ExtractResult: 解压结果
//   error: 错误信息
func ExtractWithProgress(archivePath, outputDir string, callback ProgressCallback) (*ExtractResult, error) {
	options := &ExtractOptions{
		OutputDir:        outputDir,
		ProgressCallback: callback,
	}
	return Extract(archivePath, options)
}

// ExtractWithPassword 带密码的解压
//
// 参数:
//   archivePath: 压缩包路径
//   outputDir: 输出目录(空则使用默认)
//   passwords: 密码列表
//
// 返回:
//   ExtractResult: 解压结果
//   error: 错误信息
func ExtractWithPassword(archivePath, outputDir string, passwords []string) (*ExtractResult, error) {
	options := &ExtractOptions{
		OutputDir: outputDir,
		Passwords: passwords,
	}
	return Extract(archivePath, options)
}

// IsSupported 检查文件是否支持解压
//
// 参数:
//   archivePath: 压缩包路径
//
// 返回:
//   bool: 是否支持
//   string: 格式名称
func IsSupported(archivePath string) (bool, string) {
	return isSupportedInternal(archivePath)
}

// GetSupportedFormats 获取支持的格式列表
//
// 返回:
//   []string: 支持的格式列表
func GetSupportedFormats() []string {
	return []string{"zip", "rar", "7z", "tar", "tar.gz", "tar.bz2"}
}