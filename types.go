package unzip

import (
	"fmt"
	"time"
)

// recursiveExtractor 递归解压器接口 (内部使用)
type recursiveExtractor interface {
	// extract 解压文件到指定目录
	extract(archivePath, outputDir string) (*recursiveExtractResult, error)

	// extractWithConfig 使用配置解压文件
	extractWithConfig(archivePath, outputDir string, config extractConfig) (*recursiveExtractResult, error)

	// getSupportedFormats 获取支持的格式列表
	getSupportedFormats() []string

	// validateArchive 验证压缩包是否有效
	validateArchive(archivePath string) error
}

// extractConfig 解压配置 (内部使用)
type extractConfig struct {
	// Passwords 密码列表，按顺序尝试
	Passwords []string

	// Password 单个密码（向后兼容）
	Password string

	// MaxDepth 最大递归深度，0表示不限制
	MaxDepth int

	// MaxFileSize 单文件大小限制（字节），0表示不限制
	MaxFileSize int64

	// MaxTotalSize 总解压大小限制（字节），0表示不限制
	MaxTotalSize int64

	// Timeout 操作超时时间，0表示不限制
	Timeout time.Duration

	// Encoding 文件名编码，默认为UTF-8
	Encoding string

	// OverwriteExisting 是否覆盖已存在的文件
	OverwriteExisting bool

	// PreservePath 是否保留原始路径结构
	PreservePath bool

	// SkipHidden 是否跳过隐藏文件
	SkipHidden bool

	// AllowedExtensions 允许的文件扩展名列表
	AllowedExtensions []string

	// ForbiddenExtensions 禁止的文件扩展名列表
	ForbiddenExtensions []string
	
	// AutoRename 自动重命名重复文件
	AutoRename bool
	
	// CleanNested 清理递归解压产生的中间压缩包文件
	CleanNested bool
}

// defaultExtractConfig 返回默认配置 (内部使用)
func defaultExtractConfig() extractConfig {
	return extractConfig{
		MaxDepth:          10,
		MaxFileSize:       100 * 1024 * 1024,  // 100MB
		MaxTotalSize:      1024 * 1024 * 1024, // 1GB
		Timeout:           30 * time.Minute,
		Encoding:          "UTF-8",
		OverwriteExisting: true,
		PreservePath:      true,
		SkipHidden:        false,
		AutoRename:        true, // 默认启用自动重命名
		CleanNested:       true, // 默认启用清理功能
	}
}

// recursiveExtractResult 递归解压结果 (内部使用)
type recursiveExtractResult struct {
	// Files 解压的文件列表
	Files []extractedFile

	// TotalFiles 总文件数
	TotalFiles int

	// TotalSize 总大小（字节）
	TotalSize int64

	// MaxDepthUsed 实际使用的最大深度
	MaxDepthUsed int

	// ProcessTime 处理时间
	ProcessTime time.Duration

	// Warnings 警告信息
	Warnings []string

	// NestedArchives 嵌套压缩包信息
	NestedArchives []nestedArchiveInfo
	
	// CleanedCount 清理的中间压缩包数量
	CleanedCount int
}

// extractedFile 解压的文件信息 (内部使用)
type extractedFile struct {
	// Path 文件路径（相对于输出目录）
	Path string

	// Size 文件大小
	Size int64

	// ModTime 修改时间
	ModTime time.Time

	// IsDir 是否为目录
	IsDir bool

	// SourceArchive 来源压缩包路径
	SourceArchive string

	// Depth 嵌套深度（0为根级别）
	Depth int

	// Checksum 文件校验和（可选）
	Checksum string
}

// nestedArchiveInfo 嵌套压缩包信息 (内部使用)
type nestedArchiveInfo struct {
	// Path 压缩包路径
	Path string

	// Format 压缩格式
	Format string

	// Depth 嵌套深度
	Depth int

	// Size 压缩包大小
	Size int64

	// ExtractedFiles 从此压缩包解压的文件数
	ExtractedFiles int

	// HasPassword 是否有密码保护
	HasPassword bool

	// PasswordUsed 使用的密码（如果有）
	PasswordUsed string
}

// ArchiveFormat 压缩格式枚举
type ArchiveFormat string

const (
	FormatZIP     ArchiveFormat = "zip"
	FormatRAR     ArchiveFormat = "rar"
	Format7Z      ArchiveFormat = "7z"
	FormatTAR     ArchiveFormat = "tar"
	FormatTARGZ   ArchiveFormat = "tar.gz"
	FormatTARBZ2  ArchiveFormat = "tar.bz2"
	FormatUnknown ArchiveFormat = "unknown"
)

// String 返回格式字符串
func (f ArchiveFormat) String() string {
	return string(f)
}

// ExtractError 解压错误类型
type ExtractError struct {
	Type    ErrorType
	Message string
	Path    string
	Cause   error
}

// Error 实现error接口
func (e *ExtractError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s: %s (path: %s)", e.Type, e.Message, e.Path)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap 返回原始错误
func (e *ExtractError) Unwrap() error {
	return e.Cause
}

// ErrorType 错误类型枚举
type ErrorType string

const (
	// ErrUnsupportedFormat 不支持的格式
	ErrUnsupportedFormat ErrorType = "UNSUPPORTED_FORMAT"

	// ErrPasswordRequired 需要密码
	ErrPasswordRequired ErrorType = "PASSWORD_REQUIRED"

	// ErrInvalidPassword 密码错误
	ErrInvalidPassword ErrorType = "INVALID_PASSWORD"

	// ErrCorruptedArchive 压缩包损坏
	ErrCorruptedArchive ErrorType = "CORRUPTED_ARCHIVE"

	// ErrPathTraversal 路径遍历攻击
	ErrPathTraversal ErrorType = "PATH_TRAVERSAL"

	// ErrFileTooLarge 文件过大
	ErrFileTooLarge ErrorType = "FILE_TOO_LARGE"

	// ErrMaxDepthExceeded 超过最大深度
	ErrMaxDepthExceeded ErrorType = "MAX_DEPTH_EXCEEDED"

	// ErrTimeout 操作超时
	ErrTimeout ErrorType = "TIMEOUT"

	// ErrInvalidPath 无效路径
	ErrInvalidPath ErrorType = "INVALID_PATH"

	// ErrPermissionDenied 权限拒绝
	ErrPermissionDenied ErrorType = "PERMISSION_DENIED"

	// ErrDiskFull 磁盘空间不足
	ErrDiskFull ErrorType = "DISK_FULL"

	// ErrInternalError 内部错误
	ErrInternalError ErrorType = "INTERNAL_ERROR"
)

// String 返回错误类型字符串
func (et ErrorType) String() string {
	return string(et)
}

// NewExtractError 创建解压错误 (内部使用)
func NewExtractError(errType ErrorType, message, path string, cause error) *ExtractError {
	return &ExtractError{
		Type:    errType,
		Message: message,
		Path:    path,
		Cause:   cause,
	}
}

