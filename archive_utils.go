package unzip

import (
	"os"
	"path/filepath"
	"strings"
)

// ArchiveUtils 压缩文件工具接口（精简版）
type ArchiveUtils interface {
	// EnsureDirectoryExists 确保目录存在
	EnsureDirectoryExists(dirPath string) error

	// IsHiddenFile 检查是否为隐藏文件
	IsHiddenFile(filename string) bool
}

// defaultArchiveUtils 默认压缩文件工具实现
type defaultArchiveUtils struct{}

// NewArchiveUtils 创建新的压缩文件工具
func NewArchiveUtils() ArchiveUtils {
	return &defaultArchiveUtils{}
}

// EnsureDirectoryExists 确保目录存在
func (u *defaultArchiveUtils) EnsureDirectoryExists(dirPath string) error {
	if dirPath == "" {
		return nil
	}

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return os.MkdirAll(dirPath, 0755)
	}
	return nil
}

// IsHiddenFile 检查是否为隐藏文件
func (u *defaultArchiveUtils) IsHiddenFile(filename string) bool {
	if filename == "" {
		return false
	}

	base := filepath.Base(filename)
	
	// Unix/Linux隐藏文件（以.开头）
	if strings.HasPrefix(base, ".") && len(base) > 1 {
		return true
	}

	// 常见的系统文件
	systemFiles := []string{
		"Thumbs.db", "Desktop.ini", ".DS_Store", 
		"__MACOSX", ".AppleDouble", ".LSOverride",
	}

	for _, sysFile := range systemFiles {
		if strings.EqualFold(base, sysFile) {
			return true
		}
	}

	return false
}