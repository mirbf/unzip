package unzip

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)


// GenerateUniqueFileName 生成唯一文件名（处理重复文件）
func GenerateUniqueFileName(filePath string) string {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return filePath // 文件不存在，直接返回
	}

	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)
	ext := filepath.Ext(filename)
	nameWithoutExt := strings.TrimSuffix(filename, ext)

	// 尝试添加数字后缀
	for i := 1; i <= 999; i++ {
		newName := fmt.Sprintf("%s_%d%s", nameWithoutExt, i, ext)
		newPath := filepath.Join(dir, newName)
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
	}

	// 如果数字后缀都用完了，使用时间戳
	timestamp := time.Now().Format("20060102_150405")
	newName := fmt.Sprintf("%s_%s%s", nameWithoutExt, timestamp, ext)
	return filepath.Join(dir, newName)
}

// HandleFileConflict 处理文件冲突
func HandleFileConflict(targetPath string, config extractConfig) (string, error) {
	// 检查文件是否存在
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return targetPath, nil // 不存在冲突
	}

	if config.OverwriteExisting {
		return targetPath, nil // 允许覆盖
	}

	if config.AutoRename {
		return GenerateUniqueFileName(targetPath), nil // 自动重命名
	}

	return "", NewExtractError(ErrPermissionDenied, "文件已存在且不允许覆盖", targetPath, nil)
}

// RemoveDuplicateStrings 去除字符串切片中的重复项
func RemoveDuplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}





