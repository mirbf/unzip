package unzip

import (
	"path/filepath"
	"strings"
)

// extractWithSmartPasswordTries 智能密码尝试解压 (内部函数)
func extractWithSmartPasswordTries(archivePath, outputDir string, config extractConfig) (*recursiveExtractResult, error) {
	// 创建解压器
	extractor := newRecursiveExtractor()

	// 首先尝试无密码解压
	result, err := extractor.extractWithConfig(archivePath, outputDir, config)
	if err == nil {
		return result, nil
	}

	// 检查是否为密码错误
	passwordManager := newPasswordManager()
	if !passwordManager.(*defaultPasswordManager).isPasswordError(err) {
		return nil, err // 不是密码问题，直接返回错误
	}

	// 检测文件格式
	detector := NewFormatDetector()
	format, err := detector.DetectFormat(archivePath)
	if err != nil {
		return nil, err
	}

	// 获取解压器
	formatManager := NewFormatExtractorManager()
	extractorInterface, err := formatManager.GetExtractorForFormat(format)
	if err != nil {
		return nil, err
	}

	// 构建智能密码列表
	passwords := passwordManager.buildPasswordList(config.Passwords, true, true)

	// 尝试密码解压
	result, usedPassword, err := passwordManager.tryPasswords(extractorInterface, archivePath, outputDir, passwords, config, 0)
	if err != nil {
		return nil, err
	}

	// 在结果中记录使用的密码
	if len(result.NestedArchives) > 0 {
		result.NestedArchives[0].PasswordUsed = usedPassword
	}

	return result, nil
}


// quickExtractInternal 快速解压内部实现
func quickExtractInternal(archivePath string) (string, error) {
	// 设置默认输出目录
	dir := filepath.Dir(archivePath)
	base := filepath.Base(archivePath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if strings.HasSuffix(name, ".tar") {
		name = strings.TrimSuffix(name, ".tar")
	}
	outputDir := filepath.Join(dir, name)

	// 使用默认配置解压
	config := defaultExtractConfig()
	_, err := extractWithSmartPasswordTries(archivePath, outputDir, config)
	if err != nil {
		return "", err
	}

	return outputDir, nil
}

// isSupportedInternal 检查文件是否支持解压 (内部函数)
func isSupportedInternal(archivePath string) (bool, string) {
	detector := NewFormatDetector()
	format, err := detector.DetectFormat(archivePath)
	if err != nil || format == FormatUnknown {
		return false, ""
	}
	return true, string(format)
}
