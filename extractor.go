package unzip

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// recursiveExtractorImpl 递归解压器的默认实现
type recursiveExtractorImpl struct {
	validator       SecurityValidator
	detector        FormatDetector
	encodingHandler EncodingHandler
	archiveUtils    ArchiveUtils
	formatManager   FormatExtractorManager
}

// newRecursiveExtractor 创建新的递归解压器
func newRecursiveExtractor() recursiveExtractor {
	return &recursiveExtractorImpl{
		validator:       NewSecurityValidator(),
		detector:        NewFormatDetector(),
		encodingHandler: NewEncodingHandler(),
		archiveUtils:    NewArchiveUtils(),
		formatManager:   NewFormatExtractorManager(),
	}
}

// newRecursiveExtractorWithDeps 创建带依赖的递归解压器
func newRecursiveExtractorWithDeps(
	validator SecurityValidator,
	detector FormatDetector,
	encodingHandler EncodingHandler,
	archiveUtils ArchiveUtils,
	formatManager FormatExtractorManager,
) recursiveExtractor {
	return &recursiveExtractorImpl{
		validator:       validator,
		detector:        detector,
		encodingHandler: encodingHandler,
		archiveUtils:    archiveUtils,
		formatManager:   formatManager,
	}
}

// extract 解压文件到指定目录
func (e *recursiveExtractorImpl) extract(archivePath, outputDir string) (*recursiveExtractResult, error) {
	return e.extractWithConfig(archivePath, outputDir, defaultExtractConfig())
}

// extractWithConfig 使用配置解压文件
func (e *recursiveExtractorImpl) extractWithConfig(archivePath, outputDir string, config extractConfig) (*recursiveExtractResult, error) {
	// 验证输入参数
	if err := e.validateInputs(archivePath, outputDir, config); err != nil {
		return nil, err
	}

	// 检测文件格式 - 使用detector进行检测
	format, err := e.detector.DetectFormat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInternalError, "无法检测文件格式", archivePath, err)
	}

	if format == FormatUnknown {
		return nil, NewExtractError(ErrUnsupportedFormat, "不支持的文件格式", archivePath, nil)
	}

	// 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建输出目录", outputDir, err)
	}

	// 根据格式选择解压器并执行解压
	result, err := e.extractByFormat(format, archivePath, outputDir, config, 0)
	if err != nil {
		return nil, err
	}

	// 设置源压缩包信息
	for i := range result.Files {
		if result.Files[i].SourceArchive == "" {
			result.Files[i].SourceArchive = archivePath
		}
	}

	// 🗑️ 如果启用了清理选项，删除递归解压过程中的中间压缩包
	if config.CleanNested {
		cleanedCount := e.cleanupNestedArchives(outputDir)
		result.CleanedCount = cleanedCount
	}

	return result, nil
}

// cleanupNestedArchives 清理输出目录中的中间压缩包文件
func (e *recursiveExtractorImpl) cleanupNestedArchives(outputDir string) int {
	cleanedCount := 0
	
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			switch ext {
			case ".zip", ".rar", ".7z", ".tar":
				if err := os.Remove(path); err == nil {
					cleanedCount++
				}
			case ".gz", ".bz2":
				if strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".tar"+ext) {
					if err := os.Remove(path); err == nil {
						cleanedCount++
					}
				}
			}
		}
		
		return nil
	})
	
	if err != nil {
		// 清理过程中的错误不应该影响主要功能
		// 可以考虑添加到警告中，但这里为了简化就忽略
	}
	
	return cleanedCount
}

// getSupportedFormats 获取支持的格式列表
func (e *recursiveExtractorImpl) getSupportedFormats() []string {
	supportedFormats := e.formatManager.GetSupportedFormats()
	formats := make([]string, len(supportedFormats))
	for i, format := range supportedFormats {
		formats[i] = string(format)
	}
	return formats
}

// validateArchive 验证压缩包是否有效
func (e *recursiveExtractorImpl) validateArchive(archivePath string) error {
	// 检查文件是否存在
	if _, err := os.Stat(archivePath); err != nil {
		return NewExtractError(ErrInvalidPath, "文件不存在", archivePath, err)
	}

	// 使用detector检测文件格式
	format, err := e.detector.DetectFormat(archivePath)
	if err != nil {
		return NewExtractError(ErrInternalError, "无法检测文件格式", archivePath, err)
	}

	if format == FormatUnknown {
		return NewExtractError(ErrUnsupportedFormat, "不支持的文件格式", archivePath, nil)
	}

	// 使用格式管理器验证文件
	return e.formatManager.ValidateArchiveByFormat(format, archivePath)
}

// validateInputs 验证输入参数
func (e *recursiveExtractorImpl) validateInputs(archivePath, outputDir string, config extractConfig) error {
	// 验证压缩包路径
	if archivePath == "" {
		return NewExtractError(ErrInvalidPath, "压缩包路径不能为空", "", nil)
	}

	// 验证输出目录
	if outputDir == "" {
		return NewExtractError(ErrInvalidPath, "输出目录不能为空", "", nil)
	}

	// 验证压缩包是否存在
	if _, err := os.Stat(archivePath); err != nil {
		return NewExtractError(ErrInvalidPath, "压缩包文件不存在", archivePath, err)
	}

	// 验证配置
	if err := ValidateExtractConfig(config); err != nil {
		return err
	}

	return nil
}

// extractByFormat 根据格式选择解压器
func (e *recursiveExtractorImpl) extractByFormat(format ArchiveFormat, archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error) {
	// 检查递归深度
	if err := e.validator.ValidateDepth(depth, config.MaxDepth); err != nil {
		return nil, err
	}

	// 使用格式管理器进行解压
	return e.formatManager.ExtractByFormat(format, archivePath, outputDir, config, depth)
}

// processNestedArchives 处理嵌套压缩包
func (e *recursiveExtractorImpl) processNestedArchives(result *recursiveExtractResult, baseOutputDir string, config extractConfig, currentDepth int) error {
	// 查找嵌套的压缩包 - 使用detector进行检测
	var nestedArchives []string
	for _, file := range result.Files {
		if !file.IsDir {
			// 使用detector检测是否为压缩文件
			if format, err := e.detector.DetectFormat(file.Path); err == nil && format != FormatUnknown {
				nestedArchives = append(nestedArchives, file.Path)
			}
		}
	}

	// 递归解压嵌套压缩包
	for _, nestedPath := range nestedArchives {
		// 使用detector检测嵌套文件格式
		format, err := e.detector.DetectFormat(nestedPath)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("无法检测嵌套文件格式: %s, 错误: %v", nestedPath, err))
			continue
		}

		if format == FormatUnknown {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("不支持的嵌套文件格式: %s", nestedPath))
			continue
		}

		// 创建嵌套解压目录
		nestedDir := e.createNestedDir(nestedPath)
		if err := e.archiveUtils.EnsureDirectoryExists(nestedDir); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("无法创建嵌套解压目录: %s, 错误: %v", nestedDir, err))
			continue
		}

		// 递归解压
		nestedConfig := config
		nestedConfig.MaxDepth = config.MaxDepth - currentDepth - 1

		nestedResult, err := e.extractByFormat(format, nestedPath, nestedDir, nestedConfig, currentDepth+1)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("嵌套压缩包解压失败: %s, 错误: %v", nestedPath, err))
			continue
		}

		// 合并结果
		result.Files = append(result.Files, nestedResult.Files...)
		result.Warnings = append(result.Warnings, nestedResult.Warnings...)
		result.NestedArchives = append(result.NestedArchives, nestedResult.NestedArchives...)
		result.TotalFiles += nestedResult.TotalFiles
		result.TotalSize += nestedResult.TotalSize

		if nestedResult.MaxDepthUsed > result.MaxDepthUsed {
			result.MaxDepthUsed = nestedResult.MaxDepthUsed
		}

		// 记录嵌套压缩包信息
		nestedInfo := nestedArchiveInfo{
			Path:           nestedPath,
			Format:         string(format),
			Depth:          currentDepth + 1,
			Size:           0, // 需要从文件信息中获取
			ExtractedFiles: nestedResult.TotalFiles,
			HasPassword:    false, // 需要根据实际情况判断
		}

		// 获取文件大小
		if stat, err := os.Stat(nestedPath); err == nil {
			nestedInfo.Size = stat.Size()
		}

		result.NestedArchives = append(result.NestedArchives, nestedInfo)
	}

	return nil
}

// createNestedDir 创建嵌套解压目录名
func (e *recursiveExtractorImpl) createNestedDir(archivePath string) string {
	dir := filepath.Dir(archivePath)
	base := filepath.Base(archivePath)

	// 移除扩展名
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	// 处理复合扩展名（如.tar.gz）
	if strings.HasSuffix(name, ".tar") {
		name = strings.TrimSuffix(name, ".tar")
	}

	return filepath.Join(dir, name+"_extracted")
}




// extractSingleZipFile 解压单个ZIP文件
func (e *recursiveExtractorImpl) extractSingleZipFile(file *zip.File, fileName, outputDir string, config extractConfig) (*extractedFile, error) {
	// 验证路径安全性
	if err := e.validator.ValidatePath(fileName, outputDir); err != nil {
		return nil, err
	}

	// 构建目标路径
	targetPath, err := PathSafeJoin(outputDir, fileName)
	if err != nil {
		return nil, err
	}

	// 创建extractedFile信息
	extractedFile := &extractedFile{
		Path:          targetPath,
		Size:          int64(file.UncompressedSize64),
		ModTime:       file.Modified,
		IsDir:         file.FileInfo().IsDir(),
		SourceArchive: "", // 将在上层设置
		Depth:         0,
	}

	// 处理目录
	if extractedFile.IsDir {
		if err := e.archiveUtils.EnsureDirectoryExists(targetPath); err != nil {
			return nil, NewExtractError(ErrPermissionDenied, "无法创建目录", targetPath, err)
		}
		return extractedFile, nil
	}

	// 检查文件是否已存在
	if !config.OverwriteExisting {
		if _, err := os.Stat(targetPath); err == nil {
			return nil, NewExtractError(ErrPermissionDenied, "文件已存在且不允许覆盖", targetPath, nil)
		}
	}

	// 创建父目录
	parentDir := filepath.Dir(targetPath)
	if err := e.archiveUtils.EnsureDirectoryExists(parentDir); err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建父目录", parentDir, err)
	}

	// 打开ZIP文件中的文件
	src, err := file.Open()
	if err != nil {
		// 使用ZIP解压器处理错误
		extractorInterface, extractorErr := e.formatManager.GetExtractorForFormat(FormatZIP)
		if extractorErr != nil {
			return nil, NewExtractError(ErrInternalError, "无法获取ZIP解压器", file.Name, extractorErr)
		}
		zipExtractor := extractorInterface.(zipExtractor)
		return nil, zipExtractor.(*defaultZipExtractor).handleZipError(err, file.Name)
	}
	defer src.Close()

	// 创建目标文件
	dst, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
	if err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建目标文件", targetPath, err)
	}
	defer dst.Close()

	// 复制文件内容
	_, err = io.Copy(dst, src)
	if err != nil {
		return nil, NewExtractError(ErrInternalError, "文件复制失败", targetPath, err)
	}

	// 设置文件时间
	if err := os.Chtimes(targetPath, file.Modified, file.Modified); err != nil {
		// 时间设置失败不是致命错误，只记录警告
		// 这里可以添加到警告列表中
	}

	return extractedFile, nil
}

// extractNestedArchive 解压嵌套压缩包
func (e *recursiveExtractorImpl) extractNestedArchive(archivePath, baseOutputDir string, config extractConfig, currentDepth int) (*recursiveExtractResult, error) {
	// 检查递归深度
	if err := e.validator.ValidateDepth(currentDepth, config.MaxDepth); err != nil {
		return nil, err
	}

	// 创建嵌套解压目录
	nestedDir := strings.TrimSuffix(archivePath, filepath.Ext(archivePath)) + "_extracted"
	if err := e.archiveUtils.EnsureDirectoryExists(nestedDir); err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建嵌套解压目录", nestedDir, err)
	}

	// 检测嵌套文件格式
	format, err := e.detector.DetectFormat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInternalError, "无法检测嵌套文件格式", archivePath, err)
	}

	// 使用格式管理器进行解压
	nestedConfig := config
	nestedConfig.MaxDepth = config.MaxDepth - currentDepth

	// 通过格式管理器解压
	result, err := e.formatManager.ExtractByFormat(format, archivePath, nestedDir, nestedConfig, currentDepth+1)
	if err != nil {
		return nil, err
	}

	// 更新深度信息
	for i := range result.Files {
		result.Files[i].Depth = currentDepth
	}

	for i := range result.NestedArchives {
		result.NestedArchives[i].Depth = currentDepth
	}

	return result, nil
}
