package unzip

import (
	"archive/tar"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// tarExtractor TAR格式解压器接口
type tarExtractor interface {
	// Extract 解压TAR文件
	Extract(archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error)

	// ValidateArchive 验证TAR文件
	ValidateArchive(archivePath string) error

	// GetArchiveInfo 获取TAR文件信息
	GetArchiveInfo(archivePath string) (*tarArchiveInfo, error)

	// ListFiles 列出TAR文件中的文件
	ListFiles(archivePath string) ([]string, error)

	// ExtractFile 解压单个文件
	ExtractFile(archivePath, fileName, outputPath string) error
}

// defaultTarExtractor 默认TAR解压器实现
type defaultTarExtractor struct {
	validator       SecurityValidator
	encodingHandler EncodingHandler
	archiveUtils    ArchiveUtils
}

// newTarExtractor 创建新的TAR解压器
func newTarExtractor() tarExtractor {
	return &defaultTarExtractor{
		validator:       NewSecurityValidator(),
		encodingHandler: NewEncodingHandler(),
		archiveUtils:    NewArchiveUtils(),
	}
}

// newTarExtractorWithDeps 创建带依赖的TAR解压器
func newTarExtractorWithDeps(validator SecurityValidator, encodingHandler EncodingHandler, archiveUtils ArchiveUtils) tarExtractor {
	return &defaultTarExtractor{
		validator:       validator,
		encodingHandler: encodingHandler,
		archiveUtils:    archiveUtils,
	}
}

// Extract 解压TAR文件
func (e *defaultTarExtractor) Extract(archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error) {
	// 验证配置
	if err := ValidateExtractConfig(config); err != nil {
		return nil, err
	}

	// 验证文件格式
	if err := e.ValidateArchive(archivePath); err != nil {
		return nil, err
	}

	// 创建输出目录
	if err := e.archiveUtils.EnsureDirectoryExists(outputDir); err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建输出目录", outputDir, err)
	}

	// 检测压缩格式
	detector := NewFormatDetector()
	format, err := detector.DetectFormat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInternalError, "无法检测文件格式", archivePath, err)
	}

	// 开始解压
	startTime := time.Now()
	result := &recursiveExtractResult{
		Files:          make([]extractedFile, 0),
		Warnings:       make([]string, 0),
		NestedArchives: make([]nestedArchiveInfo, 0),
	}

	// 根据格式选择解压方法
	switch format {
	case FormatTAR:
		err = e.extractTar(archivePath, outputDir, config, result)
	case FormatTARGZ:
		err = e.extractTarGz(archivePath, outputDir, config, result)
	case FormatTARBZ2:
		err = e.extractTarBz2(archivePath, outputDir, config, result)
	default:
		return nil, NewExtractError(ErrUnsupportedFormat, "不支持的TAR格式", archivePath, nil)
	}

	if err != nil {
		return nil, err
	}

	// 完善结果信息
	result.TotalFiles = len(result.Files)
	result.ProcessTime = time.Since(startTime)
	if result.MaxDepthUsed < depth {
		result.MaxDepthUsed = depth
	}

	// 计算总大小
	for _, file := range result.Files {
		result.TotalSize += file.Size
	}

	// 🔥 关键修复：添加递归解压处理
	if depth < config.MaxDepth {
		err := e.processNestedArchives(result, outputDir, config, depth)
		if err != nil {
			// 递归处理失败，记录警告而不是返回错误
			result.Warnings = append(result.Warnings, fmt.Sprintf("递归处理失败: %v", err))
		}
	}

	return result, nil
}

// ValidateArchive 验证TAR文件
func (e *defaultTarExtractor) ValidateArchive(archivePath string) error {
	// 检查文件是否存在
	if _, err := os.Stat(archivePath); err != nil {
		return NewExtractError(ErrInvalidPath, "文件不存在", archivePath, err)
	}

	// 检查文件格式
	detector := NewFormatDetector()
	format, err := detector.DetectFormat(archivePath)
	if err != nil {
		return NewExtractError(ErrInternalError, "无法检测文件格式", archivePath, err)
	}

	// 检查是否为TAR系列格式
	if format != FormatTAR && format != FormatTARGZ && format != FormatTARBZ2 {
		return NewExtractError(ErrUnsupportedFormat, "不是TAR格式文件", archivePath, nil)
	}

	// 尝试打开文件进行基本验证
	file, err := os.Open(archivePath)
	if err != nil {
		return NewExtractError(ErrInvalidPath, "无法打开文件", archivePath, err)
	}
	defer file.Close()

	// 根据格式创建对应的reader进行验证
	reader, err := e.createTarReader(file, format)
	if err != nil {
		return NewExtractError(ErrCorruptedArchive, "无法创建TAR读取器", archivePath, err)
	}

	// 尝试读取第一个条目进行验证
	_, err = reader.Next()
	if err != nil && err != io.EOF {
		return NewExtractError(ErrCorruptedArchive, "TAR文件格式错误", archivePath, err)
	}

	return nil
}

// GetArchiveInfo 获取TAR文件信息
func (e *defaultTarExtractor) GetArchiveInfo(archivePath string) (*tarArchiveInfo, error) {
	// 验证文件
	if err := e.ValidateArchive(archivePath); err != nil {
		return nil, err
	}

	// 获取文件统计信息
	stat, err := os.Stat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInvalidPath, "无法获取文件信息", archivePath, err)
	}

	// 检测格式
	detector := NewFormatDetector()
	format, err := detector.DetectFormat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInternalError, "无法检测文件格式", archivePath, err)
	}

	info := &tarArchiveInfo{
		Path:           archivePath,
		Size:           stat.Size(),
		ModTime:        stat.ModTime(),
		Format:         format,
		FileCount:      0,
		DirectoryCount: 0,
		TotalSize:      0,
		HasLongNames:   false,
		HasSymlinks:    false,
	}

	// 扫描文件内容获取详细信息
	if err := e.scanTarContent(archivePath, format, info); err != nil {
		// 如果扫描失败，只返回基本信息
		// 不作为错误处理
	}

	return info, nil
}

// ListFiles 列出TAR文件中的文件
func (e *defaultTarExtractor) ListFiles(archivePath string) ([]string, error) {
	// 验证文件
	if err := e.ValidateArchive(archivePath); err != nil {
		return nil, err
	}

	// 检测格式
	detector := NewFormatDetector()
	format, err := detector.DetectFormat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInternalError, "无法检测文件格式", archivePath, err)
	}

	// 打开文件
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInvalidPath, "无法打开文件", archivePath, err)
	}
	defer file.Close()

	// 创建TAR读取器
	reader, err := e.createTarReader(file, format)
	if err != nil {
		return nil, NewExtractError(ErrCorruptedArchive, "无法创建TAR读取器", archivePath, err)
	}

	var files []string

	// 遍历所有条目
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, NewExtractError(ErrCorruptedArchive, "读取TAR条目失败", archivePath, err)
		}

		files = append(files, header.Name)
	}

	return files, nil
}

// ExtractFile 解压单个文件
func (e *defaultTarExtractor) ExtractFile(archivePath, fileName, outputPath string) error {
	// 验证文件
	if err := e.ValidateArchive(archivePath); err != nil {
		return err
	}

	// 检测格式
	detector := NewFormatDetector()
	format, err := detector.DetectFormat(archivePath)
	if err != nil {
		return NewExtractError(ErrInternalError, "无法检测文件格式", archivePath, err)
	}

	// 打开文件
	file, err := os.Open(archivePath)
	if err != nil {
		return NewExtractError(ErrInvalidPath, "无法打开文件", archivePath, err)
	}
	defer file.Close()

	// 创建TAR读取器
	reader, err := e.createTarReader(file, format)
	if err != nil {
		return NewExtractError(ErrCorruptedArchive, "无法创建TAR读取器", archivePath, err)
	}

	// 查找指定文件
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return NewExtractError(ErrInvalidPath, "文件不存在于TAR中", fileName, nil)
		}
		if err != nil {
			return NewExtractError(ErrCorruptedArchive, "读取TAR条目失败", archivePath, err)
		}

		if header.Name == fileName {
			// 找到文件，开始解压
			return e.extractSingleEntry(header, reader, outputPath)
		}
	}
}

// 私有方法

// extractTar 解压纯TAR文件
func (e *defaultTarExtractor) extractTar(archivePath, outputDir string, config extractConfig, result *recursiveExtractResult) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return NewExtractError(ErrInvalidPath, "无法打开TAR文件", archivePath, err)
	}
	defer file.Close()

	reader := tar.NewReader(file)
	return e.extractFromTarReader(reader, outputDir, config, result, archivePath)
}

// extractTarGz 解压TAR.GZ文件
func (e *defaultTarExtractor) extractTarGz(archivePath, outputDir string, config extractConfig, result *recursiveExtractResult) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return NewExtractError(ErrInvalidPath, "无法打开TAR.GZ文件", archivePath, err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return NewExtractError(ErrCorruptedArchive, "无法创建GZIP读取器", archivePath, err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	return e.extractFromTarReader(tarReader, outputDir, config, result, archivePath)
}

// extractTarBz2 解压TAR.BZ2文件
func (e *defaultTarExtractor) extractTarBz2(archivePath, outputDir string, config extractConfig, result *recursiveExtractResult) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return NewExtractError(ErrInvalidPath, "无法打开TAR.BZ2文件", archivePath, err)
	}
	defer file.Close()

	bz2Reader := bzip2.NewReader(file)
	tarReader := tar.NewReader(bz2Reader)
	return e.extractFromTarReader(tarReader, outputDir, config, result, archivePath)
}

// extractFromTarReader 从TAR读取器解压
func (e *defaultTarExtractor) extractFromTarReader(reader *tar.Reader, outputDir string, config extractConfig, result *recursiveExtractResult, archivePath string) error {
	var totalSize int64

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return NewExtractError(ErrCorruptedArchive, "读取TAR条目失败", archivePath, err)
		}

		// 检查超时
		if config.Timeout > 0 && time.Since(time.Now()) > config.Timeout {
			return NewExtractError(ErrTimeout, "解压操作超时", archivePath, nil)
		}

		// 智能解码文件名
		originalFileName := header.Name
		fileName, detectedEncoding, err := e.encodingHandler.SmartDecodeFileName(originalFileName)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("文件名解码失败: %s (错误: %v)", originalFileName, err))
			fileName = originalFileName // 使用原始文件名
		} else if detectedEncoding != "UTF-8" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("文件名编码检测: %s -> %s", originalFileName, detectedEncoding))
		}

		// 跳过隐藏文件（如果配置要求）
		if config.SkipHidden && e.archiveUtils.IsHiddenFile(fileName) {
			continue
		}

		// 验证文件大小
		if err := e.validator.ValidateFileSize(header.Size, config.MaxFileSize); err != nil {
			return err
		}

		// 验证总大小
		if err := e.validator.ValidateTotalSize(totalSize, header.Size, config.MaxTotalSize); err != nil {
			return err
		}

		// 解压单个条目
		extractedFile, err := e.extractTarEntry(header, reader, fileName, outputDir, config)
		if err != nil {
			return err
		}

		if extractedFile != nil {
			extractedFile.SourceArchive = archivePath
			result.Files = append(result.Files, *extractedFile)
			totalSize += extractedFile.Size
		}
	}

	return nil
}

// extractTarEntry 解压TAR条目
func (e *defaultTarExtractor) extractTarEntry(header *tar.Header, reader *tar.Reader, fileName, outputDir string, config extractConfig) (*extractedFile, error) {
	// 验证路径安全性
	if err := e.validator.ValidatePath(fileName, outputDir); err != nil {
		return nil, err
	}

	// 构建目标路径
	targetPath, err := PathSafeJoin(outputDir, fileName)
	if err != nil {
		return nil, err
	}

	// 根据条目类型处理
	switch header.Typeflag {
	case tar.TypeDir:
		// 目录 - 直接创建，不处理冲突
		if err := e.archiveUtils.EnsureDirectoryExists(targetPath); err != nil {
			return nil, NewExtractError(ErrPermissionDenied, "无法创建目录", targetPath, err)
		}
		
		// 创建extractedFile信息
		extractedFile := &extractedFile{
			Path:          targetPath,
			Size:          header.Size,
			ModTime:       header.ModTime,
			IsDir:         true,
			SourceArchive: "",
			Depth:         0,
		}
		return extractedFile, nil

	case tar.TypeReg:
		// 普通文件 - 在extractRegularFile中处理冲突
		if err := e.extractRegularFile(header, reader, targetPath, config); err != nil {
			return nil, err
		}
		
		// 处理文件冲突获取最终路径（与extractRegularFile保持一致）
		finalTargetPath, err := HandleFileConflict(targetPath, config)
		if err != nil {
			return nil, err
		}
		
		// 创建extractedFile信息
		extractedFile := &extractedFile{
			Path:          finalTargetPath,  // 使用最终路径
			Size:          header.Size,
			ModTime:       header.ModTime,
			IsDir:         false,
			SourceArchive: "",
			Depth:         0,
		}
		return extractedFile, nil

	case tar.TypeSymlink:
		// 符号链接
		if err := e.extractSymlink(header, targetPath); err != nil {
			return nil, err
		}

	case tar.TypeLink:
		// 硬链接
		if err := e.extractHardlink(header, targetPath, outputDir); err != nil {
			return nil, err
		}

	default:
		// 其他类型，记录警告但不失败
		return nil, nil
	}

	// 对于符号链接和硬链接，使用原始路径
	extractedFile := &extractedFile{
		Path:          targetPath,
		Size:          header.Size,
		ModTime:       header.ModTime,
		IsDir:         header.Typeflag == tar.TypeDir,
		SourceArchive: "",
		Depth:         0,
	}

	return extractedFile, nil
}

// extractRegularFile 解压普通文件
func (e *defaultTarExtractor) extractRegularFile(header *tar.Header, reader *tar.Reader, targetPath string, config extractConfig) error {
	// 处理文件冲突（使用统一的冲突处理逻辑）
	finalTargetPath, err := HandleFileConflict(targetPath, config)
	if err != nil {
		return err
	}

	// 创建父目录
	parentDir := filepath.Dir(finalTargetPath)
	if err := e.archiveUtils.EnsureDirectoryExists(parentDir); err != nil {
		return NewExtractError(ErrPermissionDenied, "无法创建父目录", parentDir, err)
	}

	// 创建目标文件
	file, err := os.OpenFile(finalTargetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
	if err != nil {
		return NewExtractError(ErrPermissionDenied, "无法创建目标文件", finalTargetPath, err)
	}
	defer file.Close()

	// 添加文件清理机制：如果复制失败，删除已创建的文件
	var copySuccess bool
	defer func() {
		if !copySuccess {
			os.Remove(finalTargetPath)
		}
	}()

	// 复制文件内容
	_, err = io.Copy(file, reader)
	if err != nil {
		return NewExtractError(ErrInternalError, "文件复制失败", finalTargetPath, err)
	}
	copySuccess = true

	// 设置文件时间
	if err := os.Chtimes(finalTargetPath, header.ModTime, header.ModTime); err != nil {
		// 时间设置失败不是致命错误
	}

	return nil
}

// extractSymlink 解压符号链接
func (e *defaultTarExtractor) extractSymlink(header *tar.Header, targetPath string) error {
	// 创建父目录
	parentDir := filepath.Dir(targetPath)
	if err := e.archiveUtils.EnsureDirectoryExists(parentDir); err != nil {
		return NewExtractError(ErrPermissionDenied, "无法创建父目录", parentDir, err)
	}

	// 创建符号链接
	if err := os.Symlink(header.Linkname, targetPath); err != nil {
		return NewExtractError(ErrPermissionDenied, "无法创建符号链接", targetPath, err)
	}

	return nil
}

// extractHardlink 解压硬链接
func (e *defaultTarExtractor) extractHardlink(header *tar.Header, targetPath, outputDir string) error {
	// 获取链接目标的绝对路径
	linkTarget := filepath.Join(outputDir, header.Linkname)

	// 创建父目录
	parentDir := filepath.Dir(targetPath)
	if err := e.archiveUtils.EnsureDirectoryExists(parentDir); err != nil {
		return NewExtractError(ErrPermissionDenied, "无法创建父目录", parentDir, err)
	}

	// 创建硬链接
	if err := os.Link(linkTarget, targetPath); err != nil {
		return NewExtractError(ErrPermissionDenied, "无法创建硬链接", targetPath, err)
	}

	return nil
}

// extractSingleEntry 解压单个条目（用于ExtractFile）
func (e *defaultTarExtractor) extractSingleEntry(header *tar.Header, reader *tar.Reader, outputPath string) error {
	// 创建父目录
	parentDir := filepath.Dir(outputPath)
	if err := e.archiveUtils.EnsureDirectoryExists(parentDir); err != nil {
		return NewExtractError(ErrPermissionDenied, "无法创建父目录", parentDir, err)
	}

	// 根据条目类型处理
	switch header.Typeflag {
	case tar.TypeReg:
		// 普通文件
		file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return NewExtractError(ErrPermissionDenied, "无法创建目标文件", outputPath, err)
		}
		defer file.Close()

		// 添加文件清理机制：如果复制失败，删除已创建的文件
		var copySuccess bool
		defer func() {
			if !copySuccess {
				os.Remove(outputPath)
			}
		}()

		_, err = io.Copy(file, reader)
		if err != nil {
			return NewExtractError(ErrInternalError, "文件复制失败", outputPath, err)
		}
		copySuccess = true

		// 设置文件时间
		os.Chtimes(outputPath, header.ModTime, header.ModTime)

	case tar.TypeDir:
		// 目录
		if err := os.MkdirAll(outputPath, os.FileMode(header.Mode)); err != nil {
			return NewExtractError(ErrPermissionDenied, "无法创建目录", outputPath, err)
		}

	default:
		return NewExtractError(ErrUnsupportedFormat, "不支持的条目类型", outputPath, nil)
	}

	return nil
}

// createTarReader 创建TAR读取器
func (e *defaultTarExtractor) createTarReader(file *os.File, format ArchiveFormat) (*tar.Reader, error) {
	// 重置文件指针
	file.Seek(0, 0)

	switch format {
	case FormatTAR:
		return tar.NewReader(file), nil

	case FormatTARGZ:
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		return tar.NewReader(gzReader), nil

	case FormatTARBZ2:
		bz2Reader := bzip2.NewReader(file)
		return tar.NewReader(bz2Reader), nil

	default:
		return nil, fmt.Errorf("不支持的格式: %s", format)
	}
}

// scanTarContent 扫描TAR内容获取信息
func (e *defaultTarExtractor) scanTarContent(archivePath string, format ArchiveFormat, info *tarArchiveInfo) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader, err := e.createTarReader(file, format)
	if err != nil {
		return err
	}

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		info.TotalSize += header.Size

		if header.Typeflag == tar.TypeDir {
			info.DirectoryCount++
		} else {
			info.FileCount++
		}

		// 检查长文件名
		if len(header.Name) > 100 {
			info.HasLongNames = true
		}

		// 检查符号链接
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			info.HasSymlinks = true
		}
	}

	return nil
}

// tarArchiveInfo TAR文件信息
type tarArchiveInfo struct {
	Path           string
	Size           int64
	ModTime        time.Time
	Format         ArchiveFormat
	FileCount      int
	DirectoryCount int
	TotalSize      int64
	HasLongNames   bool
	HasSymlinks    bool
}

// processNestedArchives 处理TAR解压后的嵌套压缩包
func (e *defaultTarExtractor) processNestedArchives(result *recursiveExtractResult, baseOutputDir string, config extractConfig, currentDepth int) error {
	// 查找嵌套的压缩包
	var nestedArchives []string
	
	for _, file := range result.Files {
		if !file.IsDir {
			// 检测是否为压缩文件
			if e.isArchiveFile(file.Path) {
				nestedArchives = append(nestedArchives, file.Path)
			}
		}
	}

	if len(nestedArchives) == 0 {
		return nil // 没有嵌套文件
	}

	result.Warnings = append(result.Warnings, 
		fmt.Sprintf("发现 %d 个嵌套压缩包，深度 %d", len(nestedArchives), currentDepth+1))

	// 递归解压嵌套压缩包
	for _, nestedPath := range nestedArchives {
		err := e.extractNestedArchive(nestedPath, baseOutputDir, config, currentDepth+1, result)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("嵌套文件解压失败: %s, 错误: %v", nestedPath, err))
			continue
		}
	}

	return nil
}

// isArchiveFile 检查文件是否为压缩文件
func (e *defaultTarExtractor) isArchiveFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	archiveExtensions := []string{
		".zip", ".rar", ".7z", 
		".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
	}
	
	for _, archiveExt := range archiveExtensions {
		if ext == archiveExt {
			return true
		}
	}
	return false
}

// extractNestedArchive 解压嵌套压缩包
func (e *defaultTarExtractor) extractNestedArchive(nestedPath, baseOutputDir string, config extractConfig, depth int, parentResult *recursiveExtractResult) error {
	// 检查递归深度
	if depth >= config.MaxDepth {
		return fmt.Errorf("达到最大递归深度 %d", config.MaxDepth)
	}

	// 检查文件是否存在
	if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
		return fmt.Errorf("嵌套文件不存在: %s", nestedPath)
	}

	// 创建递归解压器来处理嵌套文件
	recursiveExtractor := newRecursiveExtractor()
	
	// 构造新的配置
	nestedConfig := config
	nestedConfig.MaxDepth = config.MaxDepth // 保持最大深度限制

	// 解压嵌套文件到同一输出目录
	nestedResult, err := recursiveExtractor.extractWithConfig(nestedPath, baseOutputDir, nestedConfig)
	if err != nil {
		return fmt.Errorf("递归解压失败: %v", err)
	}

	// 合并结果
	e.mergeResults(parentResult, nestedResult, nestedPath, depth)

	return nil
}

// mergeResults 合并递归解压结果
func (e *defaultTarExtractor) mergeResults(parentResult, nestedResult *recursiveExtractResult, nestedPath string, depth int) {
	// 合并文件列表
	for _, file := range nestedResult.Files {
		// 更新源压缩包信息
		file.SourceArchive = nestedPath
		file.Depth = depth
		parentResult.Files = append(parentResult.Files, file)
	}

	// 合并警告信息
	for _, warning := range nestedResult.Warnings {
		parentResult.Warnings = append(parentResult.Warnings, 
			fmt.Sprintf("[深度%d] %s", depth, warning))
	}

	// 合并嵌套压缩包信息
	parentResult.NestedArchives = append(parentResult.NestedArchives, nestedArchiveInfo{
		Path:           nestedPath,
		Format:         "auto-detected", // 自动检测的格式
		Depth:          depth,
		Size:           0, // 可以后续完善
		ExtractedFiles: len(nestedResult.Files),
		HasPassword:    false, // 可以后续完善
		PasswordUsed:   "",
	})

	// 更新统计信息
	parentResult.TotalFiles += nestedResult.TotalFiles
	if nestedResult.MaxDepthUsed > parentResult.MaxDepthUsed {
		parentResult.MaxDepthUsed = nestedResult.MaxDepthUsed
	}
}
