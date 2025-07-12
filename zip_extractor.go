package unzip

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	
	encryptedzip "github.com/yeka/zip"
)

// zipExtractor ZIP格式解压器接口
type zipExtractor interface {
	// Extract 解压ZIP文件
	Extract(archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error)

	// ValidateArchive 验证ZIP文件
	ValidateArchive(archivePath string) error

	// GetArchiveInfo 获取ZIP文件信息
	GetArchiveInfo(archivePath string) (*zipArchiveInfo, error)

	// ExtractSingleFile 解压单个文件
	ExtractSingleFile(file *zip.File, fileName, outputDir string, config extractConfig) (*extractedFile, error)
}

// defaultZipExtractor 默认ZIP解压器实现
type defaultZipExtractor struct {
	validator         SecurityValidator
	encodingHandler   EncodingHandler
	filenameSanitizer *FilenameSanitizer
}

// newZipExtractor 创建新的ZIP解压器
func newZipExtractor() zipExtractor {
	return &defaultZipExtractor{
		validator:         NewSecurityValidator(),
		encodingHandler:   NewEncodingHandler(),
		filenameSanitizer: NewFilenameSanitizer(),
	}
}

// newZipExtractorWithDeps 创建带依赖的ZIP解压器
func newZipExtractorWithDeps(validator SecurityValidator, encodingHandler EncodingHandler) zipExtractor {
	return &defaultZipExtractor{
		validator:         validator,
		encodingHandler:   encodingHandler,
		filenameSanitizer: NewFilenameSanitizer(),
	}
}

// Extract 解压ZIP文件
func (e *defaultZipExtractor) Extract(archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error) {
	// 调试信息：确认Extract方法被调用
	// fmt.Printf("🔍 [DEBUG] ZIP Extract方法被调用: %s\n", archivePath)
	// fmt.Printf("🔍 [DEBUG] 配置密码: %s, 密码列表: %v\n", config.Password, config.Passwords)
	
	// 验证配置
	if err := ValidateExtractConfig(config); err != nil {
		return nil, err
	}

	// 验证文件格式
	if err := e.ValidateArchive(archivePath); err != nil {
		return nil, err
	}

	// 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建输出目录", outputDir, err)
	}

	// 开始解压
	startTime := time.Now()
	result := &recursiveExtractResult{
		Files:          make([]extractedFile, 0),
		Warnings:       make([]string, 0),
		NestedArchives: make([]nestedArchiveInfo, 0),
	}

	// 尝试使用密码解压
	err := e.extractWithPasswords(archivePath, outputDir, config, result)
	if err != nil {
		return nil, err
	}

	// 完善结果信息
	result.TotalFiles = len(result.Files)
	result.ProcessTime = time.Since(startTime)
	if result.MaxDepthUsed < depth {
		result.MaxDepthUsed = depth
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

// extractWithPasswords 尝试使用密码列表解压ZIP文件
func (e *defaultZipExtractor) extractWithPasswords(archivePath, outputDir string, config extractConfig, result *recursiveExtractResult) error {
	// 准备密码列表（使用集中的密码管理器）
	passwordManager := GetGlobalPasswordManager()
	userPasswords := config.Passwords
	if config.Password != "" {
		userPasswords = append([]string{config.Password}, userPasswords...)
	}
	passwordList := passwordManager.buildPasswordList(userPasswords, true, true)
	
	result.Warnings = append(result.Warnings, fmt.Sprintf("开始尝试ZIP解压，准备 %d 个密码", len(passwordList)))

	// 尝试每个密码
	for i, password := range passwordList {
		result.Warnings = append(result.Warnings, fmt.Sprintf("尝试密码 %d/%d: %s", i+1, len(passwordList), 
			func(pwd string) string {
				if pwd == "" { return "<无密码>" }
				return "***"
			}(password)))
		
		// 使用当前密码尝试解压
		err := e.tryExtractWithPassword(archivePath, outputDir, password, config, result)
		if err == nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("ZIP解压成功，使用密码: %s", 
				func(pwd string) string {
					if pwd == "" { return "<无密码>" }
					return "***"
				}(password)))
			return nil
		}
		
		// 检查是否是密码错误
		if strings.Contains(err.Error(), "password") || 
		   strings.Contains(err.Error(), "incorrect") ||
		   strings.Contains(err.Error(), "encrypted") ||
		   strings.Contains(err.Error(), "invalid") {
			result.Warnings = append(result.Warnings, fmt.Sprintf("密码错误: %v", err))
			continue
		}
		
		// 其他错误，直接返回
		return err
	}
	
	return NewExtractError(ErrInvalidPassword, fmt.Sprintf("尝试了 %d 个密码都无法解压ZIP文件", len(passwordList)), archivePath, nil)
}

// tryExtractWithPassword 使用指定密码尝试解压ZIP文件
func (e *defaultZipExtractor) tryExtractWithPassword(archivePath, outputDir, password string, config extractConfig, result *recursiveExtractResult) error {
	// 使用yeka/zip库打开加密ZIP文件
	reader, err := encryptedzip.OpenReader(archivePath)
	if err != nil {
		return e.handleZipError(err, archivePath)
	}
	defer reader.Close()

	// 解压文件
	var totalSize int64
	for _, file := range reader.File {
		// 检查文件是否加密，如果是则设置密码
		if file.IsEncrypted() {
			file.SetPassword(password)
		}

		// 智能解码文件名
		fileName, detectedEncoding, err := e.encodingHandler.SmartDecodeFileName(file.Name)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("文件名解码失败: %s (错误: %v)", file.Name, err))
			fileName = file.Name // 使用原始文件名
		} else if detectedEncoding != "UTF-8" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("文件名编码检测: %s -> %s", file.Name, detectedEncoding))
		}

		// 文件名安全化处理
		originalFileName := fileName
		fileName = e.filenameSanitizer.SanitizeFilename(fileName)
		if fileName != originalFileName {
			result.Warnings = append(result.Warnings, fmt.Sprintf("文件名安全化: %s -> %s", originalFileName, fileName))
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("文件名无需安全化: %s", fileName))
		}

		// 跳过隐藏文件（如果配置要求）
		if config.SkipHidden && e.isHiddenFile(fileName) {
			continue
		}

		// 验证文件大小
		if err := e.validator.ValidateFileSize(int64(file.UncompressedSize64), config.MaxFileSize); err != nil {
			return err
		}

		// 验证总大小
		if err := e.validator.ValidateTotalSize(totalSize, int64(file.UncompressedSize64), config.MaxTotalSize); err != nil {
			return err
		}

		// 验证路径安全性
		if err := e.validator.ValidatePath(fileName, outputDir); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("跳过不安全的路径: %s", fileName))
			continue
		}

		// 构建目标路径
		targetPath, err := PathSafeJoin(outputDir, fileName)
		if err != nil {
			return err
		}

		// 处理目录
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, file.FileInfo().Mode()); err != nil {
				return NewExtractError(ErrPermissionDenied, "无法创建目录", targetPath, err)
			}
			
			// 添加到结果
			result.Files = append(result.Files, extractedFile{
				Path:          targetPath,
				Size:          0,
				ModTime:       file.FileInfo().ModTime(),
				IsDir:         true,
				SourceArchive: archivePath,
				Depth:         0,
			})
			continue
		}

		// 处理文件冲突
		finalTargetPath, err := HandleFileConflict(targetPath, config)
		if err != nil {
			return err
		}
		
		// 如果路径被重命名，更新targetPath
		if finalTargetPath != targetPath {
			targetPath = finalTargetPath
			result.Warnings = append(result.Warnings, fmt.Sprintf("文件重命名: %s -> %s", filepath.Base(fileName), filepath.Base(targetPath)))
		}

		// 创建父目录
		parentDir := filepath.Dir(targetPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return NewExtractError(ErrPermissionDenied, "无法创建父目录", parentDir, err)
		}

		// 打开加密文件
		src, err := file.Open()
		if err != nil {
			// 检查是否是密码相关错误
			if strings.Contains(err.Error(), "password") || 
			   strings.Contains(err.Error(), "encrypted") ||
			   strings.Contains(err.Error(), "invalid") ||
			   strings.Contains(err.Error(), "wrong password") ||
			   strings.Contains(err.Error(), "bad password") {
				return fmt.Errorf("zip: invalid password or encrypted file")
			}
			return NewExtractError(ErrInternalError, "无法打开ZIP文件", targetPath, err)
		}
		defer src.Close()

		// 创建目标文件
		dst, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			src.Close()
			return NewExtractError(ErrPermissionDenied, "无法创建目标文件", targetPath, err)
		}

		// 添加文件清理机制：如果复制失败，删除已创建的文件
		var copySuccess bool
		defer func(path string) {
			dst.Close()
			if !copySuccess {
				os.Remove(path)
			}
		}(targetPath)

		// 复制文件内容
		copied, err := io.Copy(dst, src)
		src.Close()
		
		if err != nil {
			// 检查是否是密码相关错误
			if strings.Contains(err.Error(), "password") || 
			   strings.Contains(err.Error(), "encrypted") ||
			   strings.Contains(err.Error(), "invalid") ||
			   strings.Contains(err.Error(), "wrong password") ||
			   strings.Contains(err.Error(), "bad password") {
				return fmt.Errorf("zip: invalid password or encrypted file")
			}
			return NewExtractError(ErrInternalError, fmt.Sprintf("文件复制失败 (详细信息: %v)", err), targetPath, err)
		}
		copySuccess = true

		// 设置文件时间
		if err := os.Chtimes(targetPath, file.FileInfo().ModTime(), file.FileInfo().ModTime()); err != nil {
			// 时间设置失败不是致命错误
		}

		// 添加到结果
		result.Files = append(result.Files, extractedFile{
			Path:          targetPath,
			Size:          copied,
			ModTime:       file.FileInfo().ModTime(),
			IsDir:         false,
			SourceArchive: archivePath,
			Depth:         0,
		})
		
		totalSize += copied
	}

	result.TotalSize = totalSize
	return nil
}

// ValidateArchive 验证ZIP文件
func (e *defaultZipExtractor) ValidateArchive(archivePath string) error {
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

	if format != FormatZIP {
		return NewExtractError(ErrUnsupportedFormat, "不是ZIP格式文件", archivePath, nil)
	}

	// 尝试打开ZIP文件
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return e.handleZipError(err, archivePath)
	}
	defer reader.Close()

	return nil
}

// GetArchiveInfo 获取ZIP文件信息
func (e *defaultZipExtractor) GetArchiveInfo(archivePath string) (*zipArchiveInfo, error) {
	// 验证文件
	if err := e.ValidateArchive(archivePath); err != nil {
		return nil, err
	}

	// 获取文件统计信息
	stat, err := os.Stat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInvalidPath, "无法获取文件信息", archivePath, err)
	}

	// 打开ZIP文件获取详细信息
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, e.handleZipError(err, archivePath)
	}
	defer reader.Close()

	info := &zipArchiveInfo{
		Path:        archivePath,
		Size:        stat.Size(),
		ModTime:     stat.ModTime(),
		FileCount:   len(reader.File),
		HasPassword: false, // 需要检测
		Comment:     reader.Comment,
	}

	// 检查是否有加密文件
	for _, file := range reader.File {
		// 检查文件头标志位来判断是否加密
		if file.Flags&0x1 != 0 {
			info.HasPassword = true
			break
		}
	}

	return info, nil
}

// ExtractSingleFile 解压单个ZIP文件
func (e *defaultZipExtractor) ExtractSingleFile(file *zip.File, fileName, outputDir string, config extractConfig) (*extractedFile, error) {
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
		if err := os.MkdirAll(targetPath, file.FileInfo().Mode()); err != nil {
			return nil, NewExtractError(ErrPermissionDenied, "无法创建目录", targetPath, err)
		}
		return extractedFile, nil
	}

	// 处理文件冲突
	finalTargetPath, err := HandleFileConflict(targetPath, config)
	if err != nil {
		return nil, err
	}
	
	// 如果路径被重命名，更新相关信息
	if finalTargetPath != targetPath {
		targetPath = finalTargetPath
		extractedFile.Path = targetPath
	}

	// 创建父目录
	parentDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建父目录", parentDir, err)
	}

	// 打开ZIP文件中的文件
	src, err := e.openZipFileWithPassword(file, config)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	// 创建目标文件
	dst, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
	if err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建目标文件", targetPath, err)
	}
	defer dst.Close()

	// 添加文件清理机制：如果复制失败，删除已创建的文件
	var copySuccess bool
	defer func() {
		if !copySuccess {
			os.Remove(targetPath)
		}
	}()

	// 复制文件内容
	_, err = io.Copy(dst, src)
	if err != nil {
		return nil, NewExtractError(ErrInternalError, "文件复制失败", targetPath, err)
	}
	copySuccess = true

	// 设置文件时间
	if err := os.Chtimes(targetPath, file.Modified, file.Modified); err != nil {
		// 时间设置失败不是致命错误，只记录警告
		// 这里可以添加到警告列表中
	}

	return extractedFile, nil
}

// ExtractSingleEncryptedFile 解压单个加密ZIP文件
func (e *defaultZipExtractor) ExtractSingleEncryptedFile(file *encryptedzip.File, fileName, outputDir string, config extractConfig, password string) (*extractedFile, error) {
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
		ModTime:       file.FileInfo().ModTime(),
		IsDir:         file.FileInfo().IsDir(),
		SourceArchive: "", // 将在上层设置
		Depth:         0,
	}

	// 处理目录
	if extractedFile.IsDir {
		if err := os.MkdirAll(targetPath, file.FileInfo().Mode()); err != nil {
			return nil, NewExtractError(ErrPermissionDenied, "无法创建目录", targetPath, err)
		}
		return extractedFile, nil
	}

	// 处理文件冲突
	finalTargetPath, err := HandleFileConflict(targetPath, config)
	if err != nil {
		return nil, err
	}
	
	// 如果路径被重命名，更新相关信息
	if finalTargetPath != targetPath {
		targetPath = finalTargetPath
		extractedFile.Path = targetPath
	}

	// 创建父目录
	parentDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建父目录", parentDir, err)
	}

	// 设置密码并打开加密文件
	if file.IsEncrypted() {
		file.SetPassword(password)
	}
	
	src, err := file.Open()
	if err != nil {
		// 检查是否是密码相关错误
		if strings.Contains(err.Error(), "password") || 
		   strings.Contains(err.Error(), "encrypted") ||
		   strings.Contains(err.Error(), "invalid") {
			return nil, fmt.Errorf("zip: invalid password or encrypted file")
		}
		return nil, NewExtractError(ErrInternalError, "无法打开ZIP文件", targetPath, err)
	}
	defer src.Close()

	// 创建目标文件
	dst, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
	if err != nil {
		return nil, NewExtractError(ErrPermissionDenied, "无法创建目标文件", targetPath, err)
	}

	// 添加文件清理机制：如果复制失败，删除已创建的文件
	var copySuccess bool
	defer func(path string) {
		dst.Close()
		if !copySuccess {
			os.Remove(path)
		}
	}(targetPath)

	// 复制文件内容
	_, err = io.Copy(dst, src)
	if err != nil {
		// 检查是否是密码相关错误
		if strings.Contains(err.Error(), "password") || 
		   strings.Contains(err.Error(), "encrypted") ||
		   strings.Contains(err.Error(), "invalid") {
			return nil, fmt.Errorf("zip: invalid password or encrypted file")
		}
		return nil, NewExtractError(ErrInternalError, "文件复制失败", targetPath, err)
	}
	copySuccess = true

	// 设置文件时间
	if err := os.Chtimes(targetPath, file.FileInfo().ModTime(), file.FileInfo().ModTime()); err != nil {
		// 时间设置失败不是致命错误
	}

	return extractedFile, nil
}

// isHiddenFile 检查是否为隐藏文件
func (e *defaultZipExtractor) isHiddenFile(fileName string) bool {
	baseName := filepath.Base(fileName)
	return strings.HasPrefix(baseName, ".") || strings.HasPrefix(baseName, "__MACOSX")
}

// handleZipError 处理ZIP相关错误
func (e *defaultZipExtractor) handleZipError(err error, path string) error {
	if err == nil {
		return nil
	}

	errorMsg := err.Error()

	// 检查常见的ZIP错误
	if strings.Contains(errorMsg, "not a valid zip file") {
		return NewExtractError(ErrCorruptedArchive, "不是有效的ZIP文件", path, err)
	}

	if strings.Contains(errorMsg, "password") || strings.Contains(errorMsg, "encrypted") {
		return NewExtractError(ErrPasswordRequired, "ZIP文件需要密码", path, err)
	}

	if strings.Contains(errorMsg, "checksum") {
		return NewExtractError(ErrCorruptedArchive, "ZIP文件校验和错误", path, err)
	}

	if strings.Contains(errorMsg, "permission denied") {
		return NewExtractError(ErrPermissionDenied, "权限不足", path, err)
	}

	if strings.Contains(errorMsg, "no space left") {
		return NewExtractError(ErrDiskFull, "磁盘空间不足", path, err)
	}

	// 默认内部错误
	return NewExtractError(ErrInternalError, "ZIP解压失败", path, err)
}

// openZipFileWithPassword 使用密码打开ZIP文件
func (e *defaultZipExtractor) openZipFileWithPassword(file *zip.File, config extractConfig) (io.ReadCloser, error) {
	// 检查文件是否加密
	if file.Flags&0x1 == 0 {
		// 文件未加密，直接打开
		return file.Open()
	}

	// 文件加密，需要密码
	// 首先尝试配置中的密码
	passwords := e.buildPasswordList(config)

	var lastErr error
	for _, password := range passwords {
		// 尝试使用密码打开文件
		if password == "" {
			// 空密码，直接尝试打开
			reader, err := file.Open()
			if err == nil {
				return reader, nil
			}
			lastErr = err
			continue
		}

		// 使用密码打开（注意：标准库不直接支持密码，这里是示例框架）
		// 实际实现可能需要使用第三方库如 github.com/alexmullins/zip
		reader, err := e.openWithPassword(file, password)
		if err == nil {
			return reader, nil
		}
		lastErr = err
	}

	// 所有密码都失败了
	return nil, e.handleZipError(lastErr, file.Name)
}

// buildPasswordList 构建密码尝试列表
func (e *defaultZipExtractor) buildPasswordList(config extractConfig) []string {
	var passwords []string

	// 添加用户指定的密码
	if config.Password != "" {
		passwords = append(passwords, config.Password)
	}

	// 添加密码列表
	passwords = append(passwords, config.Passwords...)

	// 添加内置密码（使用统一的密码管理器）
	passwordManager := GetGlobalPasswordManager()
	passwords = append(passwords, passwordManager.getBuiltinPasswords()...)

	// 去重
	return RemoveDuplicateStrings(passwords)
}

// openWithPassword 使用密码打开ZIP文件（示例实现）
func (e *defaultZipExtractor) openWithPassword(file *zip.File, password string) (io.ReadCloser, error) {
	// 注意：Go标准库的archive/zip不直接支持密码保护的ZIP文件
	// 这里提供一个框架，实际实现需要使用第三方库

	// 示例：如果使用 github.com/alexmullins/zip 库
	// file.SetPassword(password)
	// return file.Open()

	// 当前实现：直接尝试打开，让上层处理密码错误
	reader, err := file.Open()
	if err != nil {
		// 如果是密码错误，包装为密码相关错误
		if strings.Contains(err.Error(), "zip: unsupported encryption") ||
			strings.Contains(err.Error(), "zip: invalid password") {
			return nil, NewExtractError(ErrPasswordRequired, "ZIP文件需要密码或密码错误", file.Name, err)
		}
	}

	return reader, err
}

// zipArchiveInfo ZIP文件信息
type zipArchiveInfo struct {
	Path        string
	Size        int64
	ModTime     time.Time
	FileCount   int
	HasPassword bool
	Comment     string
}

// processNestedArchives 处理ZIP解压后的嵌套压缩包
func (e *defaultZipExtractor) processNestedArchives(result *recursiveExtractResult, baseOutputDir string, config extractConfig, currentDepth int) error {
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
func (e *defaultZipExtractor) isArchiveFile(filePath string) bool {
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
func (e *defaultZipExtractor) extractNestedArchive(nestedPath, baseOutputDir string, config extractConfig, depth int, parentResult *recursiveExtractResult) error {
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
func (e *defaultZipExtractor) mergeResults(parentResult, nestedResult *recursiveExtractResult, nestedPath string, depth int) {
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
