package unzip

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nwaples/rardecode/v2"
)

// rarExtractor RAR格式解压器接口
type rarExtractor interface {
	// Extract 解压RAR文件
	Extract(archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error)

	// ValidateArchive 验证RAR文件
	ValidateArchive(archivePath string) error

	// GetArchiveInfo 获取RAR文件信息
	GetArchiveInfo(archivePath string) (*rarArchiveInfo, error)

	// IsPasswordProtected 检查是否需要密码
	IsPasswordProtected(archivePath string) (bool, error)
}

// defaultRarExtractor 默认RAR解压器实现
type defaultRarExtractor struct {
	validator       SecurityValidator
	encodingHandler EncodingHandler
}

// newRarExtractor 创建新的RAR解压器
func newRarExtractor() rarExtractor {
	return &defaultRarExtractor{
		validator:       NewSecurityValidator(),
		encodingHandler: NewEncodingHandler(),
	}
}

// newRarExtractorWithDeps 创建带依赖的RAR解压器
func newRarExtractorWithDeps(validator SecurityValidator, encodingHandler EncodingHandler) rarExtractor {
	return &defaultRarExtractor{
		validator:       validator,
		encodingHandler: encodingHandler,
	}
}

// Extract 解压RAR文件
func (e *defaultRarExtractor) Extract(archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error) {
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

	// RAR解压使用rardecode库
	err := e.extractWithRarDecode(archivePath, outputDir, config, result)
	if err != nil {
		return nil, err
	}

	// 完善结果信息
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

// ValidateArchive 验证RAR文件
func (e *defaultRarExtractor) ValidateArchive(archivePath string) error {
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

	if format != FormatRAR {
		return NewExtractError(ErrUnsupportedFormat, "不是RAR格式文件", archivePath, nil)
	}

	// 检查RAR文件头
	if err := e.validateRarHeader(archivePath); err != nil {
		return err
	}

	return nil
}

// GetArchiveInfo 获取RAR文件信息
func (e *defaultRarExtractor) GetArchiveInfo(archivePath string) (*rarArchiveInfo, error) {
	// 验证文件
	if err := e.ValidateArchive(archivePath); err != nil {
		return nil, err
	}

	// 获取文件统计信息
	stat, err := os.Stat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInvalidPath, "无法获取文件信息", archivePath, err)
	}

	info := &rarArchiveInfo{
		Path:        archivePath,
		Size:        stat.Size(),
		ModTime:     stat.ModTime(),
		FileCount:   0, // 需要通过解析RAR文件获取
		HasPassword: false,
		Version:     "",
	}

	// 检查是否需要密码
	hasPassword, err := e.IsPasswordProtected(archivePath)
	if err == nil {
		info.HasPassword = hasPassword
	}

	// 获取更多详细信息（需要实际的RAR解析库）
	if err := e.fillRarInfo(archivePath, info); err != nil {
		// 如果获取详细信息失败，只返回基本信息
		// 不作为错误处理
	}

	return info, nil
}

// IsPasswordProtected 检查RAR文件是否需要密码
func (e *defaultRarExtractor) IsPasswordProtected(archivePath string) (bool, error) {
	// 这里需要实际的RAR文件解析
	// 可以通过读取RAR文件头来判断
	// 或者使用外部工具进行检测

	// 简单的实现：尝试列出文件内容
	// 如果需要密码，通常会返回特定的错误

	// 注意：这是一个示例实现，实际需要根据使用的RAR库来实现
	return false, nil
}

// extractWithRarDecode 使用rardecode库解压RAR文件
func (e *defaultRarExtractor) extractWithRarDecode(archivePath, outputDir string, config extractConfig, result *recursiveExtractResult) error {
	// 准备密码列表（使用集中的密码管理器）
	passwordManager := GetGlobalPasswordManager()
	userPasswords := config.Passwords
	if config.Password != "" {
		userPasswords = append([]string{config.Password}, userPasswords...)
	}
	passwordList := passwordManager.buildPasswordList(userPasswords, true, true)
	
	result.Warnings = append(result.Warnings, fmt.Sprintf("开始尝试RAR解压，准备 %d 个密码", len(passwordList)))

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
			result.Warnings = append(result.Warnings, fmt.Sprintf("RAR解压成功，使用密码: %s", 
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
		   strings.Contains(err.Error(), "required") {
			result.Warnings = append(result.Warnings, fmt.Sprintf("密码错误: %v", err))
			continue
		}
		
		// 其他错误，直接返回
		return err
	}
	
	return NewExtractError(ErrInvalidPassword, fmt.Sprintf("尝试了 %d 个密码都无法解压RAR文件", len(passwordList)), archivePath, nil)
}

// tryExtractWithPassword 使用指定密码尝试解压RAR文件
func (e *defaultRarExtractor) tryExtractWithPassword(archivePath, outputDir, password string, config extractConfig, result *recursiveExtractResult) error {
	// 每次尝试都重新打开文件
	file, err := os.Open(archivePath)
	if err != nil {
		return NewExtractError(ErrInvalidPath, "无法打开RAR文件", archivePath, err)
	}
	defer file.Close()

	// 创建RAR读取器，使用密码选项
	var rarReader *rardecode.Reader
	if password == "" {
		// 无密码
		rarReader, err = rardecode.NewReader(file)
	} else {
		// 有密码
		rarReader, err = rardecode.NewReader(file, rardecode.Password(password))
	}
	
	if err != nil {
		return fmt.Errorf("rardecode.NewReader failed: %v", err)
	}

	// 遍历RAR文件中的所有文件
	for {
		header, err := rarReader.Next()
		if err == io.EOF {
			break // 文件结束
		}
		if err != nil {
			return NewExtractError(ErrCorruptedArchive, fmt.Sprintf("读取RAR条目失败: %v", err), archivePath, err)
		}

		// 智能解码文件名 - 使用RAR专用解码方法
		originalFileName := header.Name
		fileName, detectedEncoding, err := e.encodingHandler.RARDecodeFileName(originalFileName)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("RAR文件名解码失败: %s (错误: %v)", originalFileName, err))
			fileName = originalFileName // 使用原始文件名
		} else if detectedEncoding != "UTF-8" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("RAR文件名编码检测: %s -> %s", originalFileName, detectedEncoding))
		}

		// 验证路径安全性
		if err := e.validator.ValidatePath(fileName, outputDir); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("跳过不安全的路径: %s", fileName))
			continue
		}

		// 构建目标路径
		targetPath := filepath.Join(outputDir, fileName)

		// 处理目录
		if header.IsDir {
			if err := os.MkdirAll(targetPath, header.Mode()); err != nil {
				return NewExtractError(ErrPermissionDenied, "无法创建目录", targetPath, err)
			}
			
			// 添加到结果
			result.Files = append(result.Files, extractedFile{
				Path:    targetPath,
				Size:    0,
				ModTime: header.ModificationTime,
				IsDir:   true,
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
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return NewExtractError(ErrPermissionDenied, "无法创建父目录", filepath.Dir(targetPath), err)
		}

		// 创建目标文件
		outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, header.Mode())
		if err != nil {
			return NewExtractError(ErrPermissionDenied, "无法创建目标文件", targetPath, err)
		}

		// 添加文件清理机制：如果复制失败，删除已创建的文件
		var copySuccess bool
		defer func(path string) {
			if !copySuccess {
				os.Remove(path)
			}
		}(targetPath)

		// 复制内容
		_, err = io.Copy(outFile, rarReader)
		outFile.Close()

		if err != nil {
			// 检查是否是加密相关错误
			if strings.Contains(err.Error(), "encrypted") || 
			   strings.Contains(err.Error(), "password") ||
			   strings.Contains(err.Error(), "required") {
				return fmt.Errorf("rardecode: archived files encrypted, password required")
			}
			return NewExtractError(ErrInternalError, "文件复制失败", targetPath, err)
		}
		copySuccess = true

		// 设置文件时间
		if err := os.Chtimes(targetPath, header.ModificationTime, header.ModificationTime); err != nil {
			// 时间设置失败不是致命错误
		}

		// 添加到结果
		result.Files = append(result.Files, extractedFile{
			Path:    targetPath,
			Size:    int64(header.UnPackedSize),
			ModTime: header.ModificationTime,
			IsDir:   false,
		})
		
		result.TotalFiles++
		result.TotalSize += int64(header.UnPackedSize)
	}

	return nil
}

// validateRarHeader 验证RAR文件头
func (e *defaultRarExtractor) validateRarHeader(archivePath string) error {
	// 打开文件读取头部信息
	file, err := os.Open(archivePath)
	if err != nil {
		return NewExtractError(ErrInvalidPath, "无法打开文件", archivePath, err)
	}
	defer file.Close()

	// 读取RAR文件头（读取更多字节以支持RAR 5.x）
	header := make([]byte, 8)
	n, err := file.Read(header)
	if err != nil {
		return NewExtractError(ErrCorruptedArchive, "无法读取RAR文件头", archivePath, err)
	}

	// 检查RAR签名
	// RAR 4.x: "Rar!\x1a\x07\x00"
	// RAR 5.x: "Rar!\x1a\x07\x01\x00"
	if !e.isValidRarSignature(header[:n]) {
		return NewExtractError(ErrCorruptedArchive, "无效的RAR文件签名", archivePath, nil)
	}

	return nil
}

// isValidRarSignature 检查RAR文件签名
func (e *defaultRarExtractor) isValidRarSignature(header []byte) bool {
	if len(header) < 4 {
		return false
	}

	// 首先检查基本的 "Rar!" 签名
	if header[0] != 0x52 || header[1] != 0x61 || header[2] != 0x72 || header[3] != 0x21 {
		return false
	}

	// 检查完整签名
	if len(header) >= 7 {
		// RAR 4.x 签名: "Rar!\x1a\x07\x00"
		if header[4] == 0x1a && header[5] == 0x07 && header[6] == 0x00 {
			return true
		}
	}

	// RAR 5.x 签名: "Rar!\x1a\x07\x01\x00"
	if len(header) >= 8 {
		if header[4] == 0x1a && header[5] == 0x07 && header[6] == 0x01 && header[7] == 0x00 {
			return true
		}
	}

	// 更宽松的检查：只要有"Rar!\x1a\x07"就认为是有效的
	if len(header) >= 6 {
		if header[4] == 0x1a && header[5] == 0x07 {
			return true
		}
	}

	return false
}

// fillRarInfo 填充RAR文件详细信息
func (e *defaultRarExtractor) fillRarInfo(archivePath string, info *rarArchiveInfo) error {
	// 这里需要实际的RAR文件解析
	// 可以获取：
	// - 文件数量
	// - RAR版本
	// - 压缩方法
	// - 创建时间等

	// 示例实现：设置默认值
	info.FileCount = 0 // 需要实际解析
	info.Version = "Unknown"

	return nil
}

// handleRarError 处理RAR相关错误
func (e *defaultRarExtractor) handleRarError(err error, path string) error {
	if err == nil {
		return nil
	}

	errorMsg := err.Error()

	// 检查常见的RAR错误
	if strings.Contains(errorMsg, "password") || strings.Contains(errorMsg, "encrypted") {
		return NewExtractError(ErrPasswordRequired, "RAR文件需要密码", path, err)
	}

	if strings.Contains(errorMsg, "corrupt") || strings.Contains(errorMsg, "damaged") {
		return NewExtractError(ErrCorruptedArchive, "RAR文件已损坏", path, err)
	}

	if strings.Contains(errorMsg, "permission denied") {
		return NewExtractError(ErrPermissionDenied, "权限不足", path, err)
	}

	if strings.Contains(errorMsg, "no space left") {
		return NewExtractError(ErrDiskFull, "磁盘空间不足", path, err)
	}

	// 默认内部错误
	return NewExtractError(ErrInternalError, "RAR解压失败", path, err)
}

// rarArchiveInfo RAR文件信息
type rarArchiveInfo struct {
	Path        string
	Size        int64
	ModTime     time.Time
	FileCount   int
	HasPassword bool
	Version     string
}

// processNestedArchives 处理RAR解压后的嵌套压缩包
func (e *defaultRarExtractor) processNestedArchives(result *recursiveExtractResult, baseOutputDir string, config extractConfig, currentDepth int) error {
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
func (e *defaultRarExtractor) isArchiveFile(filePath string) bool {
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
func (e *defaultRarExtractor) extractNestedArchive(nestedPath, baseOutputDir string, config extractConfig, depth int, parentResult *recursiveExtractResult) error {
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
func (e *defaultRarExtractor) mergeResults(parentResult, nestedResult *recursiveExtractResult, nestedPath string, depth int) {
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
