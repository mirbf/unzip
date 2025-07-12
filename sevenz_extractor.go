package unzip

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/bodgit/sevenzip"
)

// sevenZExtractor 7Z格式解压器接口
type sevenZExtractor interface {
	// Extract 解压7Z文件
	Extract(archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error)

	// ValidateArchive 验证7Z文件
	ValidateArchive(archivePath string) error

	// GetArchiveInfo 获取7Z文件信息
	GetArchiveInfo(archivePath string) (*sevenZArchiveInfo, error)

	// IsPasswordProtected 检查是否需要密码
	IsPasswordProtected(archivePath string) (bool, error)

	// ListFiles 列出7Z文件中的文件
	ListFiles(archivePath string) ([]string, error)
}

// defaultSevenZExtractor 默认7Z解压器实现
type defaultSevenZExtractor struct {
	validator       SecurityValidator
	encodingHandler EncodingHandler
}

// newSevenZExtractor 创建新的7Z解压器
func newSevenZExtractor() sevenZExtractor {
	return &defaultSevenZExtractor{
		validator:       NewSecurityValidator(),
		encodingHandler: NewEncodingHandler(),
	}
}

// newSevenZExtractorWithDeps 创建带依赖的7Z解压器
func newSevenZExtractorWithDeps(validator SecurityValidator, encodingHandler EncodingHandler) sevenZExtractor {
	return &defaultSevenZExtractor{
		validator:       validator,
		encodingHandler: encodingHandler,
	}
}

// Extract 解压7Z文件
func (e *defaultSevenZExtractor) Extract(archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error) {
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

	result.Warnings = append(result.Warnings, fmt.Sprintf("开始解压7z文件: %s", archivePath))

	// 7Z解压需要使用外部工具或第三方库
	err := e.extractWith7z(archivePath, outputDir, config, result)
	if err != nil {
		// 如果解压失败，尝试返回已收集的警告信息
		if len(result.Warnings) > 0 {
			errorWithWarnings := fmt.Sprintf("%v\n警告信息:\n%s", err, strings.Join(result.Warnings, "\n"))
			return nil, fmt.Errorf("%s", errorWithWarnings)
		}
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

// ValidateArchive 验证7Z文件
func (e *defaultSevenZExtractor) ValidateArchive(archivePath string) error {
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

	if format != Format7Z {
		return NewExtractError(ErrUnsupportedFormat, "不是7Z格式文件", archivePath, nil)
	}

	// 检查7Z文件头
	if err := e.validate7zHeader(archivePath); err != nil {
		return err
	}

	return nil
}

// GetArchiveInfo 获取7Z文件信息
func (e *defaultSevenZExtractor) GetArchiveInfo(archivePath string) (*sevenZArchiveInfo, error) {
	// 验证文件
	if err := e.ValidateArchive(archivePath); err != nil {
		return nil, err
	}

	// 获取文件统计信息
	stat, err := os.Stat(archivePath)
	if err != nil {
		return nil, NewExtractError(ErrInvalidPath, "无法获取文件信息", archivePath, err)
	}

	info := &sevenZArchiveInfo{
		Path:            archivePath,
		Size:            stat.Size(),
		ModTime:         stat.ModTime(),
		FileCount:       0, // 需要通过解析7Z文件获取
		HasPassword:     false,
		CompressionType: "",
		SolidArchive:    false,
	}

	// 检查是否需要密码
	hasPassword, err := e.IsPasswordProtected(archivePath)
	if err == nil {
		info.HasPassword = hasPassword
	}

	// 获取更多详细信息（需要实际的7Z解析库）
	if err := e.fill7zInfo(archivePath, info); err != nil {
		// 如果获取详细信息失败，只返回基本信息
		// 不作为错误处理
	}

	return info, nil
}

// IsPasswordProtected 检查7Z文件是否需要密码
func (e *defaultSevenZExtractor) IsPasswordProtected(archivePath string) (bool, error) {
	// 尝试不使用密码打开文件
	reader, err := sevenzip.OpenReader(archivePath)
	if err != nil {
		// 如果错误信息包含密码相关字符串，说明需要密码
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "password") || 
		   strings.Contains(errorMsg, "encrypted") ||
		   strings.Contains(errorMsg, "Wrong password") {
			return true, nil
		}
		return false, err
	}
	defer reader.Close()

	// 尝试访问第一个文件，如果需要密码会在这里失败
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			errorMsg := err.Error()
			if strings.Contains(errorMsg, "password") || 
			   strings.Contains(errorMsg, "encrypted") ||
			   strings.Contains(errorMsg, "Wrong password") {
				return true, nil
			}
			return false, err
		}
		rc.Close()
		break // 只检查第一个文件就够了
	}

	return false, nil
}

// ListFiles 列出7Z文件中的文件
func (e *defaultSevenZExtractor) ListFiles(archivePath string) ([]string, error) {
	// 验证文件
	if err := e.ValidateArchive(archivePath); err != nil {
		return nil, err
	}

	// 这里需要实际的7Z文件解析
	// 返回文件列表

	// 示例实现：返回空列表
	return []string{}, nil
}

// extractWith7z 使用7z工具解压
func (e *defaultSevenZExtractor) extractWith7z(archivePath, outputDir string, config extractConfig, result *recursiveExtractResult) error {
	result.Warnings = append(result.Warnings, fmt.Sprintf("开始打开7z文件: %s", archivePath))
	
	// 准备密码列表（使用集中的密码管理器）
	passwordManager := GetGlobalPasswordManager()
	userPasswords := config.Passwords
	if config.Password != "" {
		userPasswords = append([]string{config.Password}, userPasswords...)
	}
	passwordList := passwordManager.buildPasswordList(userPasswords, true, true)
	
	result.Warnings = append(result.Warnings, fmt.Sprintf("准备尝试 %d 个密码", len(passwordList)))
	
	// 尝试使用密码打开7Z文件
	var reader *sevenzip.ReadCloser
	var err error
	var usedPassword string
	
	for i, password := range passwordList {
		result.Warnings = append(result.Warnings, fmt.Sprintf("尝试密码 %d/%d: %s", i+1, len(passwordList), 
			func(pwd string) string {
				if pwd == "" { return "<无密码>" }
				return "***"
			}(password)))
		
		if password == "" {
			// 尝试无密码
			reader, err = sevenzip.OpenReader(archivePath)
		} else {
			// 使用密码打开7z文件
			reader, err = openSevenZipWithPassword(archivePath, password)
		}
		
		if err == nil {
			usedPassword = password
			result.Warnings = append(result.Warnings, fmt.Sprintf("密码匹配成功: %s", 
				func(pwd string) string {
					if pwd == "" { return "<无密码>" }
					return "***"
				}(password)))
			break
		}
		
		result.Warnings = append(result.Warnings, fmt.Sprintf("密码失败: %v", err))
	}
	
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("所有密码都失败，打开7z文件失败: %v", err))
		return e.handle7zError(err, archivePath)
	}
	defer reader.Close()

	result.Warnings = append(result.Warnings, fmt.Sprintf("7z文件打开成功，包含 %d 个文件，使用密码: %s", len(reader.File), 
		func(pwd string) string {
			if pwd == "" { return "<无密码>" }
			return "***"
		}(usedPassword)))

	// 文件名映射表：英文临时名 -> 中文原始名
	filenameMapping := make(map[string]string)

	// 遍历文件
	for i, file := range reader.File {
		result.Warnings = append(result.Warnings, fmt.Sprintf("处理第 %d 个文件", i+1))
		
		// 获取原始文件名
		originalFileName := file.Name
		result.Warnings = append(result.Warnings, fmt.Sprintf("原始文件名: %s", originalFileName))
		
		// 为UTF-8中文文件名生成英文临时名
		tempFileName := originalFileName
		if utf8.ValidString(originalFileName) && containsChineseChars(originalFileName) {
			tempFileName = generateEnglishFilename(originalFileName)
			filenameMapping[tempFileName] = originalFileName
			result.Warnings = append(result.Warnings, fmt.Sprintf("生成英文临时文件名: %s -> %s", originalFileName, tempFileName))
			
			// 使用反射修改file.Name为英文临时名
			if err := patchFileName(file, tempFileName); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("修改文件名失败: %v", err))
				tempFileName = originalFileName // 如果修改失败，使用原名
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("文件名修改成功: %s", tempFileName))
			}
		}

		// 验证路径安全性
		if err := e.validator.ValidatePath(tempFileName, outputDir); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("跳过不安全的路径: %s", tempFileName))
			continue
		}

		// 构建临时目标路径
		tempTargetPath := filepath.Join(outputDir, tempFileName)

		// 处理目录
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(tempTargetPath, file.FileInfo().Mode()); err != nil {
				return NewExtractError(ErrPermissionDenied, "无法创建目录", tempTargetPath, err)
			}
			
			// 添加到结果
			result.Files = append(result.Files, extractedFile{
				Path:    tempTargetPath,
				Size:    0,
				ModTime: file.FileInfo().ModTime(),
				IsDir:   true,
			})
			continue
		}

		// 处理文件冲突
		finalTargetPath, err := HandleFileConflict(tempTargetPath, config)
		if err != nil {
			return err
		}
		
		// 如果路径被重命名，更新tempTargetPath
		if finalTargetPath != tempTargetPath {
			tempTargetPath = finalTargetPath
			result.Warnings = append(result.Warnings, fmt.Sprintf("文件重命名: %s -> %s", filepath.Base(tempFileName), filepath.Base(tempTargetPath)))
		}

		// 创建父目录
		if err := os.MkdirAll(filepath.Dir(tempTargetPath), 0755); err != nil {
			return NewExtractError(ErrPermissionDenied, "无法创建父目录", filepath.Dir(tempTargetPath), err)
		}

		// 打开7Z文件中的文件
		rc, err := openFileWithPassword(file, usedPassword)
		if err != nil {
			return e.handle7zError(err, tempFileName)
		}

		// 创建目标文件
		outFile, err := os.OpenFile(tempTargetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			rc.Close()
			return NewExtractError(ErrPermissionDenied, "无法创建目标文件", tempTargetPath, err)
		}

		// 添加文件清理机制：如果复制失败，删除已创建的文件
		var copySuccess bool
		defer func() {
			if !copySuccess {
				os.Remove(tempTargetPath)
			}
		}()

		// 复制内容
		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()

		if err != nil {
			return NewExtractError(ErrInternalError, "文件复制失败", tempTargetPath, err)
		}
		copySuccess = true

		// 设置文件时间
		if err := os.Chtimes(tempTargetPath, file.FileInfo().ModTime(), file.FileInfo().ModTime()); err != nil {
			// 时间设置失败不是致命错误
		}

		// 添加到结果
		result.Files = append(result.Files, extractedFile{
			Path:    tempTargetPath,
			Size:    file.FileInfo().Size(),
			ModTime: file.FileInfo().ModTime(),
			IsDir:   false,
		})
		
		result.TotalFiles++
		result.TotalSize += file.FileInfo().Size()
	}

	// 后处理阶段：将英文临时文件名重命名为中文文件名
	for englishPath, chinesePath := range filenameMapping {
		tempFullPath := filepath.Join(outputDir, englishPath)
		finalFullPath := filepath.Join(outputDir, chinesePath)
		
		// 检查临时文件是否存在
		if _, err := os.Stat(tempFullPath); os.IsNotExist(err) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("临时文件不存在，跳过重命名: %s", englishPath))
			continue
		}
		
		// 确保最终路径的父目录存在
		if err := os.MkdirAll(filepath.Dir(finalFullPath), 0755); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("无法创建最终目录: %s", filepath.Dir(finalFullPath)))
			continue
		}
		
		// 重命名文件
		if err := os.Rename(tempFullPath, finalFullPath); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("重命名失败: %s -> %s (错误: %v)", englishPath, chinesePath, err))
			continue
		}
		
		result.Warnings = append(result.Warnings, fmt.Sprintf("文件重命名成功: %s -> %s", englishPath, chinesePath))
		
		// 更新结果中的文件路径
		for i, extractedFile := range result.Files {
			if extractedFile.Path == tempFullPath {
				result.Files[i].Path = finalFullPath
				break
			}
		}
	}

	return nil
}

// validate7zHeader 验证7Z文件头
func (e *defaultSevenZExtractor) validate7zHeader(archivePath string) error {
	// 打开文件读取头部信息
	file, err := os.Open(archivePath)
	if err != nil {
		return NewExtractError(ErrInvalidPath, "无法打开文件", archivePath, err)
	}
	defer file.Close()

	// 读取7Z文件头
	header := make([]byte, 6)
	n, err := file.Read(header)
	if err != nil || n < 6 {
		return NewExtractError(ErrCorruptedArchive, "无法读取7Z文件头", archivePath, err)
	}

	// 检查7Z签名: "7z\xBC\xAF\x27\x1C"
	if !e.isValid7zSignature(header) {
		return NewExtractError(ErrCorruptedArchive, "无效的7Z文件签名", archivePath, nil)
	}

	return nil
}

// isValid7zSignature 检查7Z文件签名
func (e *defaultSevenZExtractor) isValid7zSignature(header []byte) bool {
	if len(header) < 6 {
		return false
	}

	// 7Z 签名
	sevenzSig := []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}
	return string(header[:6]) == string(sevenzSig)
}

// fill7zInfo 填充7Z文件详细信息
func (e *defaultSevenZExtractor) fill7zInfo(archivePath string, info *sevenZArchiveInfo) error {
	// 这里需要实际的7Z文件解析
	// 可以获取：
	// - 文件数量
	// - 压缩方法
	// - 是否为固实压缩
	// - 创建时间等

	// 示例实现：设置默认值
	info.FileCount = 0 // 需要实际解析
	info.CompressionType = "Unknown"
	info.SolidArchive = false

	return nil
}

// containsChineseChars 检查字符串是否包含中文字符
func containsChineseChars(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// generateEnglishFilename 为中文文件名生成对应的英文文件名
func generateEnglishFilename(chineseFilename string) string {
	// 使用MD5哈希生成唯一的英文文件名
	hash := md5.Sum([]byte(chineseFilename))
	hashStr := fmt.Sprintf("%x", hash)
	
	// 保留文件扩展名
	ext := filepath.Ext(chineseFilename)
	
	// 生成英文文件名: file_<hash前8位><原始扩展名>
	englishName := fmt.Sprintf("file_%s%s", hashStr[:8], ext)
	
	// 如果原文件名包含目录，保留目录结构（但目录名也需要处理）
	dir := filepath.Dir(chineseFilename)
	if dir != "." && dir != "" {
		// 处理目录中的中文字符
		dirParts := strings.Split(dir, string(filepath.Separator))
		englishDirParts := make([]string, len(dirParts))
		for i, part := range dirParts {
			if containsChineseChars(part) {
				dirHash := md5.Sum([]byte(part))
				englishDirParts[i] = fmt.Sprintf("dir_%x", dirHash)[:12] // 使用前12位避免路径过长
			} else {
				englishDirParts[i] = part
			}
		}
		englishDir := strings.Join(englishDirParts, string(filepath.Separator))
		englishName = filepath.Join(englishDir, englishName)
	}
	
	return englishName
}

// patchFileName 使用反射修改7z文件对象的Name字段
func patchFileName(file *sevenzip.File, newName string) error {
	// 获取file对象的反射值
	fileValue := reflect.ValueOf(file)
	if fileValue.Kind() != reflect.Ptr {
		return fmt.Errorf("file对象不是指针类型")
	}
	
	// 获取指向的结构体
	fileStruct := fileValue.Elem()
	if fileStruct.Kind() != reflect.Struct {
		return fmt.Errorf("file对象不是结构体类型")
	}
	
	// 查找Name字段
	nameField := fileStruct.FieldByName("Name")
	if !nameField.IsValid() {
		return fmt.Errorf("未找到Name字段")
	}
	
	// 检查字段类型
	if nameField.Kind() != reflect.String {
		return fmt.Errorf("Name字段不是字符串类型")
	}
	
	// 如果字段不可设置，使用unsafe包强制修改
	if !nameField.CanSet() {
		// 使用unsafe包获取字段地址并修改
		nameFieldPtr := (*string)(unsafe.Pointer(nameField.UnsafeAddr()))
		*nameFieldPtr = newName
	} else {
		// 如果可以直接设置
		nameField.SetString(newName)
	}
	
	return nil
}

// handle7zError 处理7Z相关错误
func (e *defaultSevenZExtractor) handle7zError(err error, path string) error {
	if err == nil {
		return nil
	}

	errorMsg := err.Error()

	// 检查常见的7Z错误
	if strings.Contains(errorMsg, "password") || strings.Contains(errorMsg, "encrypted") {
		return NewExtractError(ErrPasswordRequired, "7Z文件需要密码", path, err)
	}

	if strings.Contains(errorMsg, "corrupt") || strings.Contains(errorMsg, "damaged") {
		return NewExtractError(ErrCorruptedArchive, "7Z文件已损坏", path, err)
	}

	if strings.Contains(errorMsg, "unsupported") {
		return NewExtractError(ErrUnsupportedFormat, "不支持的7Z格式或压缩方法", path, err)
	}

	if strings.Contains(errorMsg, "permission denied") {
		return NewExtractError(ErrPermissionDenied, "权限不足", path, err)
	}

	if strings.Contains(errorMsg, "no space left") {
		return NewExtractError(ErrDiskFull, "磁盘空间不足", path, err)
	}

	// 默认内部错误
	return NewExtractError(ErrInternalError, "7Z解压失败", path, err)
}

// openSevenZipWithPassword 使用密码打开7z文件
func openSevenZipWithPassword(archivePath, password string) (*sevenzip.ReadCloser, error) {
	// 使用OpenReaderWithPassword方法
	if password != "" {
		return sevenzip.OpenReaderWithPassword(archivePath, password)
	}
	// 无密码时使用普通OpenReader方法
	return sevenzip.OpenReader(archivePath)
}

// openFileWithPassword 使用密码打开7z文件中的单个文件
func openFileWithPassword(file *sevenzip.File, password string) (io.ReadCloser, error) {
	// 注意：bodgit/sevenzip库中，密码在打开档案时设置，文件提取使用Open()
	return file.Open()
}

// sevenZArchiveInfo 7Z文件信息
type sevenZArchiveInfo struct {
	Path            string
	Size            int64
	ModTime         time.Time
	FileCount       int
	HasPassword     bool
	CompressionType string
	SolidArchive    bool // 是否为固实压缩
}

// processNestedArchives 处理7Z解压后的嵌套压缩包
func (e *defaultSevenZExtractor) processNestedArchives(result *recursiveExtractResult, baseOutputDir string, config extractConfig, currentDepth int) error {
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
func (e *defaultSevenZExtractor) isArchiveFile(filePath string) bool {
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
func (e *defaultSevenZExtractor) extractNestedArchive(nestedPath, baseOutputDir string, config extractConfig, depth int, parentResult *recursiveExtractResult) error {
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
func (e *defaultSevenZExtractor) mergeResults(parentResult, nestedResult *recursiveExtractResult, nestedPath string, depth int) {
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
