package unzip

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileInfo 文件信息结构
type FileInfo struct {
	Path            string        // 文件路径
	Name            string        // 文件名
	Size            int64         // 文件大小
	Format          ArchiveFormat // 检测到的格式
	DetectedByMagic bool          // 是否通过魔数检测
	Extension       string        // 文件扩展名
}

// FormatDetector 格式检测器接口
type FormatDetector interface {
	// DetectFormat 检测文件格式
	DetectFormat(filePath string) (ArchiveFormat, error)

	// DetectFileInfo 检测文件详细信息
	DetectFileInfo(filePath string) (*FileInfo, error)

	// DetectFromReader 从Reader检测格式
	DetectFromReader(reader io.Reader) (ArchiveFormat, error)

	// DetectFromBytes 从字节数组检测格式
	DetectFromBytes(data []byte) ArchiveFormat

	// ValidateFormat 验证文件是否为指定格式
	ValidateFormat(filePath string, expectedFormat ArchiveFormat) (bool, error)
}

// defaultFormatDetector 默认格式检测器实现
type defaultFormatDetector struct {
	maxMagicBytes int // 读取用于魔数检测的最大字节数
}

// NewFormatDetector 创建新的格式检测器
func NewFormatDetector() FormatDetector {
	return &defaultFormatDetector{
		maxMagicBytes: 512, // 默认读取512字节
	}
}

// DetectFormat 检测文件格式
func (d *defaultFormatDetector) DetectFormat(filePath string) (ArchiveFormat, error) {
	// 首先通过魔数检测（优先级更高）
	magicFormat, err := d.detectByMagicBytes(filePath)
	if err == nil && magicFormat != FormatUnknown {
		return magicFormat, nil
	}

	// 如果魔数检测失败，尝试扩展名检测
	if format := d.detectByExtension(filePath); format != FormatUnknown {
		// 验证文件头
		if verified, err := d.verifyByMagicBytes(filePath, format); err == nil && verified {
			return format, nil
		}
	}

	// 都失败时返回未知格式
	return FormatUnknown, nil
}

// DetectFileInfo 检测文件详细信息
func (d *defaultFormatDetector) DetectFileInfo(filePath string) (*FileInfo, error) {
	// 获取文件基本信息
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("无法获取文件信息: %v", err)
	}

	fileInfo := &FileInfo{
		Path:      filePath,
		Name:      filepath.Base(filePath),
		Size:      stat.Size(),
		Format:    FormatUnknown,
		Extension: filepath.Ext(filePath),
	}

	// 首先尝试通过魔数检测
	if detectedFormat, err := d.detectByMagicBytes(filePath); err == nil && detectedFormat != FormatUnknown {
		fileInfo.Format = detectedFormat
		fileInfo.DetectedByMagic = true
		return fileInfo, nil
	}

	// 尝试通过扩展名检测
	if format := d.detectByExtension(filePath); format != FormatUnknown {
		fileInfo.Format = format
		fileInfo.DetectedByMagic = false
	}

	return fileInfo, nil
}

// ValidateFormat 验证文件是否为指定格式
func (d *defaultFormatDetector) ValidateFormat(filePath string, expectedFormat ArchiveFormat) (bool, error) {
	detectedFormat, err := d.DetectFormat(filePath)
	return detectedFormat == expectedFormat, err
}

// DetectFromReader 从Reader检测格式
func (d *defaultFormatDetector) DetectFromReader(reader io.Reader) (ArchiveFormat, error) {
	buffer := make([]byte, d.maxMagicBytes)
	n, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		return FormatUnknown, err
	}

	if n == 0 {
		return FormatUnknown, fmt.Errorf("无法读取数据")
	}

	return d.DetectFromBytes(buffer[:n]), nil
}

// DetectFromBytes 从字节数组检测格式
func (d *defaultFormatDetector) DetectFromBytes(data []byte) ArchiveFormat {
	if len(data) < 4 {
		return FormatUnknown
	}

	// ZIP格式检测
	if d.isZipFormat(data) {
		return FormatZIP
	}

	// RAR格式检测
	if d.isRarFormat(data) {
		return FormatRAR
	}

	// 7Z格式检测
	if d.is7zFormat(data) {
		return Format7Z
	}

	// TAR格式检测
	if d.isTarFormat(data) {
		return FormatTAR
	}

	// GZIP格式检测
	if d.isGzipFormat(data) {
		return FormatTARGZ
	}

	// BZIP2格式检测
	if d.isBzip2Format(data) {
		return FormatTARBZ2
	}

	return FormatUnknown
}

// detectByExtension 通过扩展名检测格式
func (d *defaultFormatDetector) detectByExtension(filePath string) ArchiveFormat {
	ext := strings.ToLower(filepath.Ext(filePath))
	filename := strings.ToLower(filepath.Base(filePath))

	switch ext {
	case ".zip":
		return FormatZIP
	case ".rar":
		return FormatRAR
	case ".7z":
		return Format7Z
	case ".tar":
		return FormatTAR
	case ".gz":
		if strings.HasSuffix(filename, ".tar.gz") {
			return FormatTARGZ
		}
		return FormatTARGZ
	case ".bz2":
		if strings.HasSuffix(filename, ".tar.bz2") {
			return FormatTARBZ2
		}
		return FormatTARBZ2
	case ".tgz":
		return FormatTARGZ
	case ".tbz", ".tbz2":
		return FormatTARBZ2
	default:
		return FormatUnknown
	}
}

// detectByMagicBytes 通过魔数检测格式
func (d *defaultFormatDetector) detectByMagicBytes(filePath string) (ArchiveFormat, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return FormatUnknown, err
	}
	defer file.Close()

	buffer := make([]byte, d.maxMagicBytes)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return FormatUnknown, err
	}

	return d.DetectFromBytes(buffer[:n]), nil
}

// verifyByMagicBytes 验证文件魔数是否匹配期望格式
func (d *defaultFormatDetector) verifyByMagicBytes(filePath string, expectedFormat ArchiveFormat) (bool, error) {
	detectedFormat, err := d.detectByMagicBytes(filePath)
	if err != nil {
		return false, err
	}

	return detectedFormat == expectedFormat, nil
}

// isZipFormat 检测是否为ZIP格式
func (d *defaultFormatDetector) isZipFormat(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// ZIP文件的魔数: PK\x03\x04 或 PK\x05\x06 或 PK\x07\x08
	return bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}) ||
		bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x05, 0x06}) ||
		bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x07, 0x08})
}

// isRarFormat 检测是否为RAR格式
func (d *defaultFormatDetector) isRarFormat(data []byte) bool {
	if len(data) < 7 {
		return false
	}

	// RAR v4.x 魔数: Rar!\x1A\x07\x00
	if bytes.HasPrefix(data, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}) {
		return true
	}

	// RAR v5.x 魔数: Rar!\x1A\x07\x01\x00
	if len(data) >= 8 && bytes.HasPrefix(data, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}) {
		return true
	}

	return false
}

// is7zFormat 检测是否为7Z格式
func (d *defaultFormatDetector) is7zFormat(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	// 7Z魔数: 7z\xBC\xAF\x27\x1C
	return bytes.HasPrefix(data, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C})
}

// isTarFormat 检测是否为TAR格式
func (d *defaultFormatDetector) isTarFormat(data []byte) bool {
	if len(data) < 512 {
		return false
	}

	// TAR文件的标识符在偏移257处
	ustarSignature := []byte("ustar")
	if len(data) >= 262 && bytes.Equal(data[257:262], ustarSignature) {
		// 验证校验和
		return d.validateTarChecksum(data)
	}

	// 检查GNU TAR格式
	if len(data) >= 263 && bytes.Equal(data[257:263], []byte("ustar ")) {
		return d.validateTarChecksum(data)
	}

	return false
}

// isGzipFormat 检测是否为GZIP格式
func (d *defaultFormatDetector) isGzipFormat(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	// GZIP魔数: \x1F\x8B\x08
	return data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08
}

// isBzip2Format 检测是否为BZIP2格式
func (d *defaultFormatDetector) isBzip2Format(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	// BZIP2魔数: BZ
	return bytes.HasPrefix(data, []byte{0x42, 0x5A})
}

// validateTarChecksum 验证TAR文件的校验和
func (d *defaultFormatDetector) validateTarChecksum(data []byte) bool {
	if len(data) < 512 {
		return false
	}

	// 计算校验和
	var sum int64

	// 校验和字段（148-155）应该被视为空格
	for i := 0; i < 512; i++ {
		if i >= 148 && i < 156 {
			sum += int64(' ')
		} else {
			sum += int64(data[i])
		}
	}

	// 读取存储的校验和
	checksumStr := strings.TrimSpace(string(data[148:156]))
	if checksumStr == "" {
		return false
	}

	// 移除尾部的空字符和空格
	checksumStr = strings.TrimRight(checksumStr, "\x00 ")

	// 尝试解析八进制数
	var storedChecksum int64
	var err error

	if strings.HasSuffix(checksumStr, "\x00") || strings.HasSuffix(checksumStr, " ") {
		checksumStr = checksumStr[:len(checksumStr)-1]
	}

	if checksumStr != "" {
		storedChecksum, err = parseOctal(checksumStr)
		if err != nil {
			return false
		}
	}

	return sum == storedChecksum
}

// parseOctal 解析八进制字符串
func parseOctal(s string) (int64, error) {
	var result int64
	for _, char := range s {
		if char < '0' || char > '7' {
			return 0, fmt.Errorf("无效的八进制字符: %c", char)
		}
		result = result*8 + int64(char-'0')
	}
	return result, nil
}