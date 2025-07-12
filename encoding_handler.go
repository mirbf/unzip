package unzip

import (
	"fmt"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	utfencoding "golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// EncodingHandler 编码处理器接口
type EncodingHandler interface {
	// DecodeFileName 解码文件名
	DecodeFileName(fileName, encoding string) (string, error)
	
	// GetSupportedEncodings 获取支持的编码列表
	GetSupportedEncodings() []string
	
	// DetectEncoding 检测文件名编码（高级实现）
	DetectEncoding(fileName string) string
	
	// IsValidEncoding 检查编码是否有效
	IsValidEncoding(encoding string) bool
	
	// SmartDecodeFileName 智能解码文件名（自动检测+跨平台）
	SmartDecodeFileName(fileName string) (string, string, error)
	
	// ConvertToSystemEncoding 转换为系统兼容编码
	ConvertToSystemEncoding(fileName string) (string, error)
	
	// GetSystemEncoding 获取系统默认编码
	GetSystemEncoding() string
	
	// RARDecodeFileName RAR文件名专用解码方法
	RARDecodeFileName(fileName string) (string, string, error)
	
	// RepairCorruptedFileName 修复损坏的文件名
	RepairCorruptedFileName(fileName string) (string, error)
}

// defaultEncodingHandler 默认编码处理器实现
type defaultEncodingHandler struct{}

// NewEncodingHandler 创建新的编码处理器
func NewEncodingHandler() EncodingHandler {
	return &defaultEncodingHandler{}
}

// DecodeFileName 解码文件名
func (h *defaultEncodingHandler) DecodeFileName(fileName, encoding string) (string, error) {
	if encoding == "" || encoding == "UTF-8" {
		return fileName, nil
	}
	
	decoder := h.getDecoder(encoding)
	if decoder == nil {
		return fileName, fmt.Errorf("不支持的编码: %s", encoding)
	}
	
	decodedBytes, _, err := transform.Bytes(decoder, []byte(fileName))
	if err != nil {
		return fileName, err
	}
	
	return string(decodedBytes), nil
}

// GetSupportedEncodings 获取支持的编码列表
func (h *defaultEncodingHandler) GetSupportedEncodings() []string {
	return []string{
		"UTF-8",
		"GBK",
		"GB2312",
		"BIG5",
		"SHIFT_JIS",
		"SJIS",
		"EUC-KR",
		"ISO-8859-1",
		"LATIN1",
		"CP866",
		"CP1252",
		"WINDOWS-1252",
		"UTF-16",
	}
}

// DetectEncoding 检测文件名编码（高级实现）
func (h *defaultEncodingHandler) DetectEncoding(fileName string) string {
	// 首先检查是否已经是有效的UTF-8
	if utf8.ValidString(fileName) {
		return "UTF-8"
	}

	// 使用chardet库进行检测
	detector := chardet.NewTextDetector()
	result, err := detector.DetectBest([]byte(fileName))
	if err == nil && result.Confidence > 80 {
		// 映射检测结果到我们支持的编码
		switch strings.ToUpper(result.Charset) {
		case "GB2312", "GBK", "GB18030":
			return "GBK"
		case "BIG5":
			return "BIG5"
		case "SHIFT_JIS", "SJIS":
			return "SHIFT_JIS"
		case "EUC-KR":
			return "EUC-KR"
		case "ISO-8859-1", "WINDOWS-1252":
			return "ISO-8859-1"
		case "UTF-8":
			return "UTF-8"
		case "UTF-16LE", "UTF-16BE":
			return "UTF-16"
		}
	}

	// 如果检测失败，根据平台返回默认编码
	switch runtime.GOOS {
	case "windows":
		return "GBK" // Windows中文系统通常使用GBK
	case "darwin", "linux":
		return "UTF-8" // Unix系统通常使用UTF-8
	default:
		return "UTF-8"
	}
}

// IsValidEncoding 检查编码是否有效
func (h *defaultEncodingHandler) IsValidEncoding(encoding string) bool {
	supportedEncodings := h.GetSupportedEncodings()
	encoding = strings.ToUpper(encoding)
	
	for _, supported := range supportedEncodings {
		if strings.ToUpper(supported) == encoding {
			return true
		}
	}
	return false
}

// getDecoder 根据编码名称获取解码器
func (h *defaultEncodingHandler) getDecoder(encoding string) transform.Transformer {
	switch strings.ToUpper(encoding) {
	case "GBK", "GB2312":
		return simplifiedchinese.GBK.NewDecoder()
	case "BIG5":
		return traditionalchinese.Big5.NewDecoder()
	case "SHIFT_JIS", "SJIS":
		return japanese.ShiftJIS.NewDecoder()
	case "EUC-KR":
		return korean.EUCKR.NewDecoder()
	case "ISO-8859-1", "LATIN1":
		return charmap.ISO8859_1.NewDecoder()
	case "CP866":
		return charmap.CodePage866.NewDecoder()
	case "CP1252", "WINDOWS-1252":
		return charmap.Windows1252.NewDecoder()
	case "UTF-16":
		return utfencoding.UTF16(utfencoding.LittleEndian, utfencoding.UseBOM).NewDecoder()
	default:
		return nil
	}
}

// EncodingConfig 编码配置
type EncodingConfig struct {
	DefaultEncoding string   // 默认编码
	FallbackEncodings []string // 备用编码列表
	AutoDetect      bool     // 是否自动检测编码
}

// SmartDecodeFileName 智能解码文件名（自动检测+跨平台）
func (h *defaultEncodingHandler) SmartDecodeFileName(fileName string) (string, string, error) {
	// 首先检查是否已经是有效的UTF-8
	if utf8.ValidString(fileName) {
		// 如果是有效UTF-8，进一步检查是否包含合理的中文字符
		hasValidChinese := false
		for _, r := range fileName {
			if unicode.Is(unicode.Han, r) {
				hasValidChinese = true
				break
			}
		}
		
		// 如果包含有效的中文字符，或者不包含可疑字符，则认为编码正确
		if hasValidChinese || !h.containsSuspiciousChars(fileName) {
			// 进行系统兼容性转换
			systemFileName, err := h.ConvertToSystemEncoding(fileName)
			if err != nil {
				return fileName, "UTF-8", nil
			}
			return systemFileName, "UTF-8", nil
		}
	}
	
	// 检查是否需要编码转换
	needsDecoding := false
	
	// 检查1：是否包含可疑字符
	if h.containsSuspiciousChars(fileName) {
		needsDecoding = true
	}
	
	// 检查2：不是有效UTF-8
	if !utf8.ValidString(fileName) {
		needsDecoding = true
	}
	
	if needsDecoding {
		return h.forceDecodeFileName(fileName)
	}

	// 如果已经是有效的UTF-8且看起来正常，进行系统兼容性转换
	systemFileName, err := h.ConvertToSystemEncoding(fileName)
	if err != nil {
		return fileName, "UTF-8", nil
	}
	return systemFileName, "UTF-8", nil
}

// containsSuspiciousChars 检查是否包含可疑字符（可能的编码问题）
func (h *defaultEncodingHandler) containsSuspiciousChars(fileName string) bool {
	// 检查是否包含常见的编码错误字符
	for _, r := range fileName {
		// 检查替换字符（U+FFFD）
		if r == '\uFFFD' {
			return true
		}
		// 检查控制字符（除了常见的空白字符）
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return true
		}
	}
	
	// 检查是否包含过多的?字符（可能的编码失败标志）
	questionMarkCount := strings.Count(fileName, "?")
	if questionMarkCount > 2 && len(fileName) > 10 {
		return true
	}
	
	// 检查是否包含常见的乱码字节序列
	suspiciousBytes := []byte(fileName)
	for i := 0; i < len(suspiciousBytes)-1; i++ {
		// 检查高位字节序列，可能是非UTF-8编码
		if suspiciousBytes[i] >= 0x80 && suspiciousBytes[i+1] >= 0x80 {
			// 尝试检测是否为有效的UTF-8序列
			if !utf8.Valid(suspiciousBytes[i:i+2]) {
				return true
			}
		}
	}
	
	return false
}

// forceDecodeFileName 强制解码文件名（不管是否UTF-8有效）
func (h *defaultEncodingHandler) forceDecodeFileName(fileName string) (string, string, error) {
	// 将文件名转换为字节数组进行处理
	fileNameBytes := []byte(fileName)
	
	// 优先尝试GBK编码（中文ZIP/RAR常用）
	priorityEncodings := []string{"GBK", "GB2312", "BIG5", "SHIFT_JIS", "EUC-KR", "ISO-8859-1"}
	
	for _, encoding := range priorityEncodings {
		// 尝试将原始字节作为指定编码解码
		decoder := h.getDecoder(encoding)
		if decoder != nil {
			decoded, _, err := transform.Bytes(decoder, fileNameBytes)
			if err == nil {
				decodedStr := string(decoded)
				if h.isReasonableFileName(decodedStr) {
					// 转换为系统兼容编码
					systemFileName, err := h.ConvertToSystemEncoding(decodedStr)
					if err != nil {
						return decodedStr, encoding, nil
					}
					return systemFileName, encoding, nil
				}
			}
		}
	}
	
	// 如果优先编码都失败，使用chardet自动检测
	detector := chardet.NewTextDetector()
	result, err := detector.DetectBest(fileNameBytes)
	if err == nil && result.Confidence > 70 {
		detectedEncoding := h.mapCharsetToEncoding(result.Charset)
		if detectedEncoding != "" {
			decoded, err := h.DecodeFileName(fileName, detectedEncoding)
			if err == nil && h.isReasonableFileName(decoded) {
				systemFileName, err := h.ConvertToSystemEncoding(decoded)
				if err != nil {
					return decoded, detectedEncoding, nil
				}
				return systemFileName, detectedEncoding, nil
			}
		}
	}
	
	// 最后的备用方案：清理文件名中的无效字符
	cleanFileName := h.sanitizeFileName(fileName)
	return cleanFileName, "CLEANED", nil
}

// mapCharsetToEncoding 将chardet的字符集映射到我们支持的编码
func (h *defaultEncodingHandler) mapCharsetToEncoding(charset string) string {
	switch strings.ToUpper(charset) {
	case "GB2312", "GBK", "GB18030":
		return "GBK"
	case "BIG5":
		return "BIG5"
	case "SHIFT_JIS", "SJIS":
		return "SHIFT_JIS"
	case "EUC-KR":
		return "EUC-KR"
	case "ISO-8859-1", "WINDOWS-1252":
		return "ISO-8859-1"
	case "UTF-8":
		return "UTF-8"
	case "UTF-16LE", "UTF-16BE":
		return "UTF-16"
	default:
		return ""
	}
}

// isReasonableFileName 检查解码后的文件名是否合理
func (h *defaultEncodingHandler) isReasonableFileName(fileName string) bool {
	// 检查是否包含合理的字符
	if !utf8.ValidString(fileName) {
		return false
	}
	
	// 检查是否包含过多控制字符
	controlCharCount := 0
	for _, r := range fileName {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			controlCharCount++
		}
	}
	
	// 如果控制字符过多，认为不合理
	if controlCharCount > len(fileName)/4 {
		return false
	}
	
	return true
}

// sanitizeFileName 清理文件名中的无效字符
func (h *defaultEncodingHandler) sanitizeFileName(fileName string) string {
	// 替换无效字符为安全字符
	cleaned := strings.Map(func(r rune) rune {
		// 保留正常的ASCII字符和常见的Unicode字符
		if r < 32 {
			return '_' // 替换控制字符
		}
		if r == '?' && !utf8.ValidString(string(r)) {
			return '_' // 替换无效的?字符
		}
		// 替换文件系统不支持的字符
		switch r {
		case '<', '>', ':', '"', '|', '*':
			return '_'
		default:
			return r
		}
	}, fileName)
	
	// 确保文件名不为空
	if cleaned == "" {
		cleaned = "unknown_file"
	}
	
	return cleaned
}

// ConvertToSystemEncoding 转换为系统兼容编码
func (h *defaultEncodingHandler) ConvertToSystemEncoding(fileName string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		// Windows系统：如果包含中文字符且当前是UTF-8，可能需要特殊处理
		// 但通常Go的文件操作在Windows上也能正确处理UTF-8
		// 这里保持UTF-8，让Go运行时处理
		return fileName, nil
		
	case "darwin", "linux":
		// Unix系统：确保是UTF-8
		if !utf8.ValidString(fileName) {
			// 如果不是有效UTF-8，尝试修复
			return strings.ToValidUTF8(fileName, "?"), nil
		}
		return fileName, nil
		
	default:
		// 其他系统：保持UTF-8
		return fileName, nil
	}
}

// GetSystemEncoding 获取系统默认编码
func (h *defaultEncodingHandler) GetSystemEncoding() string {
	switch runtime.GOOS {
	case "windows":
		return "UTF-8" // 现代Windows版本的Go运行时使用UTF-8
	case "darwin", "linux":
		return "UTF-8"
	default:
		return "UTF-8"
	}
}

// getEncoder 根据编码名称获取编码器
func (h *defaultEncodingHandler) getEncoder(encoding string) transform.Transformer {
	switch strings.ToUpper(encoding) {
	case "GBK", "GB2312":
		return simplifiedchinese.GBK.NewEncoder()
	case "BIG5":
		return traditionalchinese.Big5.NewEncoder()
	case "SHIFT_JIS", "SJIS":
		return japanese.ShiftJIS.NewEncoder()
	case "EUC-KR":
		return korean.EUCKR.NewEncoder()
	case "ISO-8859-1", "LATIN1":
		return charmap.ISO8859_1.NewEncoder()
	case "UTF-16":
		return utfencoding.UTF16(utfencoding.LittleEndian, utfencoding.UseBOM).NewEncoder()
	default:
		return nil
	}
}

// EncodeFileName 编码文件名
func (h *defaultEncodingHandler) EncodeFileName(fileName, encoding string) (string, error) {
	if encoding == "" || encoding == "UTF-8" {
		return fileName, nil
	}
	
	encoder := h.getEncoder(encoding)
	if encoder == nil {
		return fileName, fmt.Errorf("不支持的编码: %s", encoding)
	}
	
	encodedBytes, _, err := transform.Bytes(encoder, []byte(fileName))
	if err != nil {
		return fileName, err
	}
	
	return string(encodedBytes), nil
}

// RARDecodeFileName RAR文件名专用解码方法
func (h *defaultEncodingHandler) RARDecodeFileName(fileName string) (string, string, error) {
	// RAR特有的编码问题处理
	
	// 首先尝试修复明显损坏的文件名
	if repairedName, err := h.RepairCorruptedFileName(fileName); err == nil {
		if repairedName != fileName {
			// 文件名被修复，继续用修复后的名称进行解码
			fileName = repairedName
		}
	}
	
	// RAR v5格式特定处理：检查是否为损坏的UTF-8
	if utf8.ValidString(fileName) {
		// 检查是否包含常见的RAR编码错误模式
		if h.hasRAREncodingIssues(fileName) {
			// 尝试原始字节级别的修复
			return h.repairRAREncodingIssues(fileName)
		}
		// UTF-8有效且没有明显问题，直接返回
		return fileName, "UTF-8", nil
	}
	
	// 文件名不是有效UTF-8，尝试各种编码
	fileNameBytes := []byte(fileName)
	
	// RAR常用编码优先级（基于实际使用情况）
	rarEncodings := []string{
		"GBK",        // 中文RAR最常用
		"GB2312",     // 简体中文
		"BIG5",       // 繁体中文
		"SHIFT_JIS",  // 日文
		"EUC-KR",     // 韩文
		"CP866",      // 俄文（RAR原产地）
		"ISO-8859-1", // 西欧
		"CP1252",     // Windows西欧
	}
	
	for _, encoding := range rarEncodings {
		decoder := h.getDecoder(encoding)
		if decoder == nil {
			continue
		}
		
		// 尝试解码
		decodedBytes, _, err := transform.Bytes(decoder, fileNameBytes)
		if err != nil {
			continue
		}
		
		decodedName := string(decodedBytes)
		
		// 检查解码结果是否合理
		if h.isReasonableRARFileName(decodedName) {
			return decodedName, encoding, nil
		}
	}
	
	// 所有编码都失败，尝试最后的修复措施
	return h.fallbackRARRepair(fileName)
}

// RepairCorruptedFileName 修复损坏的文件名
func (h *defaultEncodingHandler) RepairCorruptedFileName(fileName string) (string, error) {
	if fileName == "" {
		return "", fmt.Errorf("空文件名")
	}
	
	// 移除或替换问题字符
	repairedName := fileName
	
	// 替换替换字符（U+FFFD）
	repairedName = strings.ReplaceAll(repairedName, "\uFFFD", "_")
	
	// 移除控制字符（除了基本的空白字符）
	var cleanRunes []rune
	for _, r := range repairedName {
		if r >= 32 || r == '\t' || r == '\n' || r == '\r' {
			cleanRunes = append(cleanRunes, r)
		} else {
			cleanRunes = append(cleanRunes, '_')
		}
	}
	repairedName = string(cleanRunes)
	
	// 如果文件名过长，截断
	const maxFileNameLength = 255
	if len(repairedName) > maxFileNameLength {
		// 保留扩展名
		ext := ""
		if idx := strings.LastIndex(repairedName, "."); idx > 0 && idx > len(repairedName)-10 {
			ext = repairedName[idx:]
			repairedName = repairedName[:idx]
		}
		
		maxBase := maxFileNameLength - len(ext)
		if len(repairedName) > maxBase {
			repairedName = repairedName[:maxBase]
		}
		repairedName += ext
	}
	
	return repairedName, nil
}

// hasRAREncodingIssues 检查是否存在RAR特有的编码问题
func (h *defaultEncodingHandler) hasRAREncodingIssues(fileName string) bool {
	// 检查常见的RAR编码错误模式
	
	// 模式1：连续的高位字符但看起来不像正常的中文/Unicode
	suspiciousPatterns := []string{
		"濂", "ョ", "壒", "鏇", "硷", "細", "寮", "€", "灞", "€",
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(fileName, pattern) {
			return true
		}
	}
	
	// 模式2：字符密度异常（可能的编码错误）
	runeCount := len([]rune(fileName))
	byteCount := len(fileName)
	if runeCount > 0 && float64(byteCount)/float64(runeCount) > 4.0 {
		// 平均每个字符超过4字节，可能有编码问题
		return true
	}
	
	return false
}

// repairRAREncodingIssues 修复RAR编码问题
func (h *defaultEncodingHandler) repairRAREncodingIssues(fileName string) (string, string, error) {
	// 尝试将当前字符串当作错误编码的字节序列处理
	fileNameBytes := []byte(fileName)
	
	// 尝试常见的编码修复
	repairEncodings := []string{"GBK", "GB2312", "BIG5"}
	
	for _, encoding := range repairEncodings {
		decoder := h.getDecoder(encoding)
		if decoder == nil {
			continue
		}
		
		// 先将UTF-8字符串转换为字节，然后作为目标编码解码
		decodedBytes, _, err := transform.Bytes(decoder, fileNameBytes)
		if err != nil {
			continue
		}
		
		repairedName := string(decodedBytes)
		if h.isReasonableRARFileName(repairedName) {
			return repairedName, encoding + "_REPAIRED", nil
		}
	}
	
	// 修复失败，返回清理后的原文件名
	cleanName, _ := h.RepairCorruptedFileName(fileName)
	return cleanName, "CLEANED", nil
}

// isReasonableRARFileName 检查RAR解码后的文件名是否合理
func (h *defaultEncodingHandler) isReasonableRARFileName(fileName string) bool {
	if !utf8.ValidString(fileName) {
		return false
	}
	
	if len(fileName) == 0 || len(fileName) > 500 {
		return false
	}
	
	// 检查是否包含合理的字符比例
	totalRunes := len([]rune(fileName))
	validChars := 0
	
	for _, r := range fileName {
		// 检查是否为合理的文件名字符
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || 
		   (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || 
		   r == ' ' || r == '(' || r == ')' || r == '[' || r == ']' ||
		   (r >= 0x4e00 && r <= 0x9fff) || // 中文字符范围
		   (r >= 0x3040 && r <= 0x309f) || // 日文平假名
		   (r >= 0x30a0 && r <= 0x30ff) || // 日文片假名
		   (r >= 0xac00 && r <= 0xd7af) {  // 韩文
			validChars++
		}
	}
	
	// 要求至少80%的字符是合理的
	return float64(validChars)/float64(totalRunes) >= 0.8
}

// fallbackRARRepair RAR文件名修复的最后手段
func (h *defaultEncodingHandler) fallbackRARRepair(fileName string) (string, string, error) {
	// 生成一个基于原文件名的安全文件名
	hash := fmt.Sprintf("%x", []byte(fileName))
	if len(hash) > 8 {
		hash = hash[:8]
	}
	
	// 尝试保留扩展名
	ext := ""
	if idx := strings.LastIndex(fileName, "."); idx > 0 {
		potentialExt := fileName[idx:]
		if len(potentialExt) <= 5 && len(potentialExt) > 1 {
			// 检查扩展名是否只包含ASCII字符
			isASCIIExt := true
			for _, r := range potentialExt {
				if r > 127 {
					isASCIIExt = false
					break
				}
			}
			if isASCIIExt {
				ext = potentialExt
			}
		}
	}
	
	fallbackName := fmt.Sprintf("rar_file_%s%s", hash, ext)
	return fallbackName, "FALLBACK", nil
}