package unzip

import (
	"fmt"
	"strings"
)

// 🚀 优化1：快速检验是否真需要密码
// quickPasswordCheck 快速检查文件是否真的需要密码
func (pm *defaultPasswordManager) quickPasswordCheck(extractor interface{}, archivePath, outputDir string, config extractConfig, depth int) (bool, error) {
	// 尝试无密码解压
	tryConfig := config
	tryConfig.Password = ""
	tryConfig.Passwords = []string{""}
	
	_, err := pm.tryExtractWithPassword(extractor, archivePath, outputDir, tryConfig, depth)
	
	if err == nil {
		// 无密码解压成功，说明不需要密码
		return false, nil
	}
	
	// 检查错误类型
	if extractErr, ok := err.(*ExtractError); ok {
		switch extractErr.Type {
		case ErrPasswordRequired, ErrInvalidPassword:
			// 明确需要密码
			return true, nil
		case ErrCorruptedArchive, ErrUnsupportedFormat, ErrInvalidPath:
			// 这些错误不是密码问题，直接返回错误
			return false, err
		default:
			// 其他错误，检查是否是密码相关
			return pm.isPasswordError(err), nil
		}
	}
	
	// 默认假设需要密码
	return pm.isPasswordError(err), nil
}

// extractWithoutPassword 无密码解压（当确认不需要密码时使用）
func (pm *defaultPasswordManager) extractWithoutPassword(extractor interface{}, archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, string, error) {
	config.Password = ""
	config.Passwords = []string{""}
	
	result, err := pm.tryExtractWithPassword(extractor, archivePath, outputDir, config, depth)
	return result, "", err
}

// passwordManager 密码管理器接口
type passwordManager interface {
	// tryPasswords 尝试多个密码解压
	tryPasswords(extractor interface{}, archivePath, outputDir string, passwords []string, config extractConfig, depth int) (*recursiveExtractResult, string, error)

	// getBuiltinPasswords 获取内置密码列表
	getBuiltinPasswords() []string

	// buildPasswordList 构建完整的密码尝试列表
	buildPasswordList(userPasswords []string, includeBuiltin, unused bool) []string

}

// defaultPasswordManager 默认密码管理器实现
type defaultPasswordManager struct {
	formatManager FormatExtractorManager
}

// newPasswordManager 创建新的密码管理器
func newPasswordManager() passwordManager {
	return &defaultPasswordManager{
		formatManager: NewFormatExtractorManager(),
	}
}


// tryPasswords 尝试多个密码解压
func (pm *defaultPasswordManager) tryPasswords(
	extractor interface{},
	archivePath, outputDir string,
	passwords []string,
	config extractConfig,
	depth int,
) (*recursiveExtractResult, string, error) {

	// 🚀 优化1：先检验是否真需要密码
	needsPassword, err := pm.quickPasswordCheck(extractor, archivePath, outputDir, config, depth)
	if err != nil {
		return nil, "", err
	}
	if !needsPassword {
		// 文件不需要密码，直接解压
		return pm.extractWithoutPassword(extractor, archivePath, outputDir, config, depth)
	}

	// 调试信息
	// fmt.Printf("🔍 [DEBUG] tryPasswords被调用，解压器类型: %T\n", extractor)
	
	// 如果没有提供密码列表，使用默认列表
	if len(passwords) == 0 {
		passwords = pm.buildPasswordList(config.Passwords, true, true)
	}
	
	// fmt.Printf("🔍 [DEBUG] 准备尝试 %d 个密码\n", len(passwords))
	if len(passwords) > 0 {
		previewCount := len(passwords)
		if previewCount > 5 {
			previewCount = 5
		}
		// fmt.Printf("🔍 [DEBUG] 前%d个密码: %v\n", previewCount, passwords[:previewCount])
	}

	var lastErr error

	// 逐个尝试密码
	for i, password := range passwords {
		// fmt.Printf("🔍 [DEBUG] 尝试密码 %d/%d: %s\n", i+1, len(passwords), func(pwd string) string {
		// 	if pwd == "" { return "<空密码>" }
		// 	return "***"
		// }(password))
		
		// 更新配置中的密码
		tryConfig := config
		tryConfig.Password = password
		tryConfig.Passwords = []string{password}

		// 根据解压器类型尝试解压
		result, err := pm.tryExtractWithPassword(extractor, archivePath, outputDir, tryConfig, depth)

		if err == nil {
			// 解压成功
			return result, password, nil
		}

		// 检查错误类型
		if extractErr, ok := err.(*ExtractError); ok {
			switch extractErr.Type {
			case ErrPasswordRequired, ErrInvalidPassword:
				// 密码错误，继续尝试下一个
				lastErr = err
				continue
			case ErrInternalError:
				// 内部错误可能是密码问题，通过isPasswordError进一步检查
				if pm.isPasswordError(err) {
					lastErr = err
					continue
				}
				// 如果不是密码错误，直接返回
				return nil, password, err
			default:
				// 其他错误，直接返回
				return nil, password, err
			}
		}

		// 非密码相关错误，直接返回
		if !pm.isPasswordError(err) {
			return nil, password, err
		}

		lastErr = err

		// 🚀 优化：缩短进度报告间隔
		if i > 0 && i%3 == 0 {
			fmt.Printf("已尝试 %d 个密码...\n", i+1)
		}
	}

	// 所有密码都失败了
	return nil, "", NewExtractError(
		ErrInvalidPassword,
		fmt.Sprintf("尝试了 %d 个密码都无法解压", len(passwords)),
		archivePath,
		lastErr,
	)
}

// getBuiltinPasswords 获取内置密码列表 (🚀 优化：合并默认和常用密码)
func (pm *defaultPasswordManager) getBuiltinPasswords() []string {
	return []string{
		// 🥇 第一优先级：最常用密码
		"1",         // 用户要求：必须包含"1"并且排前面
		"",          // 无密码（最常见）
		"123456",    // 最常用数字密码
		"123",       // 简单数字
		
		// 🥈 第二优先级：其他高频密码
		"password",  // 最常用英文密码
		"密码",       // 中文密码
		"12345",     // 简单数字序列
		"1234",      // 更简单数字
		
		// 🥉 第三优先级：补充密码
		"0",         // 零
		"admin",     // 管理员密码
		"123456789", // 长数字序列
		"qwerty",    // 键盘序列
	}
}

// buildPasswordList 构建完整的密码尝试列表 (🚀 优化：简化逻辑)
func (pm *defaultPasswordManager) buildPasswordList(userPasswords []string, includeBuiltin, _ bool) []string {
	var passwords []string

	// 1. 用户提供的密码（优先级最高）
	passwords = append(passwords, userPasswords...)

	// 2. 内置密码列表（如果需要）
	if includeBuiltin {
		passwords = append(passwords, pm.getBuiltinPasswords()...)
	}

	// 去重
	return RemoveDuplicateStrings(passwords)
}


// 私有方法

// tryExtractWithPassword 尝试用指定密码解压
func (pm *defaultPasswordManager) tryExtractWithPassword(
	extractor interface{},
	archivePath, outputDir string,
	config extractConfig,
	depth int,
) (*recursiveExtractResult, error) {

	// 根据解压器类型调用对应的解压方法
	switch e := extractor.(type) {
	case zipExtractor:
		return e.Extract(archivePath, outputDir, config, depth)
	case rarExtractor:
		return e.Extract(archivePath, outputDir, config, depth)
	case sevenZExtractor:
		return e.Extract(archivePath, outputDir, config, depth)
	case tarExtractor:
		return e.Extract(archivePath, outputDir, config, depth)
	default:
		return nil, NewExtractError(ErrInternalError, "不支持的解压器类型", archivePath, nil)
	}
}

// isPasswordError 检查是否为密码相关错误
func (pm *defaultPasswordManager) isPasswordError(err error) bool {
	if err == nil {
		return false
	}

	errorMsg := strings.ToLower(err.Error())

	// 检查常见的密码错误关键词
	passwordKeywords := []string{
		"password",
		"encrypted",
		"wrong password",
		"invalid password",
		"needs password",
		"requires password",
		"密码",
		"加密",
		"flate: corrupt input",     // ZIP文件密码错误时的常见错误
		"corrupt input",            // 压缩流损坏通常是密码问题
		"checksum error",           // 校验和错误可能是密码问题
	}

	for _, keyword := range passwordKeywords {
		if strings.Contains(errorMsg, keyword) {
			return true
		}
	}

	// 检查ExtractError类型
	if extractErr, ok := err.(*ExtractError); ok {
		return extractErr.Type == ErrPasswordRequired || extractErr.Type == ErrInvalidPassword
	}

	return false
}




// GetGlobalPasswordManager 获取全局密码管理器
func GetGlobalPasswordManager() *defaultPasswordManager {
	return &defaultPasswordManager{}
}

