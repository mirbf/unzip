package unzip

import (
	"fmt"
)

// FormatExtractorManager 格式解压器管理器接口
type FormatExtractorManager interface {
	// ExtractByFormat 根据格式解压文件
	ExtractByFormat(format ArchiveFormat, archivePath, outputDir string, config extractConfig, depth int) (*recursiveExtractResult, error)

	// GetExtractorForFormat 获取指定格式的解压器
	GetExtractorForFormat(format ArchiveFormat) (interface{}, error)

	// GetSupportedFormats 获取支持的格式列表
	GetSupportedFormats() []ArchiveFormat

	// ValidateArchiveByFormat 根据格式验证压缩文件
	ValidateArchiveByFormat(format ArchiveFormat, archivePath string) error
}

// defaultFormatExtractorManager 默认格式解压器管理器实现
type defaultFormatExtractorManager struct {
	zipExtractor    zipExtractor
	rarExtractor    rarExtractor
	sevenzExtractor sevenZExtractor
	tarExtractor    tarExtractor
}

// NewFormatExtractorManager 创建新的格式解压器管理器
func NewFormatExtractorManager() FormatExtractorManager {
	return &defaultFormatExtractorManager{
		zipExtractor:    newZipExtractor(),
		rarExtractor:    newRarExtractor(),
		sevenzExtractor: newSevenZExtractor(),
		tarExtractor:    newTarExtractor(),
	}
}

// ExtractByFormat 根据格式解压文件
func (m *defaultFormatExtractorManager) ExtractByFormat(
	format ArchiveFormat,
	archivePath, outputDir string,
	config extractConfig,
	depth int,
) (*recursiveExtractResult, error) {
	switch format {
	case FormatZIP:
		if m.zipExtractor == nil {
			return nil, NewExtractError(ErrUnsupportedFormat, "ZIP解压器未初始化", archivePath, nil)
		}
		return m.zipExtractor.Extract(archivePath, outputDir, config, depth)

	case FormatRAR:
		if m.rarExtractor == nil {
			return nil, NewExtractError(ErrUnsupportedFormat, "RAR解压器未初始化", archivePath, nil)
		}
		return m.rarExtractor.Extract(archivePath, outputDir, config, depth)

	case Format7Z:
		if m.sevenzExtractor == nil {
			return nil, NewExtractError(ErrUnsupportedFormat, "7Z解压器未初始化", archivePath, nil)
		}
		return m.sevenzExtractor.Extract(archivePath, outputDir, config, depth)

	case FormatTAR, FormatTARGZ, FormatTARBZ2:
		if m.tarExtractor == nil {
			return nil, NewExtractError(ErrUnsupportedFormat, "TAR解压器未初始化", archivePath, nil)
		}
		return m.tarExtractor.Extract(archivePath, outputDir, config, depth)

	default:
		return nil, NewExtractError(
			ErrUnsupportedFormat,
			fmt.Sprintf("不支持的压缩格式: %s", format),
			archivePath,
			nil,
		)
	}
}

// GetExtractorForFormat 获取指定格式的解压器
func (m *defaultFormatExtractorManager) GetExtractorForFormat(format ArchiveFormat) (interface{}, error) {
	switch format {
	case FormatZIP:
		if m.zipExtractor == nil {
			return nil, fmt.Errorf("ZIP解压器未初始化")
		}
		return m.zipExtractor, nil

	case FormatRAR:
		if m.rarExtractor == nil {
			return nil, fmt.Errorf("RAR解压器未初始化")
		}
		return m.rarExtractor, nil

	case Format7Z:
		if m.sevenzExtractor == nil {
			return nil, fmt.Errorf("7Z解压器未初始化")
		}
		return m.sevenzExtractor, nil

	case FormatTAR, FormatTARGZ, FormatTARBZ2:
		if m.tarExtractor == nil {
			return nil, fmt.Errorf("TAR解压器未初始化")
		}
		return m.tarExtractor, nil

	default:
		return nil, fmt.Errorf("不支持的压缩格式: %s", format)
	}
}

// GetSupportedFormats 获取支持的格式列表
func (m *defaultFormatExtractorManager) GetSupportedFormats() []ArchiveFormat {
	formats := make([]ArchiveFormat, 0)

	// 添加内置格式
	if m.zipExtractor != nil {
		formats = append(formats, FormatZIP)
	}
	if m.rarExtractor != nil {
		formats = append(formats, FormatRAR)
	}
	if m.sevenzExtractor != nil {
		formats = append(formats, Format7Z)
	}
	if m.tarExtractor != nil {
		formats = append(formats, FormatTAR, FormatTARGZ, FormatTARBZ2)
	}

	return formats
}

// ValidateArchiveByFormat 根据格式验证压缩文件
func (m *defaultFormatExtractorManager) ValidateArchiveByFormat(format ArchiveFormat, archivePath string) error {
	switch format {
	case FormatZIP:
		if m.zipExtractor == nil {
			return NewExtractError(ErrUnsupportedFormat, "ZIP解压器未初始化", archivePath, nil)
		}
		return m.zipExtractor.ValidateArchive(archivePath)

	case FormatRAR:
		if m.rarExtractor == nil {
			return NewExtractError(ErrUnsupportedFormat, "RAR解压器未初始化", archivePath, nil)
		}
		return m.rarExtractor.ValidateArchive(archivePath)

	case Format7Z:
		if m.sevenzExtractor == nil {
			return NewExtractError(ErrUnsupportedFormat, "7Z解压器未初始化", archivePath, nil)
		}
		return m.sevenzExtractor.ValidateArchive(archivePath)

	case FormatTAR, FormatTARGZ, FormatTARBZ2:
		if m.tarExtractor == nil {
			return NewExtractError(ErrUnsupportedFormat, "TAR解压器未初始化", archivePath, nil)
		}
		return m.tarExtractor.ValidateArchive(archivePath)

	default:
		return NewExtractError(
			ErrUnsupportedFormat,
			fmt.Sprintf("不支持的压缩格式: %s", format),
			archivePath,
			nil,
		)
	}
}