# Unzip - Go单文件解压库

一个专注于单文件解压的Go语言库，支持多种压缩格式的递归解压功能。

## 特性

- 🗜️ **多格式支持**: ZIP、RAR、7Z、TAR、TAR.GZ、TAR.BZ2等主流压缩格式
- 🔄 **递归解压**: 自动检测并解压嵌套的压缩包
- 🔐 **密码支持**: 支持加密压缩包的密码解压
- 🛡️ **安全防护**: 内置路径遍历攻击防护和资源限制
- 📝 **详细错误**: 提供详细的错误信息和类型分类
- 🎯 **单文件专用**: 专为单文件解压场景优化，不移动原文件
- 🧪 **完整测试**: 包含全面的单元测试和集成测试

## 安装

```bash
go get github.com/mirbf/unzip
```

## 快速开始

### 基本用法

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/mirbf/unzip"
)

func main() {
    // 基本解压
    result, err := unzip.Extract("/path/to/archive.zip", nil)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("解压成功: %d个文件\n", result.FilesCount)
    fmt.Printf("解压到: %s\n", result.ExtractedTo)
    fmt.Printf("总大小: %d字节\n", result.TotalSize)
}
```

### 带选项的解压

```go
options := &unzip.ExtractOptions{
    OutputDir:   "/path/to/output",
    Passwords:   []string{"password123", "secret"},
    MaxDepth:    5,
    MaxFileSize: 100 * 1024 * 1024, // 100MB
    Overwrite:   true,
    AutoRename:  true,
}

result, err := unzip.Extract("/path/to/encrypted.zip", options)
```

### 快速解压

```go
// 快速解压到默认目录
outputDir, err := unzip.QuickExtract("/path/to/archive.zip")
```

## API文档

### 主要函数

#### Extract

主要的解压函数，支持所有压缩格式的解压。

```go
func Extract(archivePath string, options *ExtractOptions) (*ExtractResult, error)
```

#### QuickExtract

快速解压函数，使用默认设置解压到同名目录。

```go
func QuickExtract(archivePath string) (string, error)
```

#### IsSupported

检查文件是否为支持的压缩格式。

```go
func IsSupported(archivePath string) (bool, string)
```

### 核心类型

#### ExtractOptions

解压配置选项。

```go
type ExtractOptions struct {
    OutputDir        string           // 输出目录
    Passwords        []string         // 密码列表
    ProgressCallback ProgressCallback // 进度回调
    MaxDepth         int              // 最大递归深度
    MaxFileSize      int64            // 单文件大小限制
    Timeout          time.Duration    // 超时时间
    Overwrite        bool             // 覆盖现有文件
    AutoRename       bool             // 自动重命名重复文件
    CleanNested      bool             // 清理中间压缩包文件
}
```

#### ExtractResult

解压结果信息。

```go
type ExtractResult struct {
    Success      bool          // 是否成功
    ExtractedTo  string        // 解压到的目录
    FilesCount   int           // 解压的文件数量
    TotalSize    int64         // 总大小(字节)
    ProcessTime  time.Duration // 处理时间
    PasswordUsed string        // 使用的密码(如果有)
    Warnings     []string      // 警告信息
    NestedCount  int           // 嵌套压缩包数量
    CleanedCount int           // 清理的中间压缩包数量
}
```

### 错误类型

库定义了详细的错误类型用于错误处理：

- `ErrUnsupportedFormat`: 不支持的压缩格式
- `ErrPasswordRequired`: 需要密码
- `ErrInvalidPassword`: 密码错误
- `ErrCorruptedArchive`: 压缩包损坏
- `ErrPathTraversal`: 路径遍历攻击
- `ErrFileTooLarge`: 文件过大
- `ErrMaxDepthExceeded`: 超过最大递归深度
- `ErrTimeout`: 操作超时

## 支持的格式

| 格式 | 扩展名 | 密码支持 | 递归支持 |
|------|--------|----------|----------|
| ZIP | .zip | ✅ | ✅ |
| RAR | .rar | ✅ | ✅ |
| 7-Zip | .7z | ✅ | ✅ |
| TAR | .tar | ❌ | ✅ |
| TAR.GZ | .tar.gz, .tgz | ❌ | ✅ |
| TAR.BZ2 | .tar.bz2, .tbz2 | ❌ | ✅ |

## 安全考虑

- **路径遍历防护**: 自动检测和阻止 `../` 等路径遍历攻击
- **资源限制**: 支持文件大小和总大小限制
- **超时控制**: 防止恶意压缩包导致的无限循环
- **深度限制**: 防止过深的嵌套导致栈溢出

## 性能优化

- **流式处理**: 大文件采用流式读写，减少内存占用
- **格式检测**: 快速文件头检测，避免不必要的解压尝试
- **缓存机制**: 智能缓存常用解压器实例
- **并发安全**: 所有操作都是并发安全的

## 测试

运行所有测试：

```bash
go test ./...
```

运行基准测试：

```bash
go test -bench=. ./...
```

生成测试覆盖率报告：

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 示例

查看 `examples/` 目录获取更多使用示例：

- `basic/`: 基本解压示例
- `password/`: 密码保护压缩包解压
- `recursive/`: 递归解压示例
- `config/`: 高级配置示例

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License