package unzip

// ProgressReporter 进度报告器接口（简化版本）
type ProgressReporter interface {
	// 基本进度报告
	OnFileProgress(current, total int64, filename string)
}

// SimpleProgressReporter 简单进度报告器
type SimpleProgressReporter struct {
	callback ProgressCallback
}

// NewSimpleProgressReporter 创建简单进度报告器
func NewSimpleProgressReporter(callback ProgressCallback) *SimpleProgressReporter {
	return &SimpleProgressReporter{
		callback: callback,
	}
}

// OnFileProgress 报告文件进度
func (r *SimpleProgressReporter) OnFileProgress(current, total int64, filename string) {
	if r.callback != nil {
		r.callback(current, total, filename)
	}
}