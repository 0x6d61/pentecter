package tools

import "context"

// InternalTool は外部プロセスを起動せず Go 内部で実行されるツールのインターフェース。
// CommandRunner が binary 名で内部ツールを検出し、sh -c の代わりにこのインターフェースを呼ぶ。
type InternalTool interface {
	// Execute はツールを実行し、出力を lineCh 経由でストリーム返却する。
	// 戻り値は (exitCode, error)。lineCh は呼び出し元が close する。
	Execute(ctx context.Context, args []string, lineCh chan<- OutputLine) (int, error)
}
