// 用户条目写操作(web 层消费;治理语义收口,审计在 web 层落)。
// 0.27.1-kb-simplify:enabled 概念整体退役——条目不再有启停(生效以案件勾选
// 为准),CreateUser/UpdateUser 不再收 enabled 参数;kb_entries.enabled 列
// 存量保留恒写 true,留待后续迁移清理;内置启停(SetBuiltinEnabled)随之下线。
package kb

import (
	"context"
)

// CreateUser 新建用户条目(校验同内置装载口径;id/时间回写)。
func (s *Service) CreateUser(ctx context.Context, actor, title, content string,
	appliesTo []string) (*Entry, error) {

	e := &Entry{Title: title, Content: content, AppliesTo: appliesTo,
		Source: SourceUser, Enabled: true, CreatedBy: actor}
	e.ID = "user-draft" // 校验用占位(落库后由 PG 回写真实 UUID)
	if err := validate(e); err != nil {
		return nil, err
	}
	e.ID = ""
	if err := s.store.CreateKB(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}

// UpdateUser 改用户条目(ok=false=无此条目;调用方负责确认不是内置条目)。
func (s *Service) UpdateUser(ctx context.Context, id, title, content string,
	appliesTo []string) (*Entry, bool, error) {

	e := &Entry{ID: id, Title: title, Content: content, AppliesTo: appliesTo,
		Source: SourceUser, Enabled: true}
	if err := validate(e); err != nil {
		return nil, false, err
	}
	ok, err := s.store.UpdateKB(ctx, e)
	if err != nil || !ok {
		return nil, ok, err
	}
	return e, true, nil
}

// DeleteUser 删用户条目(ok=false=无此条目;硬删,历史在审计链)。
func (s *Service) DeleteUser(ctx context.Context, id string) (bool, error) {
	return s.store.DeleteKB(ctx, id)
}
