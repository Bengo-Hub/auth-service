package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// AuditLog stores immutable security/audit events.
type AuditLog struct {
	ent.Schema
}

// Fields of the AuditLog.
func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Optional(),
		field.UUID("user_id", uuid.UUID{}).
			Optional(),
		field.String("action").
			NotEmpty(),
		field.String("resource_type").
			Optional(),
		field.String("resource_id").
			Optional(),
		field.String("ip_address").
			Optional(),
		field.String("user_agent").
			Optional(),
		field.JSON("context", map[string]any{}).
			Optional(),
		field.Time("occurred_at").
			Default(time.Now).
			Immutable(),
	}
}
