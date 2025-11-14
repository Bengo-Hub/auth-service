package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// LoginAttempt captures authentication attempts for auditing/risk.
type LoginAttempt struct {
	ent.Schema
}

// Fields of LoginAttempt.
func (LoginAttempt) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Optional(),
		field.UUID("user_id", uuid.UUID{}).
			Optional(),
		field.String("email").
			Default(""),
		field.String("ip_address").
			Optional(),
		field.String("user_agent").
			Optional(),
		field.Bool("success").
			Default(false),
		field.String("failure_reason").
			Optional(),
		field.Time("occurred_at").
			Default(time.Now).
			Immutable(),
	}
}
