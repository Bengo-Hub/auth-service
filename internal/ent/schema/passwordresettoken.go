package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// PasswordResetToken stores password reset secrets.
type PasswordResetToken struct {
	ent.Schema
}

// Fields of PasswordResetToken.
func (PasswordResetToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("token_hash").
			Sensitive().
			NotEmpty().
			Immutable(),
		field.Time("expires_at"),
		field.Time("used_at").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of PasswordResetToken.
func (PasswordResetToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Field("user_id").
			Ref("password_reset_tokens").
			Unique().
			Required(),
	}
}
