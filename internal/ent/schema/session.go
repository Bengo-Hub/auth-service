package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Session represents long-lived refresh sessions.
type Session struct {
	ent.Schema
}

// Fields of the Session.
func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.UUID("tenant_id", uuid.UUID{}).
			Optional(),
		field.String("client_id").
			Optional(),
		field.String("session_type").
			Default("user"),
		field.String("status").
			Default("active"),
		field.String("refresh_token_hash").
			Sensitive().
			NotEmpty(),
		field.Time("issued_at").
			Default(time.Now).
			Immutable(),
		field.Time("expires_at"),
		field.Time("revoked_at").
			Optional(),
		field.String("revocation_reason").
			Optional(),
		field.String("ip_address").
			Optional(),
		field.String("user_agent").
			Optional(),
		field.JSON("metadata", map[string]any{}).
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the Session.
func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Field("user_id").
			Ref("sessions").
			Required(),
	}
}
