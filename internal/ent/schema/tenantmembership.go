package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// TenantMembership represents membership relationships.
type TenantMembership struct {
	ent.Schema
}

// Fields of the TenantMembership.
func (TenantMembership) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.UUID("tenant_id", uuid.UUID{}),
		field.JSON("roles", []string{}).
			Optional(),
		field.String("status").
			Default("active"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the TenantMembership.
func (TenantMembership) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("memberships").
			Field("user_id").
			Required(),
		edge.From("tenant", Tenant.Type).
			Ref("memberships").
			Field("tenant_id").
			Required(),
	}
}
