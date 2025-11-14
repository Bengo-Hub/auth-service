package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// UserIdentity stores linked external identity providers.
type UserIdentity struct {
	ent.Schema
}

// Fields of the UserIdentity.
func (UserIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("provider").
			NotEmpty(),
		field.String("provider_subject").
			NotEmpty(),
		field.String("provider_email").
			NotEmpty(),
		field.Bool("email_verified").
			Default(false),
		field.String("access_token").
			Optional().
			Sensitive(),
		field.String("refresh_token").
			Optional().
			Sensitive(),
		field.Time("token_expiry").
			Optional(),
		field.String("scope").
			Optional(),
		field.JSON("profile", map[string]any{}).
			Optional(),
		field.Time("linked_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the UserIdentity.
func (UserIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("identities").
			Field("user_id").
			Required().
			Unique(),
	}
}

// Indexes sets unique constraints.
func (UserIdentity) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider", "provider_subject").
			Unique(),
		index.Fields("provider", "provider_email"),
	}
}
