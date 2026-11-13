package nubulus

import (
	"context"
	"net/http"
	"time"
)

// AccountsClient is accounts-api.
type AccountsClient struct {
	service
}

// Account is an account as accounts-api returns it.
type Account struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// Membership is one entry of GET /api/v1/accounts/me: an account and the
// caller's role in it ("owner", "admin", "member", "viewer").
type Membership struct {
	Account *Account `json:"account"`
	Role    string   `json:"role"`
}

// Me returns the accounts the caller belongs to.
func (c *AccountsClient) Me(ctx context.Context) ([]Membership, error) {
	var out struct {
		Data []Membership `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/accounts/me", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}
