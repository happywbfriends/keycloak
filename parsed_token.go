package keycloak

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"net/http"
)

type ParsedToken struct {
	Claims    *jwt.MapClaims
	UserEmail string
	UserName  string
	UUID      string
}

func (s *Service) parseToken(r *http.Request, token string) (*ParsedToken, error) {
	accessToken, claims, err := s.DecodeAccessToken(r.Context(), token)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !accessToken.Valid {
		return nil, errors.Errorf("token is not valid: %v", token)
	}

	email, ok := (*claims)["email"]
	if !ok {
		return nil, errors.Errorf("token claims do not contain an email: %v", *claims)
	}

	firstname, ok := (*claims)["given_name"]
	if !ok {
		return nil, errors.Errorf("token claims do not contain a given_name: %v", *claims)
	}
	surname, ok := (*claims)["family_name"]
	if !ok {
		return nil, errors.Errorf("token claims do not contain a family_name: %v", *claims)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	t := ParsedToken{
		UUID:      fmt.Sprintf("%s_%s_%s", CookieName_UUID, email, id),
		Claims:    claims,
		UserEmail: fmt.Sprintf("%s", email),
		UserName:  fmt.Sprintf("%s %s", firstname, surname),
	}

	return &t, nil
}
