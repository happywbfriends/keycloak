package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type Middleware struct {
	s *Service
}

func NewMiddleware(service *Service) *Middleware {
	return &Middleware{
		s: service,
	}
}

type link401 struct {
	RedirectURL string `json:"redirect_url"`
}

func (m *Middleware) AuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.s.config.IsEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// 1. Проверяем токен в куках
		if m.isTokenInCookiesOk(r) {
			next.ServeHTTP(w, r)
			return
		}

		// 2. Если нет кук или произошла ошибка при проверке токена, проверим, может, это запрос после редиректа от KeyCloak
		// 2.1. Проверим параметры от KeyCloak
		params := m.getParams(r)
		if params.Code == "" || params.State == "" || !m.s.CheckState(params.State) {
			// Это не запрос после редиректа от KeyCloak, отправляем юзера на аутентификацию
			m.returnRedirectJSON(w, r)
			return
		}

		// 2.2. Пробуем получить токен...
		token, err := m.s.GetToken(r.Context(), params.Code, m.getRedirectURI(r))
		if err != nil {
			m.s.logger.Errorf(err.Error())
			m.returnRedirectJSON(w, r)
			return
		}

		// 2.3. Получили токен. Проверяем...
		var parsedToken *ParsedToken
		r, parsedToken, err = m.checkAndSaveToken(r, token.IDToken)
		if err != nil {
			m.s.logger.Errorf(err.Error())
			m.returnRedirectJSON(w, r)
			return
		}

		// 2.4. Отличный токен
		// * сохраним юзерские куки
		err = m.setUserCookies(w, r, parsedToken, token.ExpiresIn)
		if err != nil {
			m.s.logger.Errorf(err.Error())
			return
		}
		// * сохраним токен в хранилище
		m.s.storage.Set(r.Context(), parsedToken.UUID, token.IDToken, token.ExpiresIn)
		// * отредиректим юзера куда надо
		backURL := m.getBackURL(r)
		http.Redirect(w, r, backURL, http.StatusTemporaryRedirect)
	})
}

func (m *Middleware) setUserCookies(w http.ResponseWriter, r *http.Request, parsedToken *ParsedToken, maxage int) error {
	m.setCookie(w, r, CookieName_UserEmail, fmt.Sprintf("%s", url.QueryEscape(parsedToken.UserEmail)), maxage, false)
	m.setCookie(w, r, CookieName_UserName, url.QueryEscape(parsedToken.UserName), maxage, false)
	m.setCookie(w, r, CookieName_UUID, url.QueryEscape(parsedToken.UUID), maxage, true)
	return nil
}

func (m *Middleware) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxage int, isHttpOnly bool) {
	ck := &http.Cookie{
		Name:     name,
		Domain:   r.Host,
		Path:     CookiePath,
		HttpOnly: isHttpOnly,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Value:    value,
		MaxAge:   maxage,
	}
	http.SetCookie(w, ck)
}

func (m *Middleware) getParams(r *http.Request) (params *getTokenParams) {
	params = &getTokenParams{}
	q := r.URL.Query()
	params.State = q.Get(ParamName_State)
	params.Code = q.Get(ParamName_Code)
	params.SessionState = q.Get(ParamName_SessionState)
	return params
}

func (m *Middleware) checkAndSaveToken(r *http.Request, token string) (*http.Request, *ParsedToken, error) {
	parsedToken, err := m.s.parseToken(r, token)
	if err != nil {
		return r, nil, err
	}

	accessToken, claims, err := m.s.DecodeAccessToken(r.Context(), token)
	if err != nil {
		return r, nil, errors.WithStack(err)
	}
	if !accessToken.Valid {
		return r, nil, errors.New("token is not valid")
	}

	r = r.WithContext(context.WithValue(r.Context(), CtxUserValue_Claims, claims))

	str := fmt.Sprintf("%s", parsedToken.UserEmail)
	r.Header.Set("X-User-Email", str)

	return r, parsedToken, nil
}

func (m *Middleware) returnRedirectJSON(w http.ResponseWriter, r *http.Request) {
	backURL := m.getRedirectURI(r)
	u := m.s.GenerateAuthLink(backURL)
	data, _ := json.Marshal(link401{RedirectURL: u})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write(data)
}

// getRedirectURI возвращает URL, на который надо отредиректить пользователя после успешной аутентификации в Keycloak
// Код получит токен из URL, запишет его в куку и отредиректит юзера на URL основного сервиса
func (m *Middleware) getRedirectURI(r *http.Request) string {
	// Если передан заголовок X-Original-Request-Uri, то берем его.
	// Он м.б. установлен даунстримом, если сервис подключен с помощью proxy_pass в nginx,
	// в этом случае нам важно вернуть пользователя именно по этому URI.
	uri := r.Header.Get("X-Original-Request-Uri")
	if uri == "" {
		uri = r.URL.RequestURI()
	}

	uri = m.addBackURL(r, uri)

	return "https://" + strings.Trim(r.Host, "/") + uri
}

// addBackURL добавляет к URL параметр backURL - это URL основного сервиса,
// куда надо отредиректить пользователя после установки куки.
// Берется из реферера.
func (m *Middleware) addBackURL(r *http.Request, uri string) string {
	ref := r.Referer()
	if ref == "" {
		return uri
	}

	param := fmt.Sprintf("%s=%s", ParamName_BackURL, url.QueryEscape(ref))
	if strings.Contains(uri, "?") {
		uri += "&" + param
	} else {
		uri += "?" + param
	}

	return uri
}

// getBackURL возвращает backURL, который берет либо из GET-параметра, либо из конфига
func (m *Middleware) getBackURL(r *http.Request) string {
	q := r.URL.Query()
	u := q.Get(ParamName_BackURL)
	if u == "" {
		return m.s.config.BackURL
	}

	return u
}

// isTokenInCookiesOk возвращает true, если:
// * в куках нашелся UUID токена
// * в редисе нашелся соответствующий ему валидный токен
func (m *Middleware) isTokenInCookiesOk(r *http.Request) bool {
	uuidCk, err := r.Cookie(CookieName_UUID)
	if err != nil {
		// Кука не найдена
		return false
	}

	uuidCkStr, err := url.QueryUnescape(uuidCk.Value)
	if err != nil {
		// Кука найдена, но при декодировании произошла ошибка
		m.s.logger.Errorf(err.Error())
		return false
	}

	// В куках нашелся UUID, проверяем хранилище, есть ли для него токен
	tokenCk, found := m.s.storage.Get(r.Context(), uuidCkStr)
	if !found {
		return false
	}

	// Проверяем токен
	r, _, err = m.checkAndSaveToken(r, tokenCk)
	if err != nil {
		m.s.logger.Errorf(err.Error())
		return false
	}

	return true
}
