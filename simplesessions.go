package sessionManager

import (
	"time"
	"errors"
	"net/http"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// SessionOptions
// Used to configure the session manager
// Users should create their own session object and pass it as an argument...
// ...to NewSessionManager
// @param CookieName: 	The name of the cookie
// @param Salt:			key to feed into the hash algorithm
// @param Timeout:		multiplies a 1 minuet timeout duration
type SessionOptions struct {
	CookieName	string
	Salt		string
	Timeout		time.Duration
}

// Session
type Session struct {
	Id 		string
	Expires	time.Time
	Uid		int
	Cookie 	*http.Cookie
}

// Session Manager
// Composed of our session options and an array of sessions
type SessionManager struct {
	Options		SessionOptions
	Sessions 	[]Session
}

// === New Session Manager ===
// Constructor for the Session Manager
// @param siteName: used to identify the session
func NewSessionManager(opts SessionOptions) *SessionManager {
	sm := SessionManager{}
	sm.Options = opts
	return &sm
}

/* ===== Public Methods ==== */

// === GetSession ===
// Return a session matching an id and nil error when found
// Returns a nil pointer value and an error when a session is not found
// Removes expired sessions
// @param r: an id to check
func (sm *SessionManager) GetSession(id string) (*Session, error) {
	var err error
	for _, s := range sm.Sessions {
		if s.Id == id && s.Expires.After(time.Now()) {
			return &s, err
		}
		sm.ClearExpired()
	}
	err = errors.New("No session found")
	return nil, err
}

// === GetUserSession ===
// Return the id of a session that matches a user id
// Returns a non nil error on fail
// @param uid:	the id of the user we want to get a session for
func (sm *SessionManager) GetUserSession(uid int) (string, error) {
	var err error
	var sid string
	var found bool
	for _, s := range sm.Sessions {
		if s.Uid == uid {
			sid = s.Id
			found = true
		}
	}
	if !found {
		err = errors.New("No session found for a user with this id")
	}
	return sid, err
}

// === Make Session ===
// Make a new session and return an error, nil error is success case
// Session Uid -1 indicates a guest session
// Returns the id of the new session
// @param id:	the id of the user to create the session for,
func (sm *SessionManager) MakeSession(uid int) string {
	s := Session{}
	s.Id = newSID(sm.Options.Salt)
	s.Expires = time.Now().Add(sm.Options.Timeout * time.Minute)
	s.Uid = uid
	sm.Sessions = append(sm.Sessions, s)
	return s.Id
}

// === Delete Session ===
// Remove a session matching an id
// @param id: the id for the sesison to delete
func (sm *SessionManager) DeleteSession(sid string) {
	for i, s := range sm.Sessions {
		if s.Id == sid {
			sm.Sessions = append(sm.Sessions[:i], sm.Sessions[i+1:]...)
		}
	}
}

// === Set Session ===
// Create and set a cookie for the specified session
// @param w: 	the writer interface
// @param id: 	the session id to set a cookie for
func (sm *SessionManager) SetCookie(w http.ResponseWriter, s *Session) {
	c := s.Cookie
	c.Name = sm.Options.CookieName
	c.Value = s.Id
	c.Expires = s.Expires
	http.SetCookie(w, c)
}

// === Clear Expired Session ===
// Go through the session table and clear out all expired sessions
// Returns an int value of the number of sessions cleared
func (sm *SessionManager) ClearExpired() int {
	var count int
	for i, s := range sm.Sessions {
		if s.Expires.Before(time.Now()) {
			sm.Sessions = append(sm.Sessions[:i], sm.Sessions[i+1:]...)
			count++
		}
	}
	return count
}

/* ===== Private Functions ===== */

// === newSID ===
// Return a string for the new session id
// @param salt: value written to byte slice with time.now to randomize output
func newSID(salt string) string {
	key := []byte(salt + time.Now().String())
	h := hmac.New(sha256.New, key)
	h.Write([]byte(key))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
