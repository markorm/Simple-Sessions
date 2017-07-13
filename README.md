## Simple Sessions

 A session management library for go:

  * Create sessoions
  * Manage Session Cookies
  * Look up session data
  * Remove and Edit sessions
  * Remove expired sessions in routine process

 ##### Using Logger


 ```javascript
 import "github.com/markorm/simplesessions"

 // some options
 options := simplesession.SessionOptions {
 	CookieName: "myapp_session",
 	Salt: "mysecret"
 	Timeout 3600000
 }

 // get a session manager
 sessionManager := simplesessions.NewSessionManager(options)

 // call some methods
 session, err := sessionManager.GetSession(requestCookieVal)
 userId, err := sessionManager.GetUserSession(sessionId)
 sessionId := sessionManager.NewSession(userId) // -1 for guest
 sessionManager.DeleteSession(sessionId)
 sessionManager.SetCookie(responseWriter, sessionId)
 sessionManager.ClearExpired()
 sessionId, err := sessionManager.SetUID(session, uid)

 // Provides 1 function not attached to a session manager
 sessionManager.MakeSID()

 ```
