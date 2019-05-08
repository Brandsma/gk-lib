package handler

import (
	"net/http"

	"github.com/gorilla/context"
	"gopkg.in/mgo.v2"
)

type Adapter func(http.Handler) http.Handler

func Adapt(h http.Handler, adapters ...Adapter) http.Handler {
	for _, adapter := range adapters {
		h = adapter(h)
	}
	return h
}

// Adapter function to include a database reference within the context of the handler
func WithDB(db *mgo.Session) Adapter {

	// return the Adapter
	return func(h http.Handler) http.Handler {

		// the adapter (when called) should return a new handler
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// copy the database session
			dbsession := db.Copy()
			defer dbsession.Close() // clean up

			// save it in the mux context
			context.Set(r, "database", dbsession)

			// pass execution to the original handler
			h.ServeHTTP(w, r)

		})
	}
}
