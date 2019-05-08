package handler

import (
	"fmt"
	"log"
	"net/http"
)

// AppHandler is a type that defines a standard handler with return type AppError
type AppHandler func(http.ResponseWriter, *http.Request) *AppError

// AppError is the type of error that all handlers will return
// This error will be used in the ServeHTTP function
type AppError struct {
	Error   error
	Message string
	Code    int
}

func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil { // e is *appError, not os.Error.
		log.Printf("Handler error: status code: %d, message: %s, underlying err: %#v",
			e.Code, e.Message, e.Error)

		http.Error(w, e.Message, e.Code)
	}
}

// AppErrorf returns a type AppError
func AppErrorf(errorCode int, err error, format string, v ...interface{}) *AppError {
	return &AppError{
		Error:   err,
		Message: fmt.Sprintf(format, v...),
		Code:    errorCode,
	}
}
