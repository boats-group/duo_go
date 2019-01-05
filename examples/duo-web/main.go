package main

import (
	"context"
	"duo"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

type callbackParameters struct {
	Username string
	Error    error
}

type key int

type promptParameters struct {
	Host      string
	Signature string
	Error     error
}

const (
	requestIDKey key = 0
)

var (
	listenAddr     string
	apiHostname    string
	integrationKey string
	secretKey      string
	appKey         string
)

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				requestID, ok := r.Context().Value(requestIDKey).(string)
				if !ok {
					requestID = "unknown"
				}
				logger.Println(requestID, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func tracing(nextRequestID func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = nextRequestID()
			}
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func nextRequestID() string {
	return fmt.Sprintf("%d", time.Now().Local().UnixNano())
}

func promptHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		if r.Method == http.MethodGet {
			username := r.URL.Query().Get("user")
			if username == "" {
				http.Error(w, "Missing query parameter: user", http.StatusBadRequest)
				return
			}

			signature, err := duo.SignRequest(integrationKey, secretKey, appKey, username)
			parameters := promptParameters{Host: apiHostname, Signature: signature, Error: err}
			tmpl := template.New("prompt.html")
			tmpl, _ = template.ParseFiles("./templates/prompt.html")
			w.WriteHeader(http.StatusOK)
			tmpl.Execute(w, parameters)
		} else if r.Method == http.MethodPost {
			r.ParseForm()
			duoResponse := r.Form.Get("sig_response")
			if duoResponse == "" {
				http.Error(w, "Missing signature form data: sig_response", http.StatusBadRequest)
				return
			}

			username, err := duo.VerifyResponse(integrationKey, secretKey, appKey, duoResponse)
			parameters := callbackParameters{Username: username, Error: err}
			tmpl := template.New("callback.html")
			tmpl, _ = template.ParseFiles("./templates/callback.html")
			w.WriteHeader(http.StatusOK)
			tmpl.Execute(w, parameters)
		} else {
			http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
		}
	})
}

func main() {
	flag.StringVar(&listenAddr, "l", "0.0.0.0:3000", "server listen address")
	flag.StringVar(&apiHostname, "api", "", "duo api hostname")
	flag.StringVar(&integrationKey, "ik", "", "duo integration key")
	flag.StringVar(&secretKey, "sk", "", "duo secret key")
	flag.StringVar(&appKey, "ak", "", "duo application key")
	flag.Parse()

	logger := log.New(os.Stdout, "http:", log.LstdFlags)
	logger.Println("Starting http server...")

	router := http.NewServeMux()
	router.Handle("/", promptHandler())
	router.Handle("/static/", http.FileServer(http.Dir("./")))

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      tracing(nextRequestID)(logging(logger)(router)),
		ErrorLog:     logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		logger.Println("Stopping http server...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			logger.Fatalf("Failed to gracefully shutdown the server: %v\n", err)
		}
		close(done)
	}()

	logger.Printf("Server is ready to handle requests on http://%s\n", listenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Failed to listen on %s: %v\n", listenAddr, err)
	}

	<-done
	logger.Println("Server stopped")
}
