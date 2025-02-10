package main

import _ "github.com/lib/pq"

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Jamesllllllllll/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

type apiConfig struct {
	fileserverHits  atomic.Int32
	databaseQueries *database.Queries
	platform        string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (cfg *apiConfig) middwareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	w.Write(response)
	return nil
}

func respondWithError(w http.ResponseWriter, code int, msg string) error {
	return respondWithJSON(w, code, map[string]string{"error": msg})
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("error connecting to database")
	}

	mux := http.NewServeMux()

	apiCfg := apiConfig{
		databaseQueries: database.New(db),
		platform:        os.Getenv("PLATFORM"),
	}
	apiCfg.fileserverHits.Store(0)

	fs := http.FileServer(http.Dir("./"))
	handler := http.StripPrefix("/app/", fs)
	mux.Handle("/app/", apiCfg.middwareMetricsInc(handler))

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		req.Header.Add("Content-Type", "text/plain; charset=utf8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, req *http.Request) {
		req.Header.Add("Content-Type", "text/html")
		w.WriteHeader(200)
		metrictsTemplate := `
		<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited {{ . }} times!</p>
			</body>
		</html>`

		// Parse template string
		t, err := template.New("metrics").Parse(metrictsTemplate)
		if err != nil {
			http.Error(w, "failed to parse template", http.StatusInternalServerError)
			return
		}

		// Execute the template with data
		t.Execute(w, apiCfg.fileserverHits.Load())
	})

	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, req *http.Request) {
		if apiCfg.platform != "dev" {
			respondWithError(w, 403, "Forbidden")
		}

		apiCfg.databaseQueries.DeleteUsers(req.Context())
		w.WriteHeader(200)
		w.Write([]byte("Deleted all users"))
		// apiCfg.fileserverHits.Store(0)
		// req.Header.Add("Content-Type", "text/plain; charset=utf8")
		// w.WriteHeader(200)
		// w.Write([]byte("OK - Reset metrics"))
	})

	mux.HandleFunc("POST /api/chirp", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			// these tags indicate how the keys in the JSON should be mapped to the struct fields
			// the struct fields must be exported (start with a capital letter) if you want them parsed
			Body 	string `json:"body"`
			UserID 	string `json:"user_id"`
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			// an error will be thrown if the JSON is invalid or has the wrong types
			// any missing fields will simply have their values in the struct set to their zero value
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		// params is a struct with data populated successfully

		type returnVals struct {
			ID			string `json:"id"`
			CreatedAt	string `json:"created_at"`
			UpdatedAt	string `json:"updated_at"`
			Body 		string `json:"body"`
			UserID		string `json:"user_id"`
		}

		if len(params.Body) > 140 {
			respondWithError(w, 400, "Chirp is too long")
			return
		}

		words := strings.Split(strings.TrimSpace(params.Body), " ")

		for i, word := range words {
			if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
				words[i] = "****"
			}
		}

		chirp, err := apiCfg.databaseQueries.CreateChirp(req.Context(), words)
		if err != nil {
			fmt.Print("error creating chirp:", err)
			respondWithError(w, 500, "Error creating chirp")
			return
		}

		respBody := returnVals{
			ID: "0", //TODO: Make it the ID from the DB query response
			CreatedAt: "1",
			UpdatedAt: "1",
			Body: strings.Join(words, " "),
			UserID: "1",
		}
		respondWithJSON(w, 200, respBody)

	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			Email string `json:"email"`
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		user, err := apiCfg.databaseQueries.CreateUser(req.Context(), params.Email)
		if err != nil {
			fmt.Print("error creating user:", err)
			respondWithError(w, 500, "Error creating user")
			return
		}

		response := User{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		}

		respondWithJSON(w, 201, response)
	})

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()

}
