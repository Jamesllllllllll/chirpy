package main

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

	"github.com/Jamesllllllllll/chirpy/internal/auth"
	"github.com/Jamesllllllllll/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
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

type singleChirp struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    string    `json:"user_id"`
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

		err := apiCfg.databaseQueries.DeleteUsers(req.Context())
		if err != nil {
			respondWithError(w, 500, "Error deleting users")
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("Deleted all users"))
		// apiCfg.fileserverHits.Store(0)
		// req.Header.Add("Content-Type", "text/plain; charset=utf8")
		// w.WriteHeader(200)
		// w.Write([]byte("OK - Reset metrics"))
	})

	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		allChirps, err := apiCfg.databaseQueries.GetAllChirps(req.Context())
		if err != nil {
			fmt.Print("error getting chirps:", err)
			respondWithError(w, 500, "Error creating chirp")
			return
		}
		formattedChirps := make([]singleChirp, len(allChirps))
		for i, chirp := range allChirps {
			formattedChirps[i] = singleChirp{
				ID:        chirp.ID.String(),
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID.String(),
			}
		}
		respondWithJSON(w, 200, formattedChirps)
	})

	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, req *http.Request) {
		id, err := uuid.Parse(req.PathValue("chirpID"))
		if err != nil {
			respondWithError(w, 500, "Error with chirp ID")
			return
		}
		chirp, err := apiCfg.databaseQueries.GetSingleChirp(req.Context(), id)
		if err != nil {
			fmt.Println("Error retrieving chirp:", err)
			respondWithError(w, 404, "Not Found")
			return
		}
		respBody := singleChirp{
			ID:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
		}
		respondWithJSON(w, 200, respBody)
	})

	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			// these tags indicate how the keys in the JSON should be mapped to the struct fields
			// the struct fields must be exported (start with a capital letter) if you want them parsed
			Body   string `json:"body"`
			UserID string `json:"user_id"`
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

		userUUID, err := uuid.Parse(params.UserID)
		if err != nil {
			respondWithError(w, 400, "Problem with user ID")
			return
		}

		chirpParams := database.CreateChirpParams{
			Body:   strings.Join(words, " "),
			UserID: userUUID,
		}

		chirp, err := apiCfg.databaseQueries.CreateChirp(req.Context(), chirpParams)
		if err != nil {
			fmt.Print("error creating chirp:", err)
			respondWithError(w, 500, "Error creating chirp")
			return
		}

		respBody := singleChirp{
			ID:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      strings.Join(words, " "),
			UserID:    params.UserID,
		}
		respondWithJSON(w, 201, respBody)

	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		hashed_password, err := auth.HashPassword(params.Password)
		if err != nil {
			log.Printf("Error hashing password: %s", err)
			respondWithError(w, 500, "Error hashing password")
			return
		}

		createUserParams := database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashed_password,
		}
		user, err := apiCfg.databaseQueries.CreateUser(req.Context(), createUserParams)
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

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding parameters: %s", err)
			respondWithError(w, 500, "Error decoding parameters")
			return
		}

		user, err := apiCfg.databaseQueries.FindUserByEmail(req.Context(), params.Email)
		if err != nil {
			log.Printf("Incorrect email or password: %s", err)
			respondWithError(w, 401, "Incorrect email or password")
			return
		}

		match := auth.CheckPasswordHash(params.Password, user.HashedPassword)
		if match != nil {
			log.Println("Error matching password:", match)
			respondWithError(w, 401, "Incorrect email or password")
			return
		}

		response := User{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		}
		respondWithJSON(w, 200, response)
	})

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	fmt.Println("Server listening on port 8080...")
	server.ListenAndServe()

}
