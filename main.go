package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/Jamesllllllllll/chirpy/internal/auth"
	"github.com/Jamesllllllllll/chirpy/internal/database"
	"github.com/TwiN/go-away"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits  atomic.Int32
	databaseQueries *database.Queries
	platform        string
	secret          string
	polkaKey        string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
	Username     string    `json:"username"`
}

type singleChirp struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		// Handle OPTIONS requests globally
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
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
		secret:          os.Getenv("SECRET"),
		polkaKey:        os.Getenv("POLKA_KEY"),
	}
	apiCfg.fileserverHits.Store(0)

	// // First register the OPTIONS handler for API routes only
	// mux.HandleFunc("OPTIONS /api/", func(w http.ResponseWriter, r *http.Request) {
	// 	enableCors(&w)
	// 	w.WriteHeader(http.StatusOK)
	// })

	// Then register the file server
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
		authorID := req.URL.Query().Get("author_id")
		sortQ := req.URL.Query().Get("sort")
		if authorID != "" {
			userID, err := uuid.Parse(authorID)
			if err != nil {
				respondWithError(w, 404, "Error parsing user ID")
				return
			}
			authorChirps, err := apiCfg.databaseQueries.GetChirpsByAuthor(req.Context(), userID)
			if err != nil {
				respondWithError(w, 204, "no chirps found for user")
				return
			}
			formattedChirps := make([]singleChirp, len(authorChirps))
			for i, chirp := range authorChirps {
				formattedChirps[i] = singleChirp{
					ID:        chirp.ID.String(),
					CreatedAt: chirp.CreatedAt,
					UpdatedAt: chirp.UpdatedAt,
					Body:      chirp.Body,
					UserID:    chirp.UserID.String(),
					Username:  chirp.Username,
				}
			}
			if sortQ == "desc" {
				sort.Slice(formattedChirps, func(i, j int) bool { return formattedChirps[i].CreatedAt.After(formattedChirps[j].CreatedAt) })
			}
			respondWithJSON(w, 200, formattedChirps)
			return
		}
		allChirps, err := apiCfg.databaseQueries.GetAllChirps(req.Context())
		if err != nil {
			fmt.Print("error getting chirps:", err)
			respondWithError(w, 500, "Error getting chirps")
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
				Username:  chirp.Username,
			}
		}
		if sortQ == "desc" {
			sort.Slice(formattedChirps, func(i, j int) bool { return formattedChirps[i].CreatedAt.After(formattedChirps[j].CreatedAt) })
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

	mux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}

		userID, validateErr := auth.ValidateJWT(token, apiCfg.secret)
		if validateErr != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}

		id, err := uuid.Parse(req.PathValue("chirpID"))
		if err != nil {
			respondWithError(w, 500, "Error with chirp ID")
			return
		}

		chirp, err := apiCfg.databaseQueries.GetSingleChirp(req.Context(), id)
		if err != nil {
			respondWithError(w, 404, "Not found")
			return
		}
		if chirp.UserID != userID {
			respondWithError(w, 403, "Unauthorized")
			return
		}

		deleteErr := apiCfg.databaseQueries.DeleteSingleChrip(req.Context(), id)
		if deleteErr != nil {
			fmt.Println("Error deleting chirp:", err)
			respondWithError(w, 404, "Not Found")
			return
		}

		respondWithJSON(w, 204, nil)
	})

	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}

		user, err := apiCfg.databaseQueries.FindUserById(req.Context(), userID)
		if err != nil {
			respondWithError(w, 404, "Not found")
			return
		}

		type parameters struct {
			// these tags indicate how the keys in the JSON should be mapped to the struct fields
			// the struct fields must be exported (start with a capital letter) if you want them parsed
			Body     string `json:"body"`
			UserName string `json:"username"`
			// UserID string `json:"user_id"`
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		decodeErr := decoder.Decode(&params)
		if decodeErr != nil {
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

		cleanText := goaway.Censor(params.Body)

		// words := strings.Split(strings.TrimSpace(params.Body), " ")

		// for i, word := range words {
		// 	if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
		// 		words[i] = "****"
		// 	}
		// }

		// userUUID, err := uuid.Parse(params.UserID)
		// if err != nil {
		// 	respondWithError(w, 400, "Problem with user ID")
		// 	return
		// }

		chirpParams := database.CreateChirpParams{
			Body:     cleanText,
			UserID:   userID,
			Username: user.Username,
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
			Body:      cleanText,
			UserID:    userID.String(),
		}
		respondWithJSON(w, 201, respBody)

	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			Username string `json:"username"`
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
			Username:       params.Username,
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
			Username:  user.Username,
		}
		respondWithJSON(w, 201, response)
	})

	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			respondWithError(w, 401, "Unauthorized")
			return
		}

		type parameters struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		decodeErr := decoder.Decode(&params)
		if decodeErr != nil {
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

		updateUserParams := database.UpdateUserParams{
			ID:             userID,
			Email:          params.Email,
			HashedPassword: hashed_password,
		}
		user, err := apiCfg.databaseQueries.UpdateUser(req.Context(), updateUserParams)
		if err != nil {
			fmt.Print("error updating user:", err)
			respondWithError(w, 500, "Error updating user")
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

	mux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, req *http.Request) {
		type parameters struct {
			Event string `json:"event"`
			Data  struct {
				UserID string `json:"user_id"`
			} `json:"data"`
		}

		apiKey, err := auth.GetAPIKey(req.Header)
		if err != nil {
			respondWithError(w, 401, "unauthorized")
			return
		}

		if apiKey != apiCfg.polkaKey {
			respondWithError(w, 401, "unauthorized")
			return
		}

		decoder := json.NewDecoder(req.Body)
		params := parameters{}
		decodeErr := decoder.Decode(&params)
		if decodeErr != nil {
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		if params.Event != "user.upgraded" {
			respondWithError(w, 204, "no content")
			return
		}

		userID, err := uuid.Parse(params.Data.UserID)
		if err != nil {
			respondWithError(w, 500, "error parsing user ID")
			return
		}

		user, err := apiCfg.databaseQueries.UpgradeUser(req.Context(), userID)
		if err != nil {
			respondWithError(w, 404, "not found")
			return
		}

		respondWithJSON(w, 204, user)
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

		token, err := auth.MakeJWT(user.ID, apiCfg.secret, time.Second*time.Duration(3600))
		if err != nil {
			respondWithError(w, 500, "error creating JWT")
		}

		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			respondWithError(w, 500, "error creating refresh token")
		}

		response := User{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refreshToken,
			IsChirpyRed:  user.IsChirpyRed,
		}

		saveRefreshTokenParams := database.SaveRefreshTokenParams{
			Token:     refreshToken,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(1140)),
		}

		apiCfg.databaseQueries.SaveRefreshToken(req.Context(), saveRefreshTokenParams)

		respondWithJSON(w, 200, response)
	})

	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, req *http.Request) {
		refreshToken, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "unauthorized")
			return
		}
		fmt.Println("Token in /api/refresh:", refreshToken)

		dbToken, err := apiCfg.databaseQueries.LookupRefreshToken(req.Context(), refreshToken)
		if err != nil {
			fmt.Println("Error looking up refresh token:", err)
			respondWithError(w, 401, "unauthorized")
			return
		}

		fmt.Println("REVOKED AT:", dbToken.RevokedAt.Valid)

		if dbToken.ExpiresAt.Before(time.Now()) || dbToken.RevokedAt.Valid {
			fmt.Println("Token expired or revoked")
			respondWithError(w, 401, "unauthorized")
			return
		}

		newAccessToken, err := auth.MakeJWT(dbToken.UserID, apiCfg.secret, time.Second*time.Duration(3600))
		if err != nil {
			respondWithError(w, 500, "error creating JWT")
			return
		}

		fmt.Println("Refresh token:", refreshToken)
		fmt.Println("New access token:", newAccessToken)

		// response := struct {
		// 	Token string
		// }{
		// 	Token: newAccessToken,
		// }

		type simpleTokenResponse struct {
			Token string `json:"token"`
		}

		response := simpleTokenResponse{
			Token: newAccessToken,
		}
		fmt.Println("This should be the new token:", response)
		respondWithJSON(w, 200, response)
	})

	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "unauthorized")
		}

		response, err := apiCfg.databaseQueries.RevokeToken(req.Context(), token)
		if err != nil {
			respondWithError(w, 404, "not found")
		}
		respondWithJSON(w, 204, response)
	})

	mux.HandleFunc("/api/getuser", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "unauthorized")
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			respondWithError(w, 401, "unauthorized")
			return
		}

		user, err := apiCfg.databaseQueries.FindUserById(req.Context(), userID)
		if err != nil {
			respondWithError(w, 404, "user not found")
			return
		}

		response := User{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
			Username:  user.Username,
		}
		respondWithJSON(w, 200, response)
	})

	server := http.Server{
		Handler: corsMiddleware(mux),
		Addr:    ":8080",
	}
	fmt.Println("Server listening on port 8080...")
	server.ListenAndServe()

}
