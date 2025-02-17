package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Jamesllllllllll/chirpy/internal/auth"
	"github.com/Jamesllllllllll/chirpy/internal/database"
	goaway "github.com/TwiN/go-away"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits   atomic.Int32
	databaseQueries  *database.Queries
	platform         string
	secret           string
	polkaKey         string
	s3Bucket         string
	s3Region         string
	s3CfDistribution string
	s3Client         *s3.Client
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
	ImageURL  string    `json:"imageURL"`
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

func respondWithError(w http.ResponseWriter, code int, msg string, err error) {
	if err != nil {
		log.Println(err)
	}
	if code > 499 {
		log.Printf("Responding with 5XX error: %s", msg)
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	respondWithJSON(w, code, errorResponse{
		Error: msg,
	})
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

	s3Bucket := os.Getenv("S3_BUCKET")
	if s3Bucket == "" {
		log.Fatal("S3_BUCKET environment variable is not set")
	}

	s3Region := os.Getenv("S3_REGION")
	if s3Region == "" {
		log.Fatal("S3_REGION environment variable is not set")
	}

	s3CfDistribution := os.Getenv("S3_CF_DISTRO")
	if s3CfDistribution == "" {
		log.Fatal("S3_CF_DISTRO environment variable is not set")
	}

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable is not set")
	}
	ctx := context.TODO()

	awsAccessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	if awsAccessKeyID == "" {
		log.Fatal("AWS_ACCESS_KEY_ID environment variable is not set")
	}

	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if awsSecretAccessKey == "" {
		log.Fatal("AWS_SECRET_ACCESS_KEY environment variable is not set")
	}

	awsConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(s3Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			awsAccessKeyID,
			awsSecretAccessKey,
			"",
		)),
	)
	if err != nil {
		log.Fatal("Error loading awsConfig:", err)
	}

	myS3Client := s3.NewFromConfig(awsConfig)

	mux := http.NewServeMux()

	apiCfg := apiConfig{
		databaseQueries:  database.New(db),
		platform:         os.Getenv("PLATFORM"),
		secret:           os.Getenv("SECRET"),
		polkaKey:         os.Getenv("POLKA_KEY"),
		s3Bucket:         s3Bucket,
		s3Region:         s3Region,
		s3CfDistribution: s3CfDistribution,
		s3Client:         myS3Client,
	}
	apiCfg.fileserverHits.Store(0)

	// Then register the file server
	fs := http.FileServer(http.Dir("./"))
	handler := http.StripPrefix("/app/", fs)
	mux.Handle("/app/", apiCfg.middwareMetricsInc(handler))

	mux.HandleFunc("POST /api/upload", func(w http.ResponseWriter, req *http.Request) {
		// Add CORS headers specifically for this endpoint
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, multipart/form-data")
		// Handle preflight OPTIONS request
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT", err)
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT", err)
			return
		}

		chirpIDString := req.URL.Query()

		chirpID, err := uuid.Parse(chirpIDString.Get("chirpID"))
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid ID", err)
			return
		}

		// Max memory: 2MB
		const maxMemory = 2 << 20
		memErr := req.ParseMultipartForm(maxMemory)
		if memErr != nil {
			respondWithError(w, http.StatusBadRequest, "Unable to parse form", err)
			return
		}

		chirpData, err := apiCfg.databaseQueries.GetSingleChirp(req.Context(), chirpID)
		if err != nil {
			respondWithError(w, 500, "Error getting video", err)
			return
		}

		if chirpData.UserID != userID {
			respondWithError(w, http.StatusUnauthorized, "Unauthorized", err)
			return
		}

		file, header, err := req.FormFile("image")
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Unable to parse form file", err)
			return
		}
		defer file.Close()

		fmt.Println("uploading image by user", userID)

		fileExtension, _, err := mime.ParseMediaType(header.Header.Get("Content-Type"))
		if err != nil {
			respondWithError(w, 500, "Error getting file extension", err)
			return
		}
		if fileExtension != "image/png" && fileExtension != "image/jpeg" {
			respondWithError(w, 400, "Invalid file type", err)
			return
		}

		// This is where we can do io.Copy to make a temp file and process it
		// Starting at line ~90 in handler_upload_video.go in the s3 project
		// Maybe resize to be within a certain limit

		// Make empty slice of bytes for the file name
		fileName := make([]byte, 32)

		// fill with random bytes
		rand.Read(fileName)

		// encode the bytes to a URL encoded string
		encodedFilename := base64.RawURLEncoding.EncodeToString(fileName)

		// form the file path
		fullFilename := filepath.Join(userID.String(), encodedFilename) + "." + strings.Split(fileExtension, "/")[1]

		ctx := context.TODO()

		params := s3.PutObjectInput{
			Bucket:      &apiCfg.s3Bucket,
			Key:         &fullFilename,
			Body:        file,
			ContentType: &fileExtension,
		}

		_, err = apiCfg.s3Client.PutObject(ctx, &params)
		if err != nil {
			respondWithError(w, 500, "Error creating PutObject", err)
			return
		}

		imageURL := fmt.Sprintf("%s/%s", apiCfg.s3CfDistribution, fullFilename)

		addImage := database.AddImageParams{
			Imageurl: imageURL,
			ID:       chirpData.ID,
		}

		// update in DB
		updateResult, err := apiCfg.databaseQueries.AddImage(req.Context(), addImage)
		if err != nil {
			respondWithError(w, 500, "Error updating video", err)
			return
		}

		respondWithJSON(w, http.StatusOK, updateResult)
	})

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
			respondWithError(w, 403, "Forbidden", err)
		}

		err := apiCfg.databaseQueries.DeleteUsers(req.Context())
		if err != nil {
			respondWithError(w, 500, "Error deleting users", err)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("Deleted all users"))
	})

	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		authorID := req.URL.Query().Get("author_id")
		sortQ := req.URL.Query().Get("sort")
		if authorID != "" {
			userID, err := uuid.Parse(authorID)
			if err != nil {
				respondWithError(w, 404, "Error parsing user ID", err)
				return
			}
			authorChirps, err := apiCfg.databaseQueries.GetChirpsByAuthor(req.Context(), userID)
			if err != nil {
				respondWithError(w, 204, "no chirps found for user", err)
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
					ImageURL:  chirp.Imageurl,
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
			respondWithError(w, 500, "Error getting chirps", err)
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
				ImageURL:  chirp.Imageurl,
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
			respondWithError(w, 500, "Error with chirp ID", err)
			return
		}
		chirp, err := apiCfg.databaseQueries.GetSingleChirp(req.Context(), id)
		if err != nil {
			fmt.Println("Error retrieving chirp:", err)
			respondWithError(w, 404, "Not Found", err)
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
			respondWithError(w, 401, "Unauthorized", err)
			return
		}

		userID, validateErr := auth.ValidateJWT(token, apiCfg.secret)
		if validateErr != nil {
			respondWithError(w, 401, "Unauthorized", err)
			return
		}

		id, err := uuid.Parse(req.PathValue("chirpID"))
		if err != nil {
			respondWithError(w, 500, "Error with chirp ID", err)
			return
		}

		chirp, err := apiCfg.databaseQueries.GetSingleChirp(req.Context(), id)
		if err != nil {
			respondWithError(w, 404, "Not found", err)
			return
		}
		if chirp.UserID != userID {
			respondWithError(w, 403, "Unauthorized", err)
			return
		}

		deleteErr := apiCfg.databaseQueries.DeleteSingleChirp(req.Context(), id)
		if deleteErr != nil {
			fmt.Println("Error deleting chirp:", err)
			respondWithError(w, 404, "Not Found", err)
			return
		}

		respondWithJSON(w, 204, nil)
	})

	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "Unauthorized", err)
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			respondWithError(w, 401, "Unauthorized", err)
			return
		}

		user, err := apiCfg.databaseQueries.FindUserById(req.Context(), userID)
		if err != nil {
			respondWithError(w, 404, "Not found", err)
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
			respondWithError(w, 400, "Chirp is too long", err)
			return
		}

		cleanText := goaway.Censor(params.Body)

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
			respondWithError(w, 500, "Error creating chirp", err)
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
			respondWithError(w, 500, "Error hashing password", err)
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
			respondWithError(w, 500, "Error creating user", err)
			return
		}

		response := User{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			Username:    user.Username,
			IsChirpyRed: user.IsChirpyRed,
		}
		respondWithJSON(w, 201, response)
	})

	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "Unauthorized", err)
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			respondWithError(w, 401, "Unauthorized", err)
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
			respondWithError(w, 500, "Error hashing password", err)
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
			respondWithError(w, 500, "Error updating user", err)
			return
		}

		response := User{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
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
			respondWithError(w, 401, "unauthorized", err)
			return
		}

		if apiKey != apiCfg.polkaKey {
			respondWithError(w, 401, "unauthorized", err)
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
			respondWithError(w, 204, "no content", err)
			return
		}

		userID, err := uuid.Parse(params.Data.UserID)
		if err != nil {
			respondWithError(w, 500, "error parsing user ID", err)
			return
		}

		user, err := apiCfg.databaseQueries.UpgradeUser(req.Context(), userID)
		if err != nil {
			respondWithError(w, 404, "not found", err)
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
			respondWithError(w, 500, "Error decoding parameters", err)
			return
		}

		user, err := apiCfg.databaseQueries.FindUserByEmail(req.Context(), params.Email)
		if err != nil {
			log.Printf("Incorrect email or password: %s", err)
			respondWithError(w, 401, "Incorrect email or password", err)
			return
		}

		match := auth.CheckPasswordHash(params.Password, user.HashedPassword)
		if match != nil {
			log.Println("Error matching password:", match)
			respondWithError(w, 401, "Incorrect email or password", err)
			return
		}

		token, err := auth.MakeJWT(user.ID, apiCfg.secret, time.Second*time.Duration(3600))
		if err != nil {
			respondWithError(w, 500, "error creating JWT", err)
		}

		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			respondWithError(w, 500, "error creating refresh token", err)
		}

		response := User{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        token,
			RefreshToken: refreshToken,
			IsChirpyRed:  user.IsChirpyRed,
			Username:     user.Username,
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
			respondWithError(w, 401, "unauthorized", err)
			return
		}
		fmt.Println("Token in /api/refresh:", refreshToken)

		dbToken, err := apiCfg.databaseQueries.LookupRefreshToken(req.Context(), refreshToken)
		if err != nil {
			fmt.Println("Error looking up refresh token:", err)
			respondWithError(w, 401, "unauthorized", err)
			return
		}

		fmt.Println("REVOKED AT:", dbToken.RevokedAt.Valid)

		if dbToken.ExpiresAt.Before(time.Now()) || dbToken.RevokedAt.Valid {
			fmt.Println("Token expired or revoked")
			respondWithError(w, 401, "unauthorized", err)
			return
		}

		newAccessToken, err := auth.MakeJWT(dbToken.UserID, apiCfg.secret, time.Second*time.Duration(3600))
		if err != nil {
			respondWithError(w, 500, "error creating JWT", err)
			return
		}

		fmt.Println("Refresh token:", refreshToken)
		fmt.Println("New access token:", newAccessToken)

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
			respondWithError(w, 401, "unauthorized", err)
		}

		response, err := apiCfg.databaseQueries.RevokeToken(req.Context(), token)
		if err != nil {
			respondWithError(w, 404, "not found", err)
		}
		respondWithJSON(w, 204, response)
	})

	mux.HandleFunc("/api/getuser", func(w http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			respondWithError(w, 401, "unauthorized", err)
			return
		}

		userID, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			respondWithError(w, 401, "unauthorized", err)
			return
		}

		user, err := apiCfg.databaseQueries.FindUserById(req.Context(), userID)
		if err != nil {
			respondWithError(w, 404, "user not found", err)
			return
		}

		response := User{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			Username:    user.Username,
			IsChirpyRed: user.IsChirpyRed,
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
