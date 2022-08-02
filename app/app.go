package app

import (
	"capi/domain"
	"capi/logger"
	"capi/service"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
)

func sanityCheck() {
	envProps := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"DB_USER",
		"DB_PASSWD",
		"DB_ADDR",
		"DB_PORT",
		"DB_NAME",
	}

	for _, envKey := range envProps {
		if os.Getenv(envKey) == "" {
			logger.Fatal(fmt.Sprintf("environment variable %s not defined. terminating application...", envKey))
		}
	}

	logger.Info("environment variables loaded...")

}

func Start() {

	err := godotenv.Load()
	if err != nil {
		logger.Fatal("error loading .env file")
	}
	logger.Info("load environment variables...")

	sanityCheck()

	dbClient := getClientDB()

	// * wiring
	// * setup repository
	customerRepositoryDB := domain.NewCustomerRepositoryDB(dbClient)
	accountRepositoryDB := domain.NewAccountRepositoryDB(dbClient)
	authRepositoryDB := domain.NewAuthRepositoryDB(dbClient)

	// * setup service
	customerService := service.NewCustomerService(customerRepositoryDB)
	accountService := service.NewAccountService(accountRepositoryDB)
	authService := service.NewAuthService(authRepositoryDB)

	// * setup handler
	ch := CustomerHandlers{customerService}
	ah := AccountHandler{accountService}
	authH := AuthHandler{authService}

	// * create ServeMux
	mux := mux.NewRouter()

	authR := mux.PathPrefix("/auth").Subrouter()
	authR.HandleFunc("/login", authH.Login).Methods(http.MethodPost)

	authR.Use(loggingMiddleware)

	// * defining routes for customer
	customerR := mux.PathPrefix("/customers").Subrouter()

	customerR.HandleFunc("", ch.getAllCustomers).Methods(http.MethodGet)
	customerR.HandleFunc("/{customer_id:[0-9]+}", ch.getCustomerByID).Methods(http.MethodGet)
	customerR.HandleFunc("/{customer_id:[0-9]+}/accounts", ah.NewAccount).Methods(http.MethodPost)
	customerR.HandleFunc("/{customer_id:[0-9]+}/accounts/{account_id:[0-9]+}", ah.MakeTransaction).Methods(http.MethodPost)
	customerR.Use(authMiddleware)
	// * starting the server

	serverAddr := os.Getenv("SERVER_ADDRESS")
	serverPort := os.Getenv("SERVER_PORT")

	logger.Info(fmt.Sprintf("start server on %s:%s...", serverAddr, serverPort))
	http.ListenAndServe(fmt.Sprintf("%s:%s", serverAddr, serverPort), mux)
}

func getClientDB() *sqlx.DB {
	dbUser := os.Getenv("DB_USER")
	dbPasswd := os.Getenv("DB_PASSWD")
	dbAddr := os.Getenv("DB_ADDRESS")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", dbUser, dbPasswd, dbAddr, dbPort, dbName)
	db, err := sqlx.Open("postgres", connStr)
	if err != nil {
		logger.Fatal(err.Error())
	}
	logger.Info("success connect to database...")

	return db
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.Now()
		next.ServeHTTP(w, r)
		logger.Info(fmt.Sprintf("%v %v %v", r.Method, r.URL, time.Since(timer)))
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("Authorization")

		// pengecekan apakah ada token atau tidak
		if tokenHeader == "" {
			writeResponse(w, http.StatusUnauthorized, "You have not login yet")
			return
		}

		// pengecekan apakah token adalah bearer token
		if !strings.Contains(tokenHeader, "Bearer") {
			writeResponse(w, http.StatusUnauthorized, "you token not valid")
			return
		}
		// split token -> ambil tokennya buang "Bearer" nya
		splitToken := strings.Split(tokenHeader, " ")
		token := splitToken[1]

		// parsing token, err := jwt.Parse(
		parseToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte("rahasia"), nil
		})

		// check token validation
		if err != nil {
			if errors.Is(err, jwt.ErrTokenMalformed) {
				logger.Error(err.Error())
				writeResponse(w, http.StatusUnauthorized, "your token is not valid ")
				return
			} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
				writeResponse(w, http.StatusBadGateway, "Timeout to parse token")
				return
			} else {
				logger.Error("could handle this token " + err.Error())
				writeResponse(w, http.StatusBadRequest, "internal server error")
				return
			}
		}

		next.ServeHTTP(w, r)
		writeResponse(w, http.StatusOK, parseToken.Claims)
	})
}
