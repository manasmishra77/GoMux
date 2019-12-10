package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/dgrijalva/jwt-go"
)

//Creating mongoClient

var client *mongo.Client

//const mongodbUri = "mongodb+srv://manas:manasdb@pgdemo-0r2jn.mongodb.net/test?retryWrites=true&w=majority";
const mongodbUri = "mongodb://localhost:27017"

//BOOK struct

type Book struct {
	ID     primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Isbn   string             `json:"isbn,omitempty" bson:"isbn,omitempty"`
	Title  string             `json:"title,omitempty" bson:"title,omitempty"`
	Author *Author            `json:"author,omitempty" bson:"author,omitempty"`
}

//Author Struct
type Author struct {
	Firstname string `json:"firstName,omitempty" bson:"firstName,omitempty"`
	Lastname  string `json:"lastName,omitempty" bson:"lastName,omitempty"`
}

//create the JWT key used to create the signature
var jwtKey = []byte("my_secret_key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

//Struct to read the username and password from the request body
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

//A struct that will be encoded to a JWT
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

//Init books var as aslice book struct
var books []Book

//Get all books
func getBooks(w http.ResponseWriter, r *http.Request) {
	success, errInt := CheckUserAuthentication(w, r)
	if success == false {
		w.WriteHeader(errInt)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var booksToRespond []Book
	collection := client.Database("TheDemoDev").Collection("book")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message": "` + err.Error() + `" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var book Book
		cursor.Decode(&book)
		booksToRespond = append(booksToRespond, book)
	}

	if err := cursor.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(w).Encode(booksToRespond)
}

//Get single book
func getBook(w http.ResponseWriter, r *http.Request) {
	CheckUserAuthentication(w, r)
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) //Get params
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var book Book
	collection := client.Database("TheDemoDev").Collection("book")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	err := collection.FindOne(ctx, Book{ID: id}).Decode(&book)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(w).Encode(book)
}

//Create book
func createBook(w http.ResponseWriter, r *http.Request) {
	CheckUserAuthentication(w, r)
	w.Header().Set("Content-Type", "application/json")
	var book Book
	_ = json.NewDecoder(r.Body).Decode(&book)
	collection := client.Database("TheDemoDev").Collection("book")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	result, _ := collection.InsertOne(ctx, book)
	json.NewEncoder(w).Encode(result)
}

//Update book
func updateBook(w http.ResponseWriter, r *http.Request) {
	CheckUserAuthentication(w, r)
	w.Header().Set("Content-Type", "application/json")
	// params := mux.Vars(r)
	// for index, item := range books {
	// 	if item.ID == params["id"] {
	// 		books = append(books[:index], books[index+1:]...)
	// 		var book Book
	// 		_ = json.NewDecoder(r.Body).Decode(&book)
	// 		book.ID = item.ID
	// 		books = append(books, book)
	// 		json.NewEncoder(w).Encode(book)
	// 		break
	// 	}

	// }
	// json.NewEncoder(w).Encode(books)
}

//Delete book
func deleteBook(w http.ResponseWriter, r *http.Request) {
	CheckUserAuthentication(w, r)
	w.Header().Set("Content-Type", "application/json")
	// params := mux.Vars(r)
	// for index, item := range books {
	// 	if item.ID == params["id"] {
	// 		books = append(books[:index], books[index+1:]...)
	// 		break
	// 	}

	// }
	// json.NewEncoder(w).Encode(books)
}

func main() {
	fmt.Println("Hello")
	configureMongoCLient()
	//Init router
	r := mux.NewRouter()

	r.HandleFunc("/signin", Signin)

	//Mock data
	// books = append(books, Book{ID: "1", Isbn: "333", Title: "book One", Author: &Author{Firstname: "M", Lastname: "M"}})
	// books = append(books, Book{ID: "2", Isbn: "333", Title: "book One", Author: &Author{Firstname: "M", Lastname: "M"}})
	// books = append(books, Book{ID: "3", Isbn: "333", Title: "book One", Author: &Author{Firstname: "M", Lastname: "M"}})

	//Route handler/ Endpoints
	r.HandleFunc("/api/books", getBooks).Methods("GET")
	r.HandleFunc("/api/book/{id}", getBook).Methods("GET")
	r.HandleFunc("/api/books", createBook).Methods("POST")
	r.HandleFunc("/api/book/{id}", updateBook).Methods("PUT")
	r.HandleFunc("/api/book/{id}", deleteBook).Methods("DELETE")

	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	err := srv.ListenAndServe()

	fmt.Println("Starting Server")
	if err != nil {
		fmt.Println(err)
	}
	// log.Fatal(http.ListenAndServe(":8000", r))
}

//Configure mongoClient
func configureMongoCLient() {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	clientOptions := options.Client().ApplyURI(mongodbUri)
	clientNew, err := mongo.Connect(ctx, clientOptions)
	fmt.Println("1")
	if err != nil {
		fmt.Println(err)
	}

	// Check the connection
	err = clientNew.Ping(ctx, nil)
	fmt.Println("2")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Connected to MongoDB!")
	client = clientNew
}

//Implementing sign in
func Signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[creds.Username]

	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(2 * time.Minute)

	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

//handling post authentication route
func CheckUserAuthentication(w http.ResponseWriter, r *http.Request) (success bool, errInt int) {
	c, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			errInt = http.StatusUnauthorized
			success = false
			return
		}
	}
	tknStr := c.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			errInt = http.StatusUnauthorized
			success = false
			return
		}
		errInt = http.StatusBadRequest
		success = false
		return
	}

	if !tkn.Valid {
		errInt = http.StatusUnauthorized
		success = false
		return
	}
	errInt = 0
	success = true
	return
}

func Refreh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Creating a new jwt token

	expirationTime := time.Now().Add(2 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
