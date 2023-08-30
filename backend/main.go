package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
)

type TokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

var router *mux.Router

var client *mongo.Client

func GenerateAccessToken(guid string) (string, error) {
	secretKey := []byte("secret-key")
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)

	expTime, err := strconv.Atoi(os.Getenv("ACCESS_TOKEN_EXP"))

	if err != nil {
		return "", err
	}

	claims["guid"] = guid
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(expTime)).Unix()

	tokenString, err := token.SignedString(secretKey)

	if err != nil {
		return "", err
	}
	return tokenString, nil
}

type RefreshToken struct {
	Guid string `json:"guid"`
	Exp  int64  `json:"exp"`
}

func GenerateRefreshToken(guid string) (string, error) {

	expTime, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXP"))

	if err != nil {
		return "", err
	}

	data := RefreshToken{
		Guid: guid,
		Exp:  time.Now().Add(time.Minute * time.Duration(expTime)).Unix(),
	}

	// Marshal struct to JSON bytes
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	// Encode JSON bytes to Base64
	base64Encoded := base64.StdEncoding.EncodeToString(jsonBytes)

	if err != nil {
		return "", err
	}
	return base64Encoded, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	fmt.Println("guid =>", guid)
	usersCollection := client.Database("go-jwt-auth").Collection("users")

	var result struct {
		Guid string `bson:"guid"`
	}

	filter := bson.M{"guid": bson.M{"$eq": guid}}

	err := usersCollection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var tokenPair TokenPair

	accessToken, err := GenerateAccessToken(guid)
	if err != nil {
		panic(err)
	}

	refreshToken, err := GenerateRefreshToken(guid)
	if err != nil {
		panic(err)
	}

	fmt.Println(refreshToken)
	refreshTokensCollection := client.Database("go-jwt-auth").Collection("refreshTokens")

	encryptedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), 10)
	if err != nil {
		panic(err)
	}

	user := bson.D{{Key: "guid", Value: result.Guid}, {Key: "value", Value: string(encryptedRefreshToken)}}

	filter = bson.M{"guid": bson.M{"$eq": string(guid)}}

	_, err = refreshTokensCollection.DeleteMany(context.Background(), filter)
	if err != nil {
		http.Error(w, "Some error on server", http.StatusNotFound)
		return
	}

	insertedResult, err := refreshTokensCollection.InsertOne(context.TODO(), user)
	if err != nil {
		panic(err)
	}
	fmt.Println(insertedResult)

	tokenPair.AccessToken = accessToken
	tokenPair.RefreshToken = refreshToken
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenPair)
}

func refresh(w http.ResponseWriter, r *http.Request) {
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", reqBody)

	decodedBytes, err := base64.StdEncoding.DecodeString(string(reqBody))
	if err != nil {
		fmt.Println("Error decoding Base64:", err)
		return
	}

	var refreshTokenJson RefreshToken

	err = json.Unmarshal(decodedBytes, &refreshTokenJson)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}
	fmt.Println(refreshTokenJson)

	refreshTokensCollection := client.Database("go-jwt-auth").Collection("refreshTokens")

	var result struct {
		Value string `bson:"value"`
	}

	filter := bson.M{"guid": bson.M{"$eq": string(refreshTokenJson.Guid)}}

	err = refreshTokensCollection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		http.Error(w, "Refresh token not found", http.StatusNotFound)
		return
	}

	fmt.Println("Document:", result)
	fmt.Println("Comparing:", string(reqBody), result.Value)
	match := CheckPasswordHash(string(reqBody), result.Value)
	if !match {
		http.Error(w, "Refresh token is not valid", http.StatusNotFound)
		return
	}

	now := time.Now().Unix()
	fmt.Println("Comparing", refreshTokenJson.Exp, now)
	if refreshTokenJson.Exp < now {
		http.Error(w, "Refresh token is expired", http.StatusNotFound)
		return
	}

	var tokenPair TokenPair

	accessToken, err := GenerateAccessToken(refreshTokenJson.Guid)
	if err != nil {
		panic(err)
	}

	refreshToken, err := GenerateRefreshToken(refreshTokenJson.Guid)
	if err != nil {
		panic(err)
	}

	fmt.Println(refreshToken)

	encryptedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), 10)
	if err != nil {
		panic(err)
	}

	user := bson.D{{Key: "guid", Value: refreshTokenJson.Guid}, {Key: "value", Value: string(encryptedRefreshToken)}}

	filter = bson.M{"guid": bson.M{"$eq": string(refreshTokenJson.Guid)}}

	_, err = refreshTokensCollection.DeleteMany(context.Background(), filter)
	if err != nil {
		http.Error(w, "Some error on server", http.StatusNotFound)
		return
	}

	insertedResult, err := refreshTokensCollection.InsertOne(context.TODO(), user)
	if err != nil {
		panic(err)
	}
	fmt.Println(insertedResult)

	tokenPair.AccessToken = accessToken
	tokenPair.RefreshToken = refreshToken
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenPair)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func main() {
	var err error
	err = godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Some error occured. Err: %s", err)
	}
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	if err != nil {
		panic(err)
	}
	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		panic(err)
	}
	router = mux.NewRouter()
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/refresh", refresh).Methods("POST")
	if err := http.ListenAndServe(":3030", router); err != nil {
		panic(err)
	}

}
