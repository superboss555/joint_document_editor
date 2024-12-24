package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db           *sql.DB
	idLock       = &sync.Mutex{}
	upgrader     = websocket.Upgrader{}
)

// User структура для хранения данных пользователя
type User struct {
    ID       int    `json:"id"` 
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Room struct {
    ID       int    `json:"id"`
    Name     string `json:"name"`
    Password string `json:"password"`
    Creator  int    `json:"creator" `
}

// initDB инициализация базы данных
func initDB() {
	var err error
	connStr := "host=localhost user=admin password=123 dbname=doc port=5432 sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Ошибка пинга базы данных:", err)
	}
}


func userExists(email string) bool {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", email).Scan(&exists)
	if err != nil {
		log.Println("Ошибка проверки существования пользователя:", err)
		return false
	}
	return exists
}

func setCORSHeaders(w http.ResponseWriter) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func createUser(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)

    if r.Method == http.MethodOptions {
        return // Просто возвращаем ответ с установкой заголовков
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
        return
    }

    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Ошибка декодирования данных: "+err.Error(), http.StatusBadRequest)
        return
    }

    log.Printf("Received user data: %+v", user) // Логируем входящие данные

    if user.Email == "" || user.Password == "" {
        http.Error(w, "Email и пароль не могут быть пустыми", http.StatusBadRequest)
        return
    }

    // Хэшируем пароль
    hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Ошибка хэширования пароля: "+err.Error(), http.StatusInternalServerError)
        return
    }
    user.Password = string(hash)

    idLock.Lock()
    defer idLock.Unlock()

    err = db.QueryRow("INSERT INTO users(email, password) VALUES($1, $2) RETURNING id",
        user.Email, user.Password).Scan(&user.ID)
    if err != nil {
        http.Error(w, "Ошибка при создании пользователя: "+err.Error(), http.StatusInternalServerError)
        return
    }

    response := map[string]string{"message": "Пользователь успешно зарегистрирован", "redirect": "/account"}
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(response)
}


func loginUser(w http.ResponseWriter, r *http.Request) {
    setCORSHeaders(w)

    if r.Method == http.MethodOptions {
        return // Обработка preflight-запроса
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
        return
    }

    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Ошибка декодирования данных: "+err.Error(), http.StatusBadRequest)
        return
    }

    log.Printf("Received login data: %+v", user)

    if user.Email == "" || user.Password == "" {
        http.Error(w, "Email и пароль не могут быть пустыми", http.StatusBadRequest)
        return
    }

    var storedHash string
    err := db.QueryRow("SELECT id, password FROM users WHERE email = $1", user.Email).Scan(&user.ID, &storedHash)
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "Неверный Email или пароль", http.StatusUnauthorized)
            return
        }
        http.Error(w, "Ошибка получения данных: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Сравниваем хэш
    err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(user.Password))
    if err != nil {
        http.Error(w, "Неверный Email или пароль", http.StatusUnauthorized)
        return
    }

    // Устанавливаем cookie с ID пользователя
    http.SetCookie(w, &http.Cookie{
        Name:  "user_id",
        Value: strconv.Itoa(user.ID), // Преобразуем ID в строку
        Path:  "/",
        HttpOnly: true,
    })

    response := map[string]string{"message": "Успешный вход", "redirect": "/account"}
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}



func handleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка при установке соединения:", err)
		return
	}
	defer conn.Close()

	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Ошибка:", err)
			break
		}

		log.Printf("Получено сообщение: %s\n", msg)

		err = conn.WriteMessage(messageType, msg) // Эхо-ответ (если нужно)
		if err != nil {
			log.Println("Ошибка:", err)
			break
		}
	}
}


func serveHome(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "D:/projects/webDocuments/Client/index.html")
}


func serveAccount(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "D:/projects/webDocuments/Client/account.html") 
}

func createRoom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	// Извлекаем ID пользователя из cookie
	cookie, err := r.Cookie("user_id")
	if err != nil {
		http.Error(w, "Необходимо войти в систему", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.Atoi(cookie.Value) // Преобразуем значение cookie в int
	if err != nil {
		http.Error(w, "Ошибка получения ID пользователя: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var room Room
	err = json.NewDecoder(r.Body).Decode(&room)
	if err != nil {
		http.Error(w, "Ошибка при декодировании запроса: "+err.Error(), http.StatusBadRequest)
		return
	}

	room.Creator = userID // Устанавливаем ID создателя комнаты

	log.Printf("Создание комнаты с именем: %s от пользователя: %d", room.Name, room.Creator) // Логируем имя комнаты и создателя

	query := "INSERT INTO rooms (name, password, creator_id) VALUES ($1, $2, $3) RETURNING id"
	err = db.QueryRow(query, room.Name, room.Password, room.Creator).Scan(&room.ID)
	if err != nil {
		http.Error(w, "Ошибка при создании комнаты: "+err.Error(), http.StatusInternalServerError)
		log.Printf("Ошибка при создании комнаты: %v", err) // Логируем ошибку
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(room)
}



func main() {
	initDB()                     
	defer db.Close()             

    clientDir := "../Client"
    http.Handle("/", http.FileServer(http.Dir(clientDir)))
	http.HandleFunc("/register", createUser) // Обработка регистрации пользователей
	http.HandleFunc("/login", loginUser)      // Обработка входа пользователей
	http.HandleFunc("/ws", handleConnection)   // Обработка WebSocket-соединений
	http.HandleFunc("/account", serveAccount) // Обработка страницы аккаунта
	http.HandleFunc("/createRoom", createRoom) // Обработка создания комнаты
    http.HandleFunc("/home", serveHome) // Обработка создания комнаты

	log.Println("Сервер запущен на порту 8080")
	log.Fatal(http.ListenAndServe(":8080", nil)) // Запуск HTTP-сервера
}
