#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

// ------------------ Data Structures --------------------

typedef struct 
{
    char name[50];
    char surname[50];
    char dayofbirth[12];
    char address[100];
    char phone[15];
    char email[50];
    char idNumber[20];
    char accountNumber[20];
    double balance;
} UserInfo;

typedef struct 
{
    char login[15];
    char password[50];
    UserInfo info;
} User;

// -------------------------------------------------------

// ---------------------- OpenSSL  -----------------------

static void to_hex(const unsigned char* in, size_t len, char* out);
static bool from_hex(const char* in, unsigned char* out, size_t outlen);
bool hash_password(const char* password, char* out, size_t outlen);
bool verify_password(const char* password, const char* hash);

// -------------------------------------------------------

// -------------- Global / Static Variables --------------

static User loggedUser = {0};
static sqlite3* db = NULL;
static void closeDatabase();
static sqlite3* getDatabase();
static void trimLine(char* s);

// -------------------------------------------------------

// ----------------- Function Prototypes -----------------

void cleanScreen(void);
void printLine(void);
void getLogin(char* buffer, size_t size);
void getPassword(char* buffer, size_t size);
void bankMainPage(void);
void userOperationsPage(User user);
void userOperationsDepositPage(User user);
void userOperationsWithdrawPage(User user);
void userOperationsTransferPage(User user);
void userInfoPage(User user);
void userSettingsPage(User user); 
void userSettingsChangePasswordPage(User user);
void userSettingsUpdateContactInfoPage(User user);
void randomAccountNumber(char* buffer, size_t size);

bool registerUser(void);

User* loginBank(void);

// -------------------------------------------------------

// ----------------------- Main --------------------------

int main()
{
    srand((unsigned int)time(NULL));
    atexit(closeDatabase);

    if (!getDatabase())
    {
        fprintf(stderr, "Failed to open database.\n");
        return 1;
    }

    char buf[100];
    int choice;

    printf("---------- Welcome in bank ----------\n");
    while (1)
    {
        printf("1. Login\n");
        printf("2. Register\n");
        printf("0. Exit\n");

        printf("Choose an option: ");
        fgets(buf, sizeof(buf), stdin);
        choice = atoi(buf);

        switch (choice)
        {
            case 1:
            {
                if (loginBank() != NULL)
                {
                    cleanScreen();
                    printf("You are now logged in.\n");
                    printLine();
                }
                else 
                {
                    cleanScreen();
                    printf("Login failed. Please try again.\n");
                    printLine();
                }
                break;
            }
            case 2:
            {
                if (registerUser())
                {
                    cleanScreen();
                    printf("Registration successful! You can now log in.\n");
                    printLine();
                }
                else
                {
                    cleanScreen();
                    printf("Registration failed. Please try again.\n");
                    printLine();
                }
                break;
            }
            case 0:
            {
                cleanScreen();
                printf("Exiting...\n");
                printLine();

                sqlite3_close(db);

                return 0;
            }
            default:
            {
                cleanScreen();
                printf("Invalid option. Please try again.\n");
                printLine();
            }
        }
    }
}

// -------------------------------------------------------

// ----------------- Function Definitions ----------------

static void to_hex(const unsigned char* in, size_t len, char* out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++)
    {
        out[i * 2] = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}

static bool from_hex(const char* hex, unsigned char* out, size_t outlen) 
{
    size_t len = strlen(hex);
    if (len != outlen*2) return 0;
    for (size_t i = 0; i < outlen; ++i) 
    {
        char c1 = hex[2*i], c2 = hex[2*i+1];
        int v1 = (c1 >= '0' && c1 <= '9') ? c1-'0' : (c1|32) >= 'a' && (c1|32) <= 'f' ? (c1|32)-'a'+10 : -1;
        int v2 = (c2 >= '0' && c2 <= '9') ? c2-'0' : (c2|32) >= 'a' && (c2|32) <= 'f' ? (c2|32)-'a'+10 : -1;
        if (v1 < 0 || v2 < 0) return 0;
        out[i] = (unsigned char)((v1 << 4) | v2);
    }

    return 1;
}

bool hash_password(const char* password, char* out, size_t outlen) 
{
    const int iterations = 200000;
    const size_t salt_len = 16;
    const size_t dk_len = 32;

    unsigned char salt[salt_len];
    unsigned char dk[dk_len];
    if (RAND_bytes(salt, (int)salt_len) != 1) return 0;

    if (!PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, (int)salt_len,
                           iterations,
                           EVP_sha256(), (int)dk_len, dk)) 
    {
        return 0;
    }

    char salt_hex[salt_len*2 + 1];
    char dk_hex[dk_len*2 + 1];
    to_hex(salt, salt_len, salt_hex);
    to_hex(dk, dk_len, dk_hex);

    int n = snprintf(out, outlen, "pbkdf2_sha256$%d$%s$%s", iterations, salt_hex, dk_hex);
    return n > 0 && (size_t)n < outlen;
}

bool verify_password(const char* password, const char* record) 
{
    if (strchr(record, '$') == NULL) 
    {
        size_t lp = strlen(password), lr = strlen(record);
        if (lp != lr) return 0;
        return CRYPTO_memcmp(password, record, lp) == 0;
    }

    // format: pbkdf2_sha256$iters$salt_hex$hash_hex
    char alg[32];
    int iterations = 0;
    char salt_hex[128];
    char hash_hex[128];

    if (sscanf(record, "%31[^$]$%d$%127[^$]$%127s", alg, &iterations, salt_hex, hash_hex) != 4)
        return 0;
    if (strcmp(alg, "pbkdf2_sha256") != 0 || iterations <= 0) return 0;

    const size_t salt_len = strlen(salt_hex)/2;
    const size_t dk_len = strlen(hash_hex)/2;
    if (salt_len == 0 || dk_len == 0) return 0;

    unsigned char salt[64], dk_stored[64], dk_calc[64];
    if (salt_len > sizeof(salt) || dk_len > sizeof(dk_stored)) return 0;

    if (!from_hex(salt_hex, salt, salt_len)) return 0;
    if (!from_hex(hash_hex, dk_stored, dk_len)) return 0;

    if (!PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, (int)salt_len,
                           iterations, EVP_sha256(),
                           (int)dk_len, dk_calc)) 
    {
        return 0;
    }

    return CRYPTO_memcmp(dk_calc, dk_stored, dk_len) == 0;
}

void cleanScreen()
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void printLine()
{
    printf("-------------------------------------\n");
}

static void closeDatabase()
{
    if (db)
    {
        sqlite3_close(db);
        db = NULL;
    }
}

static sqlite3* getDatabase() 
{
    if (!db) 
    {
        int rc = sqlite3_open_v2
        (
            "bank.db", &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, /* | SQLITE_OPEN_FULLMUTEX */
            NULL
        );

        if (rc != SQLITE_OK) 
        {
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
            closeDatabase();
            return NULL;
        }

        const char* sql =
            "CREATE TABLE IF NOT EXISTS users ("
            "login TEXT PRIMARY KEY,"
            "password TEXT NOT NULL,"
            "name TEXT,"
            "surname TEXT,"
            "dayofbirth TEXT,"
            "address TEXT,"
            "phone TEXT,"
            "email TEXT,"
            "idNumber TEXT,"
            "accountNumber TEXT,"
            "balance REAL"
            ");";

        char* err = NULL;

        rc = sqlite3_exec(db, sql, 0, 0, &err);

        if (rc != SQLITE_OK) 
        {
            fprintf(stderr, "SQL error: %s\n", err);
            sqlite3_free(err);
            closeDatabase();
            return NULL;
        }
    }

    return db;
}

static void trimLine(char* s)
{
    if (!s) return;
    s[strcspn(s, "\n")] = '\0';
}

void getLogin(char* buffer, size_t size)
{
    if (!fgets(buffer, size, stdin)) 
    {
        if (size) buffer[0] = '\0';
        return;
    }

    char* nl = strpbrk(buffer, "\r\n");
    if (nl) 
    {
        char c = *nl;
        *nl = '\0';

        if (c == '\r') 
        {
            int ch = getchar();
            if (ch != '\n' && ch != EOF) ungetc(ch, stdin);
        }
    } 
    else 
    {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {}
    }
}

void getPassword(char* buffer, size_t size)
{
    struct termios oldt, newt;

    tcflush(STDIN_FILENO, TCIFLUSH);

    // get terminal settings
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    // disable echo
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    fgets(buffer, size, stdin);

    // restore terminal settings 
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    // remove newline character
    buffer[strcspn(buffer, "\n")] = '\0';
    printf("\n");
}

User* loginBank(void)
{
    sqlite3* db = getDatabase();
    if (!db) return NULL;

    cleanScreen();
    printf("--------------- Login ---------------\n");

    char login[32];
    char password[50];

    printf("Enter your login: ");
    fflush(stdout);
    getLogin(login, sizeof(login));

    printf("Enter your password: ");
    fflush(stdout);
    getPassword(password, sizeof(password));

    // Check in database
    sqlite3_stmt* stmt;

    const char* sql = "SELECT login, password, name, surname, dayofbirth, address, phone, email, idNumber, accountNumber, balance FROM users WHERE login = ? AND password = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, login, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        strcpy(loggedUser.login, (const char*)sqlite3_column_text(stmt, 0));
        strcpy(loggedUser.password, (const char*)sqlite3_column_text(stmt, 1));
        strcpy(loggedUser.info.name, (const char*)sqlite3_column_text(stmt, 2));
        strcpy(loggedUser.info.surname, (const char*)sqlite3_column_text(stmt, 3));
        strcpy(loggedUser.info.dayofbirth, (const char*)sqlite3_column_text(stmt, 4));
        strcpy(loggedUser.info.address, (const char*)sqlite3_column_text(stmt, 5));
        strcpy(loggedUser.info.phone, (const char*)sqlite3_column_text(stmt, 6));
        strcpy(loggedUser.info.email, (const char*)sqlite3_column_text(stmt, 7));
        strcpy(loggedUser.info.idNumber, (const char*)sqlite3_column_text(stmt, 8));
        strcpy(loggedUser.info.accountNumber, (const char*)sqlite3_column_text(stmt, 9));
        loggedUser.info.balance = sqlite3_column_double(stmt, 9);

        sqlite3_finalize(stmt);

        cleanScreen();
        printf("Login successful! Welcome %s %s.\n", loggedUser.info.name, loggedUser.info.surname);
        printLine();

        bankMainPage();

        return &loggedUser;
    }
    else
    {
        cleanScreen();
        printf("Invalid login or password. Please try again.\n");
        printLine();
    }

    return NULL;
}

bool registerUser(void)
{
    sqlite3* db = getDatabase();
    if (!db) return false;

    User u;
    cleanScreen();
    printf("-------------- Register -------------\n");

    // Info

    printf("Enter your name: ");
    fgets(u.info.name, sizeof(u.info.name), stdin);

    printf("Enter your surname: ");
    fgets(u.info.surname, sizeof(u.info.surname), stdin);

    printf("Enter your date of birth (YYYY-MM-DD): ");
    fgets(u.info.dayofbirth, sizeof(u.info.dayofbirth), stdin);

    printf("Enter your address: ");
    fgets(u.info.address, sizeof(u.info.address), stdin);

    printf("Enter your phone: ");
    fgets(u.info.phone, sizeof(u.info.phone), stdin);

    printf("Enter your email: ");
    fgets(u.info.email, sizeof(u.info.email), stdin);

    printf("Enter your ID number: ");
    fgets(u.info.idNumber, sizeof(u.info.idNumber), stdin);

    // Randomly generate account number
    randomAccountNumber(u.info.accountNumber, sizeof(u.info.accountNumber));
    u.info.balance = 0.0;

    // Login / Password

    randomAccountNumber(u.login, sizeof(u.login));
    printf("Your generated login is: %s\n", u.login);

    printf("Enter your password: ");
    getPassword(u.password, sizeof(u.password));

    printf("Confirm your password: ");
    char confirmPassword[50];
    getPassword(confirmPassword, sizeof(confirmPassword));

    if (strcmp(u.password, confirmPassword) != 0)
    {
        cleanScreen();
        printf("Passwords do not match. Registration failed.\n");
        printLine();
        return false;
    }

    printf("Do you accept the terms and conditions? (y/n): ");
    char choice;

    char ynbuf[8];
    if (!fgets(ynbuf, sizeof(ynbuf), stdin))
    {
        cleanScreen();
        printf("Input error. Registration failed.\n");
        printLine();
        return false;
    }

    trimLine(ynbuf);
    choice = ynbuf[0];

    if (choice != 'y' && choice != 'Y')
    {
        cleanScreen();
        printf("You must accept the terms and conditions to register. Registration failed.\n");
        printLine();
        return false;
    }

    // Save to database

    sqlite3_stmt* stmt;

    const char* sql = "INSERT INTO users (login, password, name, surname, dayofbirth, address, phone, email, idNumber, accountNumber, balance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_bind_text(stmt, 1, u.login, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, u.password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, u.info.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, u.info.surname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, u.info.dayofbirth, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, u.info.address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, u.info.phone, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, u.info.email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, u.info.idNumber, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, u.info.accountNumber, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 11, u.info.balance);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);

    return true;
}

void randomAccountNumber(char* buffer, size_t size)
{
    if (!buffer || size == 0) return;

    size_t n = size - 1;
    for (size_t i = 0; i < n; i++)
    {
        buffer[i] = '0' + (rand() % 10);
    }

    buffer[n] = '\0';
}

void userOperationsPage(User user)
{
    cleanScreen();
    printf("---------- User Operations ----------\n");
    printf("1. Deposit Money\n");
    printf("2. Withdraw Money\n");
    printf("3. Transfer Money\n");
    printf("0. Back to Main Menu\n");

    char buf[100];
    int choice;
    printf("Choose an option: ");
    fgets(buf, sizeof(buf), stdin);
    choice = atoi(buf);

    switch (choice)
    {
        case 1:
        {
            cleanScreen();
            userOperationsDepositPage(loggedUser);
            printLine();
            break;
        }
        case 2:
        {
            cleanScreen();
            userOperationsWithdrawPage(loggedUser);
            printLine();
            break;
        }
        case 3:
        {
            cleanScreen();
            userOperationsTransferPage(loggedUser);
            printLine();
            break;
        }
        case 0:
        {
            cleanScreen();
            bankMainPage();
            return;
        }
        default:
        {
            cleanScreen();
            printf("Invalid option. Please try again.\n");
            printLine();
        }
    }
}

void userOperationsDepositPage(User user)
{
    sqlite3* db = getDatabase();
    if (!db) return;

    cleanScreen();
    printf("--------- Deposit Money ---------\n");
    printf("Current Balance: %.2f\n", user.info.balance);

    char buf[100];
    double amount;
    printf("Enter amount to deposit: ");
    fgets(buf, sizeof(buf), stdin);

    amount = atof(buf);
    if (amount <= 0)
    {
        cleanScreen();
        printf("Invalid amount. Please try again.\n");
        printLine();
        return;
    }

    user.info.balance += amount;

    sqlite3_stmt* stmt;
    const char* sql = "UPDATE users SET balance = ? WHERE login = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_double(stmt, 1, user.info.balance);
    sqlite3_bind_text(stmt, 2, user.login, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    sqlite3_finalize(stmt);
}

void userOperationsWithdrawPage(User user)
{
    sqlite3* db = getDatabase();
    if (!db) return;

    cleanScreen();
    printf("-------- Withdraw Money --------\n");
    printf("Current Balance: %.2f\n", user.info.balance);
    
    char buf[100];
    double amount;

    printf("Enter amount to withdraw: ");
    fgets(buf, sizeof(buf), stdin);

    amount = atof(buf);
    if (amount <= 0 || amount > user.info.balance)
    {
        cleanScreen();
        printf("Invalid amount. Please try again.\n");
        printLine();
        return;
    }

    user.info.balance -= amount;
    
    sqlite3_stmt* stmt;

    const char* sql = "UPDATE users SET balance = ? WHERE login = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_double(stmt, 1, user.info.balance);
    sqlite3_bind_text(stmt, 2, user.login, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    sqlite3_finalize(stmt);
}

void userOperationsTransferPage(User user)
{
    sqlite3* db = getDatabase();
    if (!db) return;

    cleanScreen();
    printf("-------- Transfer Money --------\n");
    printf("Current Balance: %.2f\n", user.info.balance);

    char buf[100];
    char targetAccount[20];
    double amount;

    printf("Enter target account number: ");
    fgets(targetAccount, sizeof(targetAccount), stdin);
    trimLine(targetAccount);

    printf("Enter amount to transfer: ");
    fgets(buf, sizeof(buf), stdin);

    amount = atof(buf);
    if (amount <= 0 || amount > user.info.balance)
    {
        cleanScreen();
        printf("Invalid amount. Please try again.\n");
        printLine();
        return;
    }

    sqlite3_stmt* stmt;
    const char* sql = "SELECT login, balance FROM users WHERE accountNumber = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_text(stmt, 1, targetAccount, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        cleanScreen();
        printf("Target account not found. Please try again.\n");
        printLine();
        sqlite3_finalize(stmt);
        return;
    }

    char targetLogin[32];
    strcpy(targetLogin, (const char*)sqlite3_column_text(stmt, 0));
    double targetBalance = sqlite3_column_double(stmt, 1);
    sqlite3_finalize(stmt);

    user.info.balance -= amount;
    targetBalance += amount;
}

void userInfoPage(User user)
{
    cleanScreen();
    printf("----------- User Information ----------\n");
    printf("Name: %s\n", user.info.name);
    printf("Surname: %s\n", user.info.surname);
    printf("Date of Birth: %s\n", user.info.dayofbirth);
    printf("Address: %s\n", user.info.address); 
    printf("Phone: %s\n", user.info.phone);
    printf("Email: %s\n", user.info.email);
    printf("ID Number: %s\n", user.info.idNumber);
    printf("Account Number: %s\n", user.info.accountNumber);
    printf("Balance: %.2f\n", user.info.balance);

    printLine();
    printf("Press Enter to return to the main menu...");
    getchar();

    bankMainPage();
}

void userSettingsPage(User user)
{
    cleanScreen();
    printf("----------- User Settings -----------\n");
    printf("1. Change Password\n");
    printf("2. Update Contact Info\n");
    printf("0. Back to Main Menu\n");

    char buf[100];
    int choice;
    printf("Choose an option: ");
    fgets(buf, sizeof(buf), stdin);
    choice = atoi(buf);

    switch (choice)
    {
        case 1:
        {
            cleanScreen();
            userSettingsChangePasswordPage(loggedUser);
            printLine();
            break;
        }
        case 2:
        {
            cleanScreen();
            userSettingsUpdateContactInfoPage(loggedUser);
            printLine();
            break;
        }
        case 0:
        {
            cleanScreen();
            bankMainPage();
            return;
        }
        default:
        {
            cleanScreen();
            printf("Invalid option. Please try again.\n");
            printLine();
        }
    }
}

void userSettingsChangePasswordPage(User user)
{
    sqlite3* db = getDatabase();
    if (!db) return;

    cleanScreen();
    printf("------- Change Password -------\n");

    char currentPassword[50];
    char newPassword[50];
    char confirmPassword[50];

    printf("Enter your current password: ");
    getPassword(currentPassword, sizeof(currentPassword));

    if (strcmp(currentPassword, user.password) != 0)
    {
        cleanScreen();
        printf("Current password is incorrect. Please try again.\n");
        printLine();
        return;
    }

    printf("Enter your new password: ");
    getPassword(newPassword, sizeof(newPassword));

    printf("Confirm your new password: ");
    getPassword(confirmPassword, sizeof(confirmPassword));

    if (strcmp(newPassword, confirmPassword) != 0)
    {
        cleanScreen();
        printf("New passwords do not match. Please try again.\n");
        printLine();
        return;
    }

    strcpy(user.password, newPassword);

    sqlite3_stmt* stmt;
    const char* sql = "UPDATE users SET password = ? WHERE login = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_text(stmt, 1, user.password, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user.login, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    sqlite3_finalize(stmt);

    cleanScreen();
    printf("Password changed successfully.\n");
    printLine();
}

void userSettingsUpdateContactInfoPage(User user)
{
    sqlite3* db = getDatabase();
    if (!db) return;

    cleanScreen();
    printf("----- Update Contact Info -----\n");
    printf("Current Name: %s\n", user.info.name);
    printf("Current Surname: %s\n", user.info.surname);
    printf("Current Address: %s\n", user.info.address);
    printf("Current Phone: %s\n", user.info.phone);
    printf("Current Email: %s\n", user.info.email);
    printf("Current ID Number: %s\n", user.info.idNumber);

    char buf[100];
    printf("Enter new name (or press Enter to keep current): ");
    fgets(buf, sizeof(buf), stdin);
    trimLine(buf);
    if (strlen(buf) > 0) strcpy(user.info.name, buf);

    printf("Enter new surname (or press Enter to keep current): ");
    fgets(buf, sizeof(buf), stdin);
    trimLine(buf);
    if (strlen(buf) > 0) strcpy(user.info.surname, buf);

    printf("Enter new address (or press Enter to keep current): ");
    fgets(buf, sizeof(buf), stdin);
    trimLine(buf);
    if (strlen(buf) > 0) strcpy(user.info.address, buf);

    printf("Enter new phone (or press Enter to keep current): ");
    fgets(buf, sizeof(buf), stdin);
    trimLine(buf);
    if (strlen(buf) > 0) strcpy(user.info.phone, buf);

    printf("Enter new email (or press Enter to keep current): ");
    fgets(buf, sizeof(buf), stdin);
    trimLine(buf);
    if (strlen(buf) > 0) strcpy(user.info.email, buf);

    printf("Enter new ID number (or press Enter to keep current): ");
    fgets(buf, sizeof(buf), stdin);
    trimLine(buf);
    if (strlen(buf) > 0) strcpy(user.info.idNumber, buf);

    sqlite3_stmt* stmt;
    const char* sql = "UPDATE users SET name = ?, surname = ?, address = ?, phone = ?, email = ?, idNumber = ? WHERE login = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_text(stmt, 1, user.info.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user.info.surname, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user.info.address, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, user.info.phone, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, user.info.email, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, user.info.idNumber, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, user.login, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    sqlite3_finalize(stmt);
}

void bankMainPage()
{
    cleanScreen();
    printf("------------ Bank Main Page -----------\n");
    printf("1. Operations\n");
    printf("2. Information\n");
    printf("3. Settings\n");

    printf("0. Logout\n");
    printLine();

    char buf[100];
    int choice;
    printf("Choose an option: ");
    fgets(buf, sizeof(buf), stdin);
    choice = atoi(buf);

    switch (choice)
    {
        case 1:
        {
            cleanScreen();
            userOperationsPage(loggedUser);
            printLine();
            break;
        }
        case 2:
        {
            cleanScreen();
            userInfoPage(loggedUser);
            break;
        }
        case 3:
        {
            cleanScreen();
            userSettingsPage(loggedUser);
            break;
        }
        case 0:
        {
            cleanScreen();
            memset(&loggedUser, 0, sizeof(loggedUser));
            printf("Logging out...\n");
            break;
        }
        default:
        {
            cleanScreen();
            printf("Invalid option. Please try again.\n");
            printLine();
        }
    }
}

// -------------------------------------------------------
