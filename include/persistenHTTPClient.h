#include <HTTPClient.h>
#include <string.h>

class PersistentHTTPClient {
private:
    HTTPClient http;
    String serverName;
    uint16_t serverPort;
    String serverPath;
    bool isConnected;

public:
    PersistentHTTPClient(const String& server, uint16_t port, const String& path) : serverName(server), serverPort(port), serverPath(path), isConnected(false) {}

    void ensureConnected() {
        if (http.connected() == false) {
            //http.setTimeout(500);
            isConnected = http.begin(serverName, serverPort, serverPath);
        }
    }

    int send(const String& data) {
        ensureConnected(); 

        http.addHeader("Content-Type", "application/json");
        int httpResponseCode = http.POST(data);

        if (httpResponseCode > 0) {
            Serial.println("[Slinkd HTTP Send] Send data correct.");
        } else {
            Serial.print("[Slinkd HTTP Send] Error code: ");
            Serial.print(httpResponseCode);
            Serial.print("  :  ");
            Serial.println(http.errorToString(httpResponseCode));
            
            http.end(); 
            isConnected = false;
            ensureConnected(); 
        }

        return httpResponseCode;
    }

    ~PersistentHTTPClient() {
        http.end(); 
    }
};
