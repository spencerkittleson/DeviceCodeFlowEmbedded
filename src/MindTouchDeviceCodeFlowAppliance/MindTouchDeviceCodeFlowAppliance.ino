#include <ESP8266WiFi.h> // https://github.com/esp8266/Arduino
#include <ESP8266HTTPClient.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <WiFiManager.h> // https://github.com/tzapu/WiFiManager
#include <ArduinoJson.h>
#include <Arduino.h>

#include <ESPAsyncTCP.h>       // https://github.com/me-no-dev/ESPAsyncTCP
#define WEBSERVER_H            // https://github.com/me-no-dev/ESPAsyncWebServer/issues/418
#include <ESPAsyncWebServer.h> // https://github.com/me-no-dev/ESPAsyncWebServer

#define APPLIANCE_NAME F("ApplianceModel001")
const char *AUTH_ID = "-";
const char *AUTH_DOMAIN = "-";
const char *AUTH_DEVICE_KEY = "-";
const char *AUTH_DEVICE_SECERT = "-";
DynamicJsonDocument initalResponse(JSON_OBJECT_SIZE(6) + 400);
DynamicJsonDocument authenticatedResponse(JSON_OBJECT_SIZE(5) + 750);
char email[100];
int authCheckPeriod = 1000;
unsigned long timeNow = 0;
bool updateUserProfile = false;

AsyncWebServer httpServer(80); // https://github.com/me-no-dev/ESPAsyncWebServer/blob/master/examples/simple_server/simple_server.ino

void setup()
{
  Serial.begin(115200);
  WiFiManager wifiManager;

  //set custom ip for portal
  wifiManager.setAPStaticIPConfig(IPAddress(10, 0, 1, 1), IPAddress(10, 0, 1, 1), IPAddress(255, 255, 255, 0));
  Serial.printf("Connect to wifi device: %s to ip address: 10.0.1.1\n", APPLIANCE_NAME);

  // Connect to this access point
  wifiManager.autoConnect(String(APPLIANCE_NAME).c_str());
  Serial.println("Wifi Connected");

  requestIdentity();

  // Simple async web server
  setupWebServer();
}

void loop()
{
  if (initalResponse.containsKey("device_code"))
    pollAccessToken();

  if (updateUserProfile)
  {
    updateUserProfile = false;
    getCurrentUserProfile();
  }
}

/**
 * Get the current user profile and store it for later use
 */
void getCurrentUserProfile()
{
  // User profile response is large. Get the individual properties needed then remove it.
  const size_t capacity = 5 * JSON_OBJECT_SIZE(1) + 6 * JSON_OBJECT_SIZE(2) + 2 * JSON_OBJECT_SIZE(3) + JSON_OBJECT_SIZE(11) + JSON_OBJECT_SIZE(27) + 1930;
  DynamicJsonDocument currentUserResponse(capacity);
  String path = "/@api/deki/users/current?dream.out.format=json";
  httpRequest(AUTH_DOMAIN, path.c_str(), &currentUserResponse, false, "", true);
  //serializeJsonPretty(currentUserResponse, Serial);
  const char *tmpEmail = currentUserResponse["email"];
  strcpy(email, tmpEmail);
  currentUserResponse.clear();
}

void requestIdentity()
{
  // This device will request the user for identity.
  String path = "/@app/auth/" + String(AUTH_ID) + "/token/device.json";
  if (httpRequest(AUTH_DOMAIN, path.c_str(), &initalResponse, true, "scope=profile", false) == 200)
  {
    authCheckPeriod = initalResponse["interval"].as<int>() * 1000;
    serializeJsonPretty(initalResponse, Serial);
  }
  else
    Serial.print("Failed to start device code flow. Check auth configuration");
}

void pollAccessToken()
{
  if (millis() > timeNow + authCheckPeriod)
  {
    timeNow = millis();

    // Did the user enter the user code?
    String path = "/@app/auth/" + String(AUTH_ID) + "/token/access.json";
    String body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=" + String(initalResponse["device_code"].as<char *>());
    int authResponseHttpStatusCode = httpRequest(AUTH_DOMAIN, path.c_str(), &authenticatedResponse, true, body.c_str(), false);
    if (authResponseHttpStatusCode == HTTP_CODE_OK)
    {

      // Great! lets clear out the inital response object and keep the authenticated response which will be used to maintain existing auth state.
      initalResponse.clear();
      updateUserProfile = true;

      // Shave off some time so it expires sooner
      authenticatedResponse["expires_in"] = authenticatedResponse["expires_in"].as<int>() - 100;
      serializeJsonPretty(authenticatedResponse, Serial);
    }
    else if (authResponseHttpStatusCode == HTTP_CODE_PRECONDITION_REQUIRED)
      Serial.println("Waiting for the user to accept");
    else
    {
      Serial.print("Failed to get auth code. Status code: ");
      Serial.println(authResponseHttpStatusCode);
    }

    // Decrement expires_in
    initalResponse["expires_in"] = initalResponse["expires_in"].as<int>() - initalResponse["interval"].as<int>();
    if (initalResponse["expires_in"].as<int>() < 0)
    {
      Serial.println("User did not authenticate in time.  Restart the device");
      delay(5000);

      // A forever loop to cause the device to reboot
      while (1)
        ;
      ;
    }
  }
}

void refreshToken()
{
  if (authenticatedResponse.containsKey("access_token"))
  {
    authenticatedResponse["expires_in"] = authenticatedResponse["expires_in"].as<int>() - (authCheckPeriod / 1000);
    String path = "/@app/auth/" + String(AUTH_ID) + "/token/access.json";
    String body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=" + String(initalResponse["device_code"].as<char *>());
    DynamicJsonDocument doc(1024);
    int authResponseHttpStatusCode = httpRequest(AUTH_DOMAIN, path.c_str(), &doc, true, body.c_str(), true);
    if (authResponseHttpStatusCode == HTTP_CODE_OK)
    {
      serializeJsonPretty(doc, Serial);
    }
  }
}

int httpRequest(const char *domain, const char *path, DynamicJsonDocument *doc, bool isPost, const char *message, bool useBearer)
{
  HTTPClient https;

  // Insecure https client. Use from the cert store instead. See example: https://github.com/esp8266/Arduino/blob/master/libraries/ESP8266WiFi/examples/BearSSL_CertStore/BearSSL_CertStore.ino
  BearSSL::WiFiClientSecure secureClient;
  secureClient.setInsecure();
  https.begin(secureClient, domain, 443, path, true);
  if (useBearer)
  {
    String bearer = ("Bearer " + String(authenticatedResponse["access_token"].as<char *>()));
    https.addHeader(F("Authorization"), bearer);
  }
  else
    https.setAuthorization(AUTH_DEVICE_KEY, AUTH_DEVICE_SECERT);
  int httpStatusCode = 0;
  if (isPost)
  {
    https.addHeader(F("Content-Type"), F("application/x-www-form-urlencoded"));
    httpStatusCode = https.POST(message);
  }
  else
  {
    https.addHeader(F("Content-Type"), F("application/json"));
    httpStatusCode = https.GET();
  }
  if (httpStatusCode == HTTP_CODE_OK | httpStatusCode == HTTP_CODE_PRECONDITION_REQUIRED)
  {

    // This appears to be a bug in MindTouch JSON responses.  Why escape '/'?!
    auto response = https.getString();
    response.replace("\\/", "/");

    // Parse JSON object
    DeserializationError error = deserializeJson((*doc), response);
    if (error)
    {
      Serial.print(F("deserializeJson() failed: "));
      Serial.println(error.c_str());
      httpStatusCode = -1;
    }
  }
  else
  {
    Serial.printf("[HTTP] GET... failed, error: %s\n", https.errorToString(httpStatusCode).c_str());
    String response = https.getString();
    Serial.println(response);
  }
  https.end();
  secureClient.stop();
  return httpStatusCode;
}

/**
 *  A simple web server for a basic interface for this appliance
 */
void setupWebServer()
{
  httpServer.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    String body = "<!DOCTYPE html> <html>\n";
    body += "<head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, user-scalable=no\">\n";
    body += "<title>";
    body += APPLIANCE_NAME;
    body += "</title>\n";
    body += "<style>html { font-family: Helvetica; display: inline-block; margin: 0px auto; text-align: center;}\n";
    body += "body{margin-top: 50px;} h1 {color: #444444;margin: 50px auto 30px;} h3 {color: #444444;margin-bottom: 50px;}\n";
    body += ".button {display: block;min-width: 80px; max-width:200px;background-color: #1abc9c;border: none;color: white;padding: 13px 30px;text-decoration: none;font-size: 25px;margin: 0px auto 35px;cursor: pointer;border-radius: 4px;}\n";
    body += ".button-on {background-color: #1abc9c;}\n";
    body += ".button-on:active {background-color: #16a085;}\n";
    body += ".button-off {background-color: #34495e;}\n";
    body += ".button-off:active {background-color: #2c3e50;}\n";
    body += "p {font-size: 14px;color: #888;margin-bottom: 10px;}\n";
    body += "</style>\n";
    body += "</head>\n";
    body += "<body>\n";
    body += "<h1>";
    body += APPLIANCE_NAME;
    body += "</h1>\n";
    body += "<h3>Control Panel Interface</h3>\n";
    body += "{{BODY}}</br></body></html>";

    // User has not accepted user code yet.  They need to click on the `verification_uri_complete`
    if (initalResponse.containsKey("device_code") & !authenticatedResponse.containsKey("access_token"))
    {
      body.replace("{{BODY}}", "<p>Setup of your new device is required to use it. Verify this device by completing the user code validation. Refresh this page when done.</p> <br/> <h3>User Code: <a href='{{VERIFICATION_URI_COMPLETE}}' target='_blank'>{{USER_CODE}}</a></h3>");
      body.replace("{{USER_CODE}}", initalResponse["user_code"].as<char *>());
      body.replace("{{VERIFICATION_URI_COMPLETE}}", initalResponse["verification_uri_complete"].as<char *>());
    }
    else if (!initalResponse.containsKey("device_code") & authenticatedResponse.containsKey("access_token"))
    {
      body.replace("{{BODY}}", "<p>Hello {{EMAIL}}, this is your new device! Learn all about by looking at the <a href='https://{{AUTH_DOMAIN}}'>documentation and guides</a>.</br></br><a class='button' href='/get?action=logout'>logout</a>");
      body.replace("{{AUTH_DOMAIN}}", AUTH_DOMAIN);
      body.replace("{{EMAIL}}", String(email));
    }
    else
      body.replace("{{BODY}}", "<p>Unable to authorize. Find information about your device at our <a href='https://{{AUTH_DOMAIN}}'>support site</a>.</p>");

    request->send(200, "text/html", body);
  });

  // Send a GET request to <IP>/get?action=<action>
  httpServer.on("/get", HTTP_GET, [](AsyncWebServerRequest *request) {
    String action;
    if (request->hasParam("action"))
    {
      action = request->getParam("action")->value();
      if (action.equalsIgnoreCase("logout"))
      {
        authenticatedResponse.clear();
      }
      AsyncWebServerResponse *response = request->beginResponse(302, "text/html", "");
      response->addHeader("Location", "/");
      request->send(response);
    }
    else
      request->send(HTTP_CODE_OK, "text/plain", "OK");
  });
  httpServer.onNotFound([](AsyncWebServerRequest *request) {
    request->send(HTTP_CODE_NOT_FOUND, "text/plain", "Not found");
  });
  httpServer.begin();
}
