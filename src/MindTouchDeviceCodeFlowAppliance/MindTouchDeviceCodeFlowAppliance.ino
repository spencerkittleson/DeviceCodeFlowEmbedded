#include <ESP8266WiFi.h> //https://github.com/esp8266/Arduino
#include <ESP8266HTTPClient.h>

#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <WiFiManager.h> //https://github.com/tzapu/WiFiManager
#include <ArduinoJson.h>
#include <Arduino.h>

const char *AUTH_ID = "1";
const char *AUTH_DOMAIN = "-";
const char *AUTH_DEVICE_KEY = "-";
const char *AUTH_DEVICE_SECERT = "-";
DynamicJsonDocument initalResponse(1024);
DynamicJsonDocument authenticatedResponse(1024);
int auth_check_period = 1000;
unsigned long time_now = 0;

void setup()
{
  Serial.begin(115200);
  WiFiManager wifiManager;

  //set custom ip for portal
  wifiManager.setAPStaticIPConfig(IPAddress(10, 0, 1, 1), IPAddress(10, 0, 1, 1), IPAddress(255, 255, 255, 0));
  Serial.println("Connect to wifi device: ApplianceModel001 to ip address: 10.0.0.1");

  // Connect to this access point
  wifiManager.autoConnect("ApplianceModel001");
  Serial.println("Wifi Connected");

  // This device will request the user for identity.
  String path = "/@app/auth/" + String(AUTH_ID) + "/token/device.json";
  if (httpRequest(path.c_str(), &initalResponse, true, "scope=profile", false) == 200)
  {
    auth_check_period = initalResponse["interval"].as<int>() * 1000;
    serializeJsonPretty(initalResponse, Serial);
  }
  else
  {
    Serial.print("Failed to start device code flow. Check auth configuration");
  }
}

void loop()
{
  pollAccessToken();
  //refreshToken();
  if (authenticatedResponse.containsKey("access_token"))
  {
    const char *path = "/@api/deki/users/current?dream.out.format=json";
    int authResponseHttpStatusCode = httpRequest(path, &authenticatedResponse, true, "", true);
  }
}

void pollAccessToken()
{
  if (initalResponse.containsKey("device_code"))
  {
    if (millis() > time_now + auth_check_period)
    {
      time_now = millis();

      // Did the user enter the user code?
      const char *path = ("/@app/auth/" + String(AUTH_ID) + "/token/access.json").c_str();
      const char *body = ("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=" + String(initalResponse["device_code"].as<char *>())).c_str();
      int authResponseHttpStatusCode = httpRequest(path, &authenticatedResponse, true, body, false);
      if (authResponseHttpStatusCode == 200)
      {

        // Great! lets clear out the inital response object and keep the authenticated response which will be used to maintain existing auth state.
        initalResponse.clear();

        // serializeJsonPretty(authenticatedResponse, Serial);
        // Shave off some time so it expires sooner
        authenticatedResponse["expires_in"] = authenticatedResponse["expires_in"].as<int>() - 100;
      }
      else if (authResponseHttpStatusCode == 428)
      {
        Serial.println("Waiting for the user to accept");
      }
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
        while (1)
          ;
        ;
      }
    }
  }
}

void refreshToken()
{
  if (authenticatedResponse.containsKey("access_token"))
  {
    if (millis() > time_now + auth_check_period)
    {
      authenticatedResponse["expires_in"] = authenticatedResponse["expires_in"].as<int>() - (auth_check_period / 1000);
      serializeJsonPretty(authenticatedResponse, Serial);
      // refresh token logic here
    }
  }
}

int httpRequest(const char *path, DynamicJsonDocument *doc, bool isPost, const char *message, bool useBearer)
{
  HTTPClient https;

  // Insecure https client. Use from the cert store instead. See example: https://github.com/esp8266/Arduino/blob/master/libraries/ESP8266WiFi/examples/BearSSL_CertStore/BearSSL_CertStore.ino
  BearSSL::WiFiClientSecure secureClient;
  secureClient.setInsecure();
  https.begin(secureClient, AUTH_DOMAIN, 443, path, true);
  if (useBearer)
  {
    // TODO (spencerk): use given auth from json doc
    const char *bearer = ("Bearer " + String(authenticatedResponse["access_token"].as<char *>())).c_str();
    https.setAuthorization(bearer);
  }
  else
  {
    https.setAuthorization(AUTH_DEVICE_KEY, AUTH_DEVICE_SECERT);
  }
  https.addHeader("Content-Type", "application/x-www-form-urlencoded");
  int httpStatusCode = https.POST(message);
  if (httpStatusCode == 200 | httpStatusCode == 428)
  {

    // This appears to be a bug in MindTouch JSON responses.  Why escape '/'?!
    String response = https.getString();
    response.replace("\\/", "/");
    JsonObject obj = (*doc).as<JsonObject>();

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
    String response = https.getString();
    Serial.println(response);
    Serial.println(" http status code was: ");
    Serial.println(httpStatusCode);
  }
  https.end();
  secureClient.stop();
  return httpStatusCode;
}
