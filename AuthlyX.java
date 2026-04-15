import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

public final class AuthlyX {
  public static final class ResponseStruct {
    public boolean success = false;
    public String message = "";
    public String code = "";
    public String raw = "";
    public int statusCode = 0;
  }

  public static final class UserData {
    public String Username = "";
    public String Email = "";
    public String LicenseKey = "";
    public String Subscription = "";
    public String SubscriptionLevel = "";
    public String ExpiryDate = "";
    public int DaysLeft = 0;
    public String LastLogin = "";
    public String RegisteredAt = "";
    public String Hwid = "";
    public String IpAddress = "";
  }

  public static final class VariableData {
    public String VarKey = "";
    public String VarValue = "";
  }

  private static final Gson GSON = new Gson();

  private final HttpClient http;
  private final String ownerId;
  private final String appName;
  private final String version;
  private final String secret;
  private final String apiBase;
  private final boolean debug;

  public final ResponseStruct response = new ResponseStruct();
  public final UserData userData = new UserData();
  public final VariableData variableData = new VariableData();

  private boolean initialized = false;
  private String sessionId = "";
  private String applicationHash = "";
  private String cachedPublicIp = "";
  private long cachedPublicIpExpiresAtMs = 0;

  public AuthlyX(String ownerId, String appName, String version, String secret) {
    this(ownerId, appName, version, secret, true, "https://authly.cc/api/v2");
  }

  public AuthlyX(String ownerId, String appName, String version, String secret, boolean debug, String apiBase) {
    this.ownerId = ownerId == null ? "" : ownerId.trim();
    this.appName = appName == null ? "" : appName.trim();
    this.version = version == null ? "" : version.trim();
    this.secret = secret == null ? "" : secret.trim();
    this.debug = debug;
    this.apiBase = (apiBase == null || apiBase.trim().isEmpty())
      ? "https://authly.cc/api/v2"
      : apiBase.trim().replaceAll("/+$", "");
    this.http = HttpClient.newBuilder()
      .connectTimeout(Duration.ofSeconds(10))
      .build();
  }

  public boolean Init() {
    return init();
  }

  public boolean init() {
    if (!hasRequiredCredentials()) {
      return setFailure("MISSING_CREDENTIALS", "Owner ID, app name, version, and secret are required.");
    }

    this.applicationHash = getCurrentApplicationHash();

    JsonObject payload = new JsonObject();
    payload.addProperty("owner_id", ownerId);
    payload.addProperty("app_name", appName);
    payload.addProperty("version", version);
    payload.addProperty("secret", secret);
    payload.addProperty("hash", applicationHash == null ? "" : applicationHash);

    JsonObject obj = postJson("init", payload);
    if (obj == null) return false;

    String sid = getAsString(obj, "session_id");
    if (sid != null && !sid.isBlank()) this.sessionId = sid;
    this.initialized = response.success && !this.sessionId.isBlank();
    return this.initialized;
  }

  public boolean Login(String identifier) {
    return login(identifier, null, null);
  }

  public boolean login(String identifier) {
    return login(identifier, null, null);
  }

  public boolean Login(String identifier, String password) {
    return login(identifier, password, null);
  }

  public boolean login(String identifier, String password) {
    return login(identifier, password, null);
  }

  public boolean Login(String identifier, String password, String deviceType) {
    return login(identifier, password, deviceType);
  }

  public boolean login(String identifier, String password, String deviceType) {
    if (deviceType != null && !deviceType.isBlank()) {
      return deviceLogin(deviceType, identifier);
    }
    if (password == null) {
      return licenseLogin(identifier);
    }
    return userLogin(identifier, password);
  }

  public boolean Register(String username, String password, String licenseKey, String email) {
    return register(username, password, licenseKey, email);
  }

  public boolean register(String username, String password, String licenseKey, String email) {
    if (!ensureInitialized()) return false;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("username", nvl(username));
    payload.addProperty("password", nvl(password));
    payload.addProperty("key", nvl(licenseKey));
    payload.addProperty("email", email == null ? "" : email);
    payload.addProperty("hwid", getSystemIdentifier());
    JsonObject obj = postJson("register", payload);
    return obj != null && response.success;
  }

  public void Log(String message) {
    log(message);
  }

  public void log(String message) {
    if (!ensureInitialized()) return;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("message", message == null ? "" : message);
    postJson("logs", payload);
  }

  public String GetChats(String channelName) {
    return getChats(channelName);
  }

  public String getChats(String channelName) {
    if (!ensureInitialized()) return null;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("channel_name", channelName == null ? "" : channelName);
    payload.addProperty("limit", 50);
    postJson("chats/get", payload);
    return response.raw;
  }

  public void SendChat(String message) {
    sendChat(message, "general");
  }

  public void sendChat(String message) {
    sendChat(message, "general");
  }

  public void SendChat(String message, String channelName) {
    sendChat(message, channelName);
  }

  public void sendChat(String message, String channelName) {
    if (!ensureInitialized()) return;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("channel_name", (channelName == null || channelName.isBlank()) ? "general" : channelName);
    payload.addProperty("message", message == null ? "" : message);
    postJson("chats/send", payload);
  }

  public boolean ExtendTime(String username, String licenseKey) {
    return extendTime(username, licenseKey);
  }

  public boolean extendTime(String username, String licenseKey) {
    if (!ensureInitialized()) return false;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("username", nvl(username));
    payload.addProperty("license_key", nvl(licenseKey));
    payload.addProperty("sid", getSystemIdentifier());
    payload.addProperty("ip", getPublicIp());
    JsonObject obj = postJson("extend", payload);
    return obj != null && response.success;
  }

  public boolean ChangePassword(String oldPassword, String newPassword) {
    return changePassword(oldPassword, newPassword);
  }

  public boolean changePassword(String oldPassword, String newPassword) {
    if (!ensureInitialized()) return false;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("old_password", nvl(oldPassword));
    payload.addProperty("new_password", nvl(newPassword));
    JsonObject obj = postJson("change-password", payload);
    return obj != null && response.success;
  }

  public String GetVariable(String key) {
    return getVariable(key);
  }

  public String getVariable(String key) {
    if (!ensureInitialized()) return "";
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("var_key", nvl(key));
    JsonObject obj = postJson("variables", payload);
    if (obj == null || !response.success) return "";
    return variableData.VarValue == null ? "" : variableData.VarValue;
  }

  public boolean SetVariable(String key, String value) {
    return setVariable(key, value);
  }

  public boolean setVariable(String key, String value) {
    if (!ensureInitialized()) return false;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("var_key", nvl(key));
    payload.addProperty("var_value", value == null ? "" : value);
    JsonObject obj = postJson("variables/set", payload);
    return obj != null && response.success;
  }

  public boolean ValidateSession() {
    return validateSession();
  }

  public boolean validateSession() {
    if (!initialized || sessionId.isBlank()) {
      return setFailure("INVALID_SESSION", "No active session. Please login first.");
    }
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    JsonObject obj = postJson("validate-session", payload);
    return obj != null && response.success;
  }

  public boolean IsInitialized() {
    return isInitialized();
  }

  public boolean isInitialized() {
    return initialized;
  }

  public String GetSessionId() {
    return getSessionId();
  }

  public String getSessionId() {
    return sessionId;
  }

  public String GetCurrentApplicationHash() {
    return getCurrentApplicationHash();
  }

  public String getCurrentApplicationHash() {
    try {
      URL loc = AuthlyX.class.getProtectionDomain().getCodeSource() == null
        ? null
        : AuthlyX.class.getProtectionDomain().getCodeSource().getLocation();
      if (loc == null) return "UNKNOWN_HASH";
      Path path = Paths.get(loc.toURI());
      if (Files.isDirectory(path)) return "UNKNOWN_HASH";
      byte[] bytes = Files.readAllBytes(path);
      return sha256Hex(bytes);
    } catch (Exception ignored) {
      return "UNKNOWN_HASH";
    }
  }

  private boolean userLogin(String username, String password) {
    if (!ensureInitialized()) return false;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("username", nvl(username));
    payload.addProperty("password", nvl(password));
    payload.addProperty("sid", getSystemIdentifier());
    payload.addProperty("ip", getPublicIp());
    JsonObject obj = postJson("login", payload);
    return obj != null && response.success;
  }

  private boolean licenseLogin(String licenseKey) {
    if (!ensureInitialized()) return false;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("license_key", nvl(licenseKey));
    payload.addProperty("sid", getSystemIdentifier());
    payload.addProperty("ip", getPublicIp());
    JsonObject obj = postJson("licenses", payload);
    return obj != null && response.success;
  }

  private boolean deviceLogin(String deviceType, String deviceId) {
    if (!ensureInitialized()) return false;
    JsonObject payload = new JsonObject();
    payload.addProperty("session_id", sessionId);
    payload.addProperty("device_type", (deviceType == null ? "" : deviceType).trim().toLowerCase(Locale.ROOT));
    payload.addProperty("device_id", nvl(deviceId));
    payload.addProperty("ip", getPublicIp());
    JsonObject obj = postJson("device-auth", payload);
    return obj != null && response.success;
  }

  private JsonObject postJson(String route, JsonObject payload) {
    resetResponse();

    String url = apiBase + "/" + route;
    String body = GSON.toJson(payload);

    if (debug) AuthlyXLogger.log(appName, "[SDK][REQUEST] POST " + url + " " + AuthlyXLogger.maskSensitive(body));

    HttpRequest req = HttpRequest.newBuilder()
      .uri(URI.create(url))
      .timeout(Duration.ofSeconds(25))
      .header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
      .build();

    try {
      HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      String respBody = resp.body() == null ? "" : resp.body();
      if (debug) AuthlyXLogger.log(appName, "[SDK][RESPONSE] " + resp.statusCode() + " " + AuthlyXLogger.maskSensitive(respBody));

      response.raw = respBody;
      response.statusCode = resp.statusCode();

      JsonObject obj = JsonParser.parseString(respBody).getAsJsonObject();
      response.success = getAsBool(obj, "success");
      response.message = Objects.toString(getAsString(obj, "message"), "");
      response.code = Objects.toString(getAsString(obj, "code"), "");

      if (obj.has("session_id")) {
        String sid = getAsString(obj, "session_id");
        if (sid != null && !sid.isBlank()) sessionId = sid;
      }

      loadUserData(obj);
      loadVariableData(obj);

      return obj;
    } catch (Exception ex) {
      return setFailure("NETWORK_ERROR", ex.getMessage() == null ? "Network error" : ex.getMessage()) ? null : null;
    }
  }

  private void loadUserData(JsonObject obj) {
    JsonObject u = obj.has("user") && obj.get("user").isJsonObject() ? obj.getAsJsonObject("user") : null;
    JsonObject l = obj.has("license") && obj.get("license").isJsonObject() ? obj.getAsJsonObject("license") : null;
    JsonObject d = obj.has("device") && obj.get("device").isJsonObject() ? obj.getAsJsonObject("device") : null;

    if (u != null) {
      userData.Username = Objects.toString(getAsString(u, "username"), "");
      userData.Email = Objects.toString(getAsString(u, "email"), "");
      userData.Subscription = Objects.toString(getAsString(u, "subscription"), "");
      userData.SubscriptionLevel = Objects.toString(getAsString(u, "subscription_level"), "");
      userData.ExpiryDate = Objects.toString(getAsString(u, "expiry_date"), "");
      userData.DaysLeft = getAsInt(u, "days_left");
      userData.LastLogin = Objects.toString(getAsString(u, "last_login"), "");
      userData.RegisteredAt = Objects.toString(getAsString(u, "registered_at"), "");
      userData.Hwid = Objects.toString(getAsString(u, "sid"), "");
      userData.IpAddress = Objects.toString(getAsString(u, "ip_address"), "");
    }
    if (l != null) {
      String key = getAsString(l, "license_key");
      if (key != null && !key.isBlank()) userData.LicenseKey = key;
      String sub = getAsString(l, "subscription");
      if (sub != null && !sub.isBlank()) userData.Subscription = sub;
      String lvl = getAsString(l, "subscription_level");
      if (lvl != null && !lvl.isBlank()) userData.SubscriptionLevel = lvl;
      String exp = getAsString(l, "expiry_date");
      if (exp != null && !exp.isBlank()) userData.ExpiryDate = exp;
      String ip = getAsString(l, "ip_address");
      if (ip != null && !ip.isBlank()) userData.IpAddress = ip;
      String sid = getAsString(l, "sid");
      if (sid != null && !sid.isBlank()) userData.Hwid = sid;
      Integer dl = getAsIntOrNull(l, "days_left");
      if (dl != null) userData.DaysLeft = dl;
      String ll = getAsString(l, "last_login");
      if (ll != null && !ll.isBlank()) userData.LastLogin = ll;
      String ra = getAsString(l, "registered_at");
      if (ra != null && !ra.isBlank()) userData.RegisteredAt = ra;
    }
    if (d != null) {
      String exp = getAsString(d, "expiry_date");
      if (exp != null && !exp.isBlank()) userData.ExpiryDate = exp;
      String ip = getAsString(d, "ip_address");
      if (ip != null && !ip.isBlank()) userData.IpAddress = ip;
      String sid = getAsString(d, "sid");
      if (sid != null && !sid.isBlank()) userData.Hwid = sid;
      Integer dl = getAsIntOrNull(d, "days_left");
      if (dl != null) userData.DaysLeft = dl;
      String ll = getAsString(d, "last_login");
      if (ll != null && !ll.isBlank()) userData.LastLogin = ll;
      String ra = getAsString(d, "registered_at");
      if (ra != null && !ra.isBlank()) userData.RegisteredAt = ra;
      String sub = getAsString(d, "subscription");
      if (sub != null && !sub.isBlank()) userData.Subscription = sub;
      String lvl = getAsString(d, "subscription_level");
      if (lvl != null && !lvl.isBlank()) userData.SubscriptionLevel = lvl;
    }
  }

  private void loadVariableData(JsonObject obj) {
    JsonObject v = obj.has("variable") && obj.get("variable").isJsonObject() ? obj.getAsJsonObject("variable") : null;
    if (v == null) return;
    variableData.VarKey = Objects.toString(getAsString(v, "var_key"), "");
    variableData.VarValue = Objects.toString(getAsString(v, "var_value"), "");
  }

  private boolean ensureInitialized() {
    if (initialized && !sessionId.isBlank()) return true;
    return setFailure("NOT_INITIALIZED", "AuthlyX is not initialized. Call Init() first.");
  }

  private boolean hasRequiredCredentials() {
    return !ownerId.isBlank() && !appName.isBlank() && !version.isBlank() && !secret.isBlank();
  }

  private void resetResponse() {
    response.success = false;
    response.message = "";
    response.code = "";
    response.raw = "";
    response.statusCode = 0;
  }

  private boolean setFailure(String code, String message) {
    response.success = false;
    response.code = code == null ? "" : code;
    response.message = message == null ? "" : message;
    response.raw = "";
    response.statusCode = 0;
    if (debug) AuthlyXLogger.log(appName, "[SDK][ERROR] " + code + " " + AuthlyXLogger.maskSensitive(response.message));
    return false;
  }

  private String getPublicIp() {
    long now = System.currentTimeMillis();
    if (cachedPublicIp != null && !cachedPublicIp.isBlank() && now < cachedPublicIpExpiresAtMs) {
      return cachedPublicIp;
    }
    String ip = "";
    try {
      HttpRequest req = HttpRequest.newBuilder()
        .uri(URI.create("https://api.ipify.org"))
        .timeout(Duration.ofSeconds(10))
        .GET()
        .build();
      HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      ip = resp.body() == null ? "" : resp.body().trim();
    } catch (Exception ignored) {
      ip = "";
    }
    if (!ip.isBlank()) {
      cachedPublicIp = ip;
      cachedPublicIpExpiresAtMs = now + 10L * 60L * 1000L;
    }
    return cachedPublicIp == null ? "" : cachedPublicIp;
  }

  private String getSystemIdentifier() {
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    if (os.contains("win")) {
      String sid = tryReadWindowsSid();
      if (sid != null && !sid.isBlank()) return sid;
    }
    String user = System.getenv().getOrDefault("USERNAME", System.getenv().getOrDefault("USER", ""));
    String host = System.getenv().getOrDefault("COMPUTERNAME", "");
    String seed = user + "|" + host + "|" + System.getProperty("os.name", "");
    return sha256Hex(seed.getBytes(StandardCharsets.UTF_8));
  }

  private String tryReadWindowsSid() {
    Process p = null;
    try {
      p = new ProcessBuilder("whoami", "/user", "/fo", "csv", "/nh").redirectErrorStream(true).start();
      String line = readAll(p.getInputStream()).trim();
      p.waitFor();
      if (line.isBlank()) return "";
      if (line.startsWith("\"")) line = line.substring(1);
      if (line.endsWith("\"")) line = line.substring(0, line.length() - 1);
      String[] parts = line.split("\",\"");
      if (parts.length >= 2) return parts[1].trim();
      return "";
    } catch (Exception ignored) {
      return "";
    } finally {
      if (p != null) p.destroy();
    }
  }

  private static String readAll(InputStream in) throws IOException {
    try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
      StringBuilder sb = new StringBuilder();
      String s;
      while ((s = br.readLine()) != null) {
        sb.append(s).append('\n');
      }
      return sb.toString();
    }
  }

  private static String sha256Hex(byte[] bytes) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] dig = md.digest(bytes);
      StringBuilder sb = new StringBuilder(dig.length * 2);
      for (byte b : dig) sb.append(String.format("%02x", b));
      return sb.toString();
    } catch (Exception ignored) {
      return "UNKNOWN_HASH";
    }
  }

  private static String nvl(String s) {
    return s == null ? "" : s;
  }

  private static String getAsString(JsonObject o, String key) {
    if (o == null || key == null || !o.has(key)) return null;
    JsonElement el = o.get(key);
    if (el == null || el.isJsonNull()) return null;
    try {
      return el.getAsString();
    } catch (Exception ignored) {
      return null;
    }
  }

  private static boolean getAsBool(JsonObject o, String key) {
    if (o == null || key == null || !o.has(key)) return false;
    JsonElement el = o.get(key);
    if (el == null || el.isJsonNull()) return false;
    try {
      return el.getAsBoolean();
    } catch (Exception ignored) {
      return false;
    }
  }

  private static int getAsInt(JsonObject o, String key) {
    Integer v = getAsIntOrNull(o, key);
    return v == null ? 0 : v;
  }

  private static Integer getAsIntOrNull(JsonObject o, String key) {
    if (o == null || key == null || !o.has(key)) return null;
    JsonElement el = o.get(key);
    if (el == null || el.isJsonNull()) return null;
    try {
      return el.getAsInt();
    } catch (Exception ignored) {
      return null;
    }
  }

  private static final class AuthlyXLogger {
    static void log(String appName, String content) {
      if (content == null || content.isBlank()) return;
      try {
        String root = getLogRoot(appName);
        Files.createDirectories(Paths.get(root));
        String file = java.time.LocalDate.now(java.time.ZoneOffset.UTC).toString().replace("-", "_") + ".log";
        Path path = Paths.get(root, file);
        String line = "[" + java.time.LocalTime.now(java.time.ZoneOffset.UTC).toString().substring(0, 8) + "] " + maskSensitive(content) + System.lineSeparator();
        Files.writeString(path, line, StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
      } catch (Exception ignored) {
      }
    }

    static String getLogRoot(String appName) {
      String safe = (appName == null || appName.isBlank()) ? "default" : appName.trim();
      String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      if (os.contains("win")) {
        String programData = System.getenv("ProgramData");
        if (programData == null || programData.isBlank()) programData = "C:\\\\ProgramData";
        return programData + "\\\\AuthlyX\\\\" + safe;
      }
      String home = System.getProperty("user.home", ".");
      return Paths.get(home, ".authlyx", safe).toString();
    }

    static String maskSensitive(String s) {
      if (s == null || s.isBlank()) return s;
      String out = s;
      out = out.replaceAll("(?i)\"(owner_id|secret|password|license_key|session_id|hash|request_id|nonce)\"\\s*:\\s*\"[^\"]*\"", "\"$1\":\"***\"");
      out = out.replaceAll("(?i)(Authorization: Bearer )[^\\s]+", "$1***");
      return out;
    }
  }
}
