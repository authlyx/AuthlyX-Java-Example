// AuthlyX Java SDK Version 3.0 BETA
package app.authlyx;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import java.util.function.Function;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

public final class AuthlyX implements AutoCloseable
{
    static final ObjectMapper JSON =
        new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public static final class SdkException extends RuntimeException
    {
        public final String code, kind, requestId;
        public final int status;
        public final JsonNode data;

        public SdkException(String code, String message, String kind)
        {
            this(code, message, kind, 0, null);
        }

        public SdkException(String code, String message, String kind, int status, String requestId)
        {
            this(code, message, kind, status, requestId, null);
        }

        public SdkException(String code, String message, String kind, int status, String requestId,
                            JsonNode data)
        {
            super(message);
            this.data = data;
            this.code = code;
            this.kind = kind;
            this.status = status;
            this.requestId = requestId;
        }
    }

    public record
        Result(boolean success, String code, String message, JsonNode data, String requestId)
    {
        public boolean ok()
        {
            return success;
        }

        public boolean failed()
        {
            return !success;
        }

        public <T> T decode(Class<T> type)
        {
            try
            {
                return JSON.treeToValue(data, type);
            }
            catch (Exception e)
            {
                throw fail("DATA_INVALID", "The response data could not be decoded.", "security");
            }
        }

        @Override public String toString()
        {
            return code;
        }
    }

    public static final class Options
    {
        public String heartbeat;
        public String appKey, version, systemId, endpoint, buildHash = "";
        public Map<String, String> responseKeys = Map.of(), offlineKeys = Map.of(),
                                   scriptKeys = Map.of();
        public ProtectedStore storage;
        public Duration requestBudget = Duration.ofSeconds(8);
        public boolean manualHeartbeat = false, allowLocalHttp = false, updatePrompt = true;
        public java.util.function.Consumer<String> onConnection;
        public java.util.function.Consumer<SdkException> onInvalidated;
    }

    private final Options o;
    private final HttpClient http;
    private final PrivateKey key;
    private final String publicPem, keyHash, prefix;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "authlyx-v3");
        t.setDaemon(true);
        return t;
    });
    private final ScheduledExecutorService scheduler =
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "authlyx-heartbeat");
            t.setDaemon(true);
            return t;
        });
    private final Set<Operation> operations = ConcurrentHashMap.newKeySet();
    private volatile boolean disposed, loggingOut;
    private ScheduledFuture<?> heartbeat;
    public volatile JsonNode userData = JSON.createObjectNode();
    private String token, sessionId, appId, identityId, slot;
    private ObjectNode offline, credential;
    private boolean offlineSession;
    private volatile boolean updateOffered;
    private long anchorServer, anchorMono, anchorWall, deadline;
    private double heartbeatSeconds = 600, jitterSeconds = 15;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Set<String> REVOKED =
        Set.of("SESSION_EXPIRED", "ACCESS_REVOKED", "APP_PAUSED", "ACCESS_EXPIRED", "ACCESS_DENIED",
               "IP_BLACKLISTED", "IP_NOT_WHITELISTED", "SID_BLACKLISTED", "SID_NOT_WHITELISTED",
               "VERSION_NOT_ALLOWED", "HASH_NOT_ALLOWED", "COUNTRY_BLOCKED", "VPN_NOT_ALLOWED",
               "DEVICE_NOT_ALLOWED", "INVALID_CREDENTIALS",
               "APP_DISABLED",
               "IP_BLOCKED",
               "SID_BLOCKED",
               "UPDATE_REQUIRED",
               "VERSION_MISMATCH",
               "INVALID_HASH",
               "VPN_BLOCKED",
               "USER_BANNED",
               "USER_SUSPENDED",
               "USER_EXPIRED",
               "LICENSE_BANNED",
               "LICENSE_PAUSED",
               "LICENSE_EXPIRED",
               "MOTHERBOARD_BANNED",
               "MOTHERBOARD_PAUSED",
               "MOTHERBOARD_EXPIRED",
               "PROCESSOR_BANNED",
               "PROCESSOR_PAUSED",
               "PROCESSOR_EXPIRED");

    private static SdkException fail(String code, String message, String kind)
    {
        return new SdkException(code, message, kind);
    }

    public static String hash(byte[] value)
    {
        try
        {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException("SHA-256 unavailable");
        }
    }

    public static String hash(String value)
    {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] random(int count)
    {
        byte[] b = new byte[count];
        RANDOM.nextBytes(b);
        return b;
    }

    private static final String DEVICE_SCRIPT =
        "$ErrorActionPreference='SilentlyContinue';" +
        "[string](Get-CimInstance Win32_BaseBoard).SerialNumber;" +
        "[string](Get-CimInstance Win32_ComputerSystemProduct).UUID;" +
        "[string]@((Get-CimInstance Win32_SystemEnclosure).ChassisTypes)[0]";

    private final CompletableFuture<LinkedHashMap<String, Object>> device =
        CompletableFuture.supplyAsync(AuthlyX::readDevice);

    private LinkedHashMap<String, Object> deviceDetails()
    {
        try
        {
            return device.get(5, TimeUnit.SECONDS);
        }
        catch (Exception error)
        {
            return obj("name", deviceText(System.getenv("COMPUTERNAME")), "type", "Windows", "baseboard", "",
                       "uuid", "");
        }
    }

    private static String deviceText(String value)
    {
        var text = new StringBuilder();
        for (char c : (value == null ? "" : value).toCharArray())
            if (c >= ' ' && c <= '~' && "<>&".indexOf(c) < 0 && c != (char)34 && c != (char)92)
                text.append(c);
        String result = text.toString().trim();
        return result.length() > 100 ? result.substring(0, 100) : result;
    }

    private static String chassisType(int chassis)
    {
        return switch (chassis)
        {
            case 8, 9, 10, 14, 31, 32 -> "Windows laptop";
            case 30 -> "Windows tablet";
            case 17, 23, 28, 29 -> "Windows server";
            case 3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36 -> "Windows desktop";
            default -> "Windows";
        };
    }

    private static LinkedHashMap<String, Object> readDevice()
    {
        String type = "Windows", baseboard = "", uuid = "";
        if (System.getProperty("os.name", "").startsWith("Windows"))
        {
            try
            {
                Process process = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                                                     "-WindowStyle", "Hidden", "-Command", DEVICE_SCRIPT)
                                      .redirectError(ProcessBuilder.Redirect.DISCARD)
                                      .start();
                process.getOutputStream().close();
                List<String> lines =
                    new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).lines().toList();
                process.waitFor(10, TimeUnit.SECONDS);
                baseboard = lines.size() > 0 ? lines.get(0) : "";
                uuid = lines.size() > 1 ? lines.get(1) : "";
                if (lines.size() > 2 && !lines.get(2).isBlank())
                    type = chassisType(Integer.parseInt(lines.get(2).trim()));
            }
            catch (IOException | NumberFormatException error)
            {
            }
            catch (InterruptedException error)
            {
                Thread.currentThread().interrupt();
            }
        }
        return obj("name", deviceText(System.getenv("COMPUTERNAME")), "type", type, "baseboard",
                   deviceText(baseboard), "uuid", deviceText(uuid));
    }

    private static LinkedHashMap<String, Object> obj(Object... values)
    {
        var result = new LinkedHashMap<String, Object>();
        for (int i = 0; i < values.length; i += 2)
            result.put((String)values[i], values[i + 1]);
        return result;
    }

    private static String json(Object value)
    {
        try
        {
            return JSON.writeValueAsString(value);
        }
        catch (Exception e)
        {
            throw fail("INVALID_ARGUMENT", "The request could not be encoded.", "server");
        }
    }

    private static String text(JsonNode node, String name)
    {
        return node.path(name).asText("");
    }

    private static PublicKey publicKey(String pem) throws GeneralSecurityException
    {
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(
            Base64.getMimeDecoder().decode(pem.replace("-----BEGIN PUBLIC KEY-----", "")
                                               .replace("-----END PUBLIC KEY-----", ""))));
    }

    private static boolean verify(String pem, String payload, String signature)
    {
        try
        {
            var verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey(pem));
            verifier.update(payload.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(signature));
        }
        catch (Exception e)
        {
            return false;
        }
    }

    private String sign(String payload)
    {
        try
        {
            var signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        }
        catch (GeneralSecurityException e)
        {
            throw fail("SIGNING_FAILED", "The installation signature could not be created.",
                       "security");
        }
    }

    public AuthlyX(String appKey, String version)
    {
        this(defaults(appKey, version));
    }

    public static String systemId()
    {
        try
        {
            if (!System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("windows"))
                throw new IllegalStateException("Supply a platform system ID through Options.");
            Process process =
                new ProcessBuilder(
                    Path.of(System.getenv("SystemRoot"), "System32", "whoami.exe").toString(),
                    "/user", "/fo", "csv", "/nh")
                    .redirectErrorStream(true)
                    .start();
            if (!process.waitFor(3, TimeUnit.SECONDS))
            {
                process.destroyForcibly();
                throw new IOException("SID lookup timed out.");
            }
            String output =
                new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            var match = java.util.regex.Pattern.compile("S-1-\\d+(?:-\\d+)+").matcher(output);
            if (process.exitValue() != 0 || !match.find())
                throw new IOException("Windows SID unavailable.");
            return match.group();
        }
        catch (InterruptedException error)
        {
            Thread.currentThread().interrupt();
            throw fail("SYSTEM_ID_UNAVAILABLE", "SID lookup interrupted.", "cancelled");
        }
        catch (Exception error)
        {
            throw fail("SYSTEM_ID_UNAVAILABLE", "Could not read the Windows user SID.", "storage");
        }
    }

    public static Options defaults(String appKey, String version)
    {
        Options o = new Options();
        o.appKey = appKey;
        o.version = version;
        o.systemId = systemId();
        o.endpoint = "https://api.authlyx.dev";
        o.allowLocalHttp = true;
        try
        {
            o.storage =
                new WindowsProtectedStore(Path.of(System.getenv("LOCALAPPDATA"), "AuthlyX", "v3"));
        }
        catch (IOException error)
        {
            throw fail("STORAGE_UNAVAILABLE", "Could not open protected storage.", "storage");
        }
        o.responseKeys =
            Map.of("2318305346828e7b61e0447bfc4b3daac50dcda1b425814120ee3d6947609052",
                   "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaXXIKXRn0uPJ16wc4SX1GLArAGTAPeVhreGxp4f9/6Q=\n-----END PUBLIC KEY-----\n");
        o.offlineKeys =
            Map.of("d3ea94e9f098eece181306689713c9f4d984c0321948fbd0007ef471bcf5b7d2",
                   "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA7d2GrJ8SIUFor6bZuXo0NCX2k9SkHVz5PxOZDut3ydk=\n-----END PUBLIC KEY-----\n");
        o.scriptKeys = Map.of("5aec455eb0b10697",
                              "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0zpUhvFdbX95R1Q0+105MZsJr0IJ/yFTNxSiUwqfFH0=\n-----END PUBLIC KEY-----\n");
        return o;
    }

    public AuthlyX(Options source)
    {
        URI url = URI.create(source.endpoint);
        boolean local = Set.of("localhost", "127.0.0.1", "[::1]", "::1").contains(url.getHost());
        if (url.getRawUserInfo() != null || url.getQuery() != null || url.getFragment() != null ||
            (!url.getPath().isEmpty() && !url.getPath().equals("/")) ||
            (!url.getScheme().equals("https") &&
             !(source.allowLocalHttp && url.getScheme().equals("http") && local)))
            throw new IllegalArgumentException(
                "Use an HTTPS API origin. HTTP is limited to explicit loopback testing.");
        if (source.storage == null || source.responseKeys.isEmpty() || source.appKey == null ||
            source.version == null || source.systemId == null ||
            source.requestBudget.toMillis() < 100 || source.requestBudget.toMillis() > 60000)
            throw new IllegalArgumentException("Provide app identity, protected storage, trusted "
                                               + "response keys and a bounded request budget.");
        o = new Options();
        o.appKey = source.appKey;
        o.version = source.version;
        o.systemId = source.systemId;
        o.endpoint = url.getScheme() + "://" + url.getRawAuthority();
        o.buildHash = source.buildHash;
        o.responseKeys = Map.copyOf(source.responseKeys);
        o.offlineKeys = Map.copyOf(source.offlineKeys);
        o.scriptKeys = Map.copyOf(source.scriptKeys);
        o.storage = source.storage;
        o.requestBudget = source.requestBudget;
        if (source.heartbeat != null && !source.heartbeat.equals("server") &&
            !source.heartbeat.equals("manual"))
            throw new IllegalArgumentException("Use server or manual heartbeat mode.");
        o.manualHeartbeat =
            source.heartbeat == null ? source.manualHeartbeat : source.heartbeat.equals("manual");
        o.onConnection = source.onConnection;
        o.onInvalidated = source.onInvalidated;
        o.updatePrompt = source.updatePrompt;
        prefix = "authlyx.v3." + hash(o.endpoint + "/\n" + o.appKey + "\n" + o.systemId);
        try
        {
            String identityName =
                "authlyx.v3.installation." + hash(o.endpoint + "/\n" + o.systemId);
            String saved = o.storage.load(identityName);
            byte[] seed = saved == null ? random(32) : Base64.getDecoder().decode(saved);
            if (seed.length != 32)
                throw new IOException();
            if (saved == null)
                o.storage.save(identityName, Base64.getEncoder().encodeToString(seed));
            byte[] raw = new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
            byte[] der = ByteBuffer.allocate(44)
                             .put(HexFormat.of().parseHex("302a300506032b6570032100"))
                             .put(raw)
                             .array();
            key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(
                ByteBuffer.allocate(48)
                    .put(HexFormat.of().parseHex("302e020100300506032b657004220420"))
                    .put(seed)
                    .array()));
            Arrays.fill(seed, (byte)0);
            publicPem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(der) +
                        "\n-----END PUBLIC KEY-----\n";
            keyHash = hash(der);
        }
        catch (Exception e)
        {
            throw fail("STORAGE_INVALID", "Protected SDK state could not be read or saved.",
                       "storage");
        }
        http = HttpClient.newBuilder()
                   .followRedirects(HttpClient.Redirect.NEVER)
                   .connectTimeout(o.requestBudget)
                   .build();
    }

    private static final class Operation
    {
        final AtomicBoolean cancelled = new AtomicBoolean();
        volatile CompletableFuture<?> wire;

        void check()
        {
            if (cancelled.get())
                throw fail("REQUEST_CANCELLED", "The request was cancelled.", "cancelled");
        }

        void cancel()
        {
            cancelled.set(true);
            if (wire != null)
                wire.cancel(true);
        }
    }

    private <T> CompletableFuture<T> async(Function<Operation, T> action)
    {
        return async(action, false);
    }

    private <T> CompletableFuture<T> async(Function<Operation, T> action, boolean alwaysRun)
    {
        if (disposed)
            return CompletableFuture.failedFuture(
                fail("DISPOSED", "This client is disposed.", "cancelled"));
        var context = new Operation();
        var future = new CompletableFuture<T>();
        operations.add(context);
        future.whenComplete((v, e) -> {
            if (future.isCancelled())
                context.cancel();
        });
        worker.execute(() -> {
            String before = token;
            try
            {
                if (!alwaysRun)
                    context.check();
                T result = action.apply(context);
                if (!future.complete(result) && before == null && token != null)
                {
                    token = null;
                    userData = JSON.createObjectNode();
                    deadline = 0;
                    stopHeartbeat();
                    clearOffline();
                }
            }
            catch (Throwable e)
            {
                future.completeExceptionally(e);
            }
            finally
            {
                operations.remove(context);
            }
        });
        return future;
    }

    private void anchor(long value)
    {
        anchorServer = value;
        anchorMono = System.nanoTime();
        anchorWall = System.currentTimeMillis();
    }

    private long now()
    {
        return anchorServer == 0 ? System.currentTimeMillis()
                                 : anchorServer + (System.nanoTime() - anchorMono) / 1000000;
    }

    private void connection(String state)
    {
        if (o.onConnection != null)
            CompletableFuture.runAsync(() -> {
                try
                {
                    o.onConnection.accept(state);
                }
                catch (Exception ignored)
                {
                }
            });
    }

    private static String slotOf(String type, String username, String license)
    {
        String id = type.equals("user")      ? username.strip().toLowerCase(Locale.ROOT)
                    : type.equals("license") ? license.strip()
                                             : "";
        return hash(type + "\n" + id);
    }

    private static String verifier(String secret, byte[] salt)
    {
        try
        {
            var spec = new javax.crypto.spec.PBEKeySpec(secret.toCharArray(), salt, 120000, 256);
            return Base64.getEncoder().encodeToString(
                javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .getEncoded());
        }
        catch (GeneralSecurityException e)
        {
            throw fail("SIGNING_FAILED", "Could not protect offline access.", "security");
        }
    }

    private String recordName(String value)
    {
        return prefix + ".offline." + value;
    }

    private List<String> slots()
    {
        List<String> list = new ArrayList<>();
        try
        {
            String saved = o.storage.load(prefix + ".offline");
            if (saved != null)
                for (JsonNode item : JSON.readTree(saved).path("slots"))
                    if (item.isTextual())
                        list.add(item.asText());
        }
        catch (Exception ignored)
        {
        }
        return list;
    }

    private void saveSlots(List<String> list) throws IOException
    {
        if (list.isEmpty())
            o.storage.delete(prefix + ".offline");
        else
            o.storage.save(prefix + ".offline", json(obj("slots", JSON.valueToTree(list))));
    }

    private ObjectNode loadRecord(String value)
    {
        try
        {
            String saved = o.storage.load(recordName(value));
            return saved == null ? null : (ObjectNode)JSON.readTree(saved);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private void forget(String value)
    {
        if (value == null || value.isEmpty())
            return;
        try
        {
            o.storage.delete(recordName(value));
            List<String> kept = slots();
            kept.remove(value);
            saveSlots(kept);
        }
        catch (IOException e)
        {
            throw fail("STORAGE_INVALID", "Protected offline state could not be removed.",
                       "storage");
        }
    }

    private void clearOffline()
    {
        offline = null;
        offlineSession = false;
        forget(slot);
    }

    private long recordNow(JsonNode record)
    {
        return anchorServer != 0 ? now()
                                 : record.path("trustedTime").asLong() + System.currentTimeMillis() -
                                       record.path("localTime").asLong();
    }

    private Result offlineLogin(String type, String username, String password, String license)
    {
        String name = slotOf(type, username, license);
        ObjectNode record = loadRecord(name);
        if (record == null || !validRecord(record))
        {
            if (record != null)
                forget(name);
            throw fail("OFFLINE_UNAVAILABLE",
                       "Could not connect to AuthlyX, and this PC has no saved offline access for " +
                           "that account. Check your internet connection and try again.",
                       "network");
        }
        if (!type.equals("device"))
        {
            byte[] salt;
            try
            {
                salt = Base64.getDecoder().decode(text(record, "salt"));
            }
            catch (IllegalArgumentException e)
            {
                salt = new byte[0];
            }
            String actual = verifier(type.equals("user") ? password : license, salt);
            if (!MessageDigest.isEqual(actual.getBytes(StandardCharsets.UTF_8),
                                       text(record, "verifier").getBytes(StandardCharsets.UTF_8)))
                throw type.equals("user")
                    ? fail("INVALID_CREDENTIALS", "Username or password is incorrect.", "server")
                    : fail("LICENSE_NOT_FOUND", "License not found.", "server");
        }
        if (anchorServer == 0)
            anchor(recordNow(record));
        appId = text(record, "appId");
        identityId = text(record, "identityId");
        slot = name;
        offline = record;
        offlineSession = true;
        userData = record.path("userData").isObject() ? record.get("userData").deepCopy()
                                                      : JSON.createObjectNode();
        try
        {
            persist();
        }
        catch (SdkException ignored)
        {
        }
        ObjectNode data = JSON.createObjectNode();
        data.put("offline", true);
        data.set("identity", userData.deepCopy());
        return new Result(true, "OFFLINE_ACCESS",
                          "Signed in with saved offline access. Online features are unavailable " +
                              "until you reconnect.",
                          data, "");
    }

    private void invalidate(SdkException error)
    {
        token = null;
        userData = JSON.createObjectNode();
        deadline = 0;
        stopHeartbeat();
        try
        {
            clearOffline();
        }
        catch (SdkException ignored)
        {
            offline = null;
            offlineSession = false;
        }
        if (o.onInvalidated != null)
            CompletableFuture.runAsync(() -> {
                try
                {
                    o.onInvalidated.accept(error);
                }
                catch (Exception ignored)
                {
                }
            });
    }

    private Result verified(JsonNode outer, int status, String path, String body, String nonce)
    {
        try
        {
            JsonNode proof = outer.path("verification");
            String id = text(proof, "keyId"), pem = o.responseKeys.get(id),
                   payload = text(proof, "signedPayload");
            if (pem == null || payload.length() > 2000000 ||
                !hash(publicKey(pem).getEncoded()).equals(id) ||
                !verify(pem, payload, text(proof, "signature")))
                throw new IOException();
            JsonNode signed = JSON.readTree(payload);
            ObjectNode envelope = ((ObjectNode)outer).deepCopy();
            envelope.remove("verification");
            if (!text(signed, "type").equals("authlyx.response.v3") ||
                !text(signed, "keyId").equals(id) || signed.path("httpStatus").asInt() != status ||
                !signed.path("request").equals(JSON.valueToTree(obj(
                    "method", "POST", "path", path, "nonce", nonce, "bodySha256", hash(body)))) ||
                !signed.path("response").equals(envelope) ||
                !envelope.path("message").isTextual() || !envelope.path("success").isBoolean() ||
                !envelope.path("code").isTextual() || !envelope.path("requestId").isTextual())
                throw new IOException();
            anchor(Instant.parse(text(signed, "serverTime")).toEpochMilli());
            return new Result(envelope.path("success").asBoolean(), text(envelope, "code"),
                              text(envelope, "message"), envelope.path("data"),
                              text(envelope, "requestId"));
        }
        catch (Exception e)
        {
            throw fail("RESPONSE_INVALID", "The server response could not be verified.",
                       "security");
        }
    }

    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]>
    {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

        public CompletionStage<byte[]> getBody()
        {
            return result;
        }

        public void onSubscribe(Flow.Subscription value)
        {
            subscription = value;
            value.request(Long.MAX_VALUE);
        }

        public void onNext(List<ByteBuffer> values)
        {
            for (var value : values)
            {
                if (bytes.size() + value.remaining() > 2000000)
                {
                    subscription.cancel();
                    result.completeExceptionally(
                        fail("RESPONSE_INVALID", "The server response is too large.", "security"));
                    return;
                }
                byte[] chunk = new byte[value.remaining()];
                value.get(chunk);
                bytes.writeBytes(chunk);
            }
        }

        public void onError(Throwable error)
        {
            result.completeExceptionally(error);
        }

        public void onComplete()
        {
            result.complete(bytes.toByteArray());
        }
    }

    private Result request(Operation context, String path, Object data, boolean auth, boolean retry)
    {
        context.check();
        if (auth && token == null)
            throw fail("NOT_SIGNED_IN", "Sign in before using this feature.", "server");
        String body = json(data);
        long until = System.nanoTime() + o.requestBudget.toNanos();
        for (int attempt = 0;; attempt++)
        {
            context.check();
            String nonce = HexFormat.of().formatHex(random(24)), stamp = Long.toString(now());
            try
            {
                long remaining = until - System.nanoTime();
                if (remaining <= 0)
                    throw new TimeoutException();
                var builder = HttpRequest.newBuilder(URI.create(o.endpoint + path))
                                  .timeout(Duration.ofNanos(remaining))
                                  .header("Content-Type", "application/json")
                                  .header("X-AuthlyX-Nonce", nonce)
                                  .POST(HttpRequest.BodyPublishers.ofString(body));
                if (auth)
                    builder.header("Authorization", "Bearer " + token)
                        .header("X-AuthlyX-Timestamp", stamp)
                        .header(
                            "X-AuthlyX-Signature",
                            sign(json(obj("type", "authlyx.request.v3", "method", "POST", "path",
                                          path, "bodySha256", hash(body), "nonce", nonce,
                                          "timestamp", stamp, "tokenHash", hash(token)))));
                var wire = http.sendAsync(builder.build(), ignored -> new LimitedBody());
                context.wire = wire;
                HttpResponse<byte[]> response;
                try
                {
                    response = wire.get(remaining, TimeUnit.NANOSECONDS);
                }
                catch (TimeoutException e)
                {
                    wire.cancel(true);
                    throw e;
                }
                finally
                {
                    context.wire = null;
                }
                context.check();
                JsonNode outer;
                try
                {
                    outer = JSON.readTree(response.body());
                }
                catch (Exception e)
                {
                    throw fail(
                        response.statusCode() >= 500 ? "SERVICE_UNAVAILABLE" : "RESPONSE_INVALID",
                        response.statusCode() >= 500 ? "The service is temporarily unavailable."
                                                     : "The server response is not valid JSON.",
                        response.statusCode() >= 500 ? "network" : "security");
                }
                if (!outer.has("verification") && response.statusCode() >= 500)
                    throw fail("SERVICE_UNAVAILABLE", "The service is temporarily unavailable.",
                               "network");
                Result result = verified(outer, response.statusCode(), path, body, nonce);
                connection("online");
                if (!result.success() || response.statusCode() >= 400)
                {
                    String kind = response.statusCode() == 429 || response.statusCode() >= 500
                                      ? "network"
                                      : "server";
                    if (retry && attempt < 2 &&
                        (kind.equals("network") || result.code().equals("REQUEST_TIME_INVALID")))
                    {
                        String after = response.headers().firstValue("Retry-After").orElse("");
                        long delay = 150;
                        try
                        {
                            delay =
                                after.isEmpty() ? 150
                                : after.matches("[0-9]+")
                                    ? Math.multiplyExact(Long.parseLong(after), 1000)
                                    : ZonedDateTime
                                              .parse(after, DateTimeFormatter.RFC_1123_DATE_TIME)
                                              .toInstant()
                                              .toEpochMilli() -
                                          System.currentTimeMillis();
                        }
                        catch (Exception e)
                        {
                            delay = o.requestBudget.toMillis();
                        }
                        if (delay >= 0 &&
                            System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delay + 50) < until)
                        {
                            Thread.sleep(delay);
                            continue;
                        }
                    }
                    throw new SdkException(result.code(), result.message(), kind,
                                           response.statusCode(), result.requestId(), result.data());
                }
                return result;
            }
            catch (SdkException e)
            {
                if (e.kind.equals("security"))
                {
                    connection("untrusted");
                    invalidate(e);
                }
                else if (e.kind.equals("network"))
                    connection("disconnected");
                else if (auth && REVOKED.contains(e.code))
                    invalidate(e);
                throw e;
            }
            catch (CancellationException e)
            {
                throw fail("REQUEST_CANCELLED", "The request was cancelled.", "cancelled");
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
                throw fail("REQUEST_CANCELLED", "The request was cancelled.", "cancelled");
            }
            catch (TimeoutException e)
            {
                connection("disconnected");
                throw fail("NETWORK_TIMEOUT", "The request timed out. Try again when connected.",
                           "network");
            }
            catch (ExecutionException e)
            {
                if (e.getCause() instanceof SdkException failure)
                {
                    invalidate(failure);
                    throw failure;
                }
                context.check();
                connection("disconnected");
                if (retry && attempt < 2 &&
                    System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(200) < until)
                {
                    try
                    {
                        Thread.sleep(150);
                    }
                    catch (InterruptedException ignored)
                    {
                        Thread.currentThread().interrupt();
                        throw fail("REQUEST_CANCELLED", "The request was cancelled.", "cancelled");
                    }
                    continue;
                }
                throw fail("NETWORK_ERROR", "Could not connect to AuthlyX.", "network");
            }
        }
    }

    public CompletableFuture<Result> initialize()
    {
        return init();
    }
    public CompletableFuture<Void> initialize(Consumer<Result> callback)
    {
        return init(callback);
    }
    public CompletableFuture<Result> init()
    {
        return async(c
                     -> request(c, "/v3/initialize", obj("appKey", o.appKey, "version", o.version),
                                false, true))
            .handle((result, thrown) -> {
                if (thrown == null)
                    return CompletableFuture.completedFuture(result);
                Throwable cause = thrown instanceof CompletionException && thrown.getCause() != null
                                      ? thrown.getCause()
                                      : thrown;
                if (!(cause instanceof SdkException error))
                    return CompletableFuture.<Result>failedFuture(cause);
                if (error.kind.equals("network"))
                    return hasOfflineAccess().thenApply(
                        saved -> saved
                                     ? new Result(true, "OFFLINE_MODE",
                                                  "You are offline. Sign in with the account you saved offline access for.",
                                                  JSON.createObjectNode(), "")
                                     : new Result(false, error.code,
                                                  "Could not connect to AuthlyX. Check your internet connection.",
                                                  null, error.requestId == null ? "" : error.requestId));
                if (!error.kind.equals("server"))
                    return CompletableFuture.<Result>failedFuture(error);
                String[] prompt = updatePrompt(error.data, error.code, error.getMessage());
                Result failed = new Result(false, error.code, error.getMessage(), error.data,
                                           error.requestId == null ? "" : error.requestId);
                if (prompt == null)
                    return CompletableFuture.completedFuture(failed);
                return CompletableFuture.supplyAsync(() -> {
                    showUpdate(prompt);
                    return failed;
                });
            })
            .thenCompose(Function.identity());
    }

    private String[] updatePrompt(JsonNode data, String code, String message)
    {
        if (!o.updatePrompt || data == null || java.awt.GraphicsEnvironment.isHeadless())
            return null;
        JsonNode update = data.path("update");
        if (!update.isObject())
            return null;
        String url = update.path("url").asText(""), latest = update.path("version").asText(""),
               notes = update.path("notes").asText("");
        if (!url.startsWith("https://") && !url.startsWith("http://"))
            url = "";
        boolean required = code.equals("UPDATE_REQUIRED") || code.equals("VERSION_MISMATCH");
        if (!required)
        {
            if (updateOffered || !data.path("updateAvailable").asBoolean(false) || url.isEmpty())
                return null;
            updateOffered = true;
        }
        String body = required ? message : "Version " + latest + " is available.";
        body += "\n\nYour version: " + o.version;
        if (!latest.isEmpty())
            body += "\nLatest version: " + latest;
        if (!notes.isEmpty())
            body += "\n\n" + notes;
        if (!url.isEmpty())
            body += "\n\nOpen the download page?";
        String title = code.equals("UPDATE_REQUIRED")    ? "Update required"
                       : code.equals("VERSION_MISMATCH") ? "Version not supported"
                                                         : "Update available";
        return new String[] {title, body, url};
    }

    private static void showUpdate(String[] prompt)
    {
        try
        {
            boolean link = !prompt[2].isEmpty();
            var pane = new javax.swing.JOptionPane(
                prompt[1], javax.swing.JOptionPane.INFORMATION_MESSAGE,
                link ? javax.swing.JOptionPane.YES_NO_OPTION : javax.swing.JOptionPane.DEFAULT_OPTION);
            var dialog = pane.createDialog(prompt[0]);
            dialog.setAlwaysOnTop(true);
            dialog.setVisible(true);
            dialog.dispose();
            if (link && Integer.valueOf(javax.swing.JOptionPane.YES_OPTION).equals(pane.getValue()) &&
                java.awt.Desktop.isDesktopSupported())
                java.awt.Desktop.getDesktop().browse(URI.create(prompt[2]));
        }
        catch (Exception ignored)
        {
        }
    }

    public CompletableFuture<Result> registerUser(String username, String password,
                                                  String licenseKey)
    {
        return loginImpl("register", username, password, licenseKey);
    }

    public CompletableFuture<Result> changePassword(String currentPassword, String newPassword)
    {
        return protectedCall("/v3/account/password",
                             obj("currentPassword", currentPassword, "newPassword", newPassword),
                             false);
    }

    public CompletableFuture<Result> redeemLicense(String licenseKey)
    {
        return protectedCall("/v3/licenses/redeem", obj("licenseKey", licenseKey), false);
    }

    public CompletableFuture<Result> log(String message)
    {
        return protectedCall("/v3/logs/add", obj("message", message), false);
    }

    public CompletableFuture<Result> login(String license)
    {
        return licenseLogin(license);
    }

    public CompletableFuture<Result> login(String username, String password)
    {
        return loginImpl("user", username, password, "");
    }

    public CompletableFuture<Result> licenseLogin(String license)
    {
        return loginImpl("license", "", "", license);
    }

    public CompletableFuture<Result> deviceLogin()
    {
        return loginImpl("device", "", "", "");
    }

    private CompletableFuture<Result> loginImpl(String type, String username, String password,
                                                String license)
    {
        return async(c -> {
            if (token != null || offlineSession)
                throw fail("ALREADY_SIGNED_IN", "Sign out before starting another session.",
                           "server");
            loggingOut = false;
            JsonNode challenge;
            try
            {
                challenge =
                    request(c, "/v3/challenge",
                            obj("appKey", o.appKey, "installationPublicKey", publicPem), false,
                            false)
                        .data();
            }
            catch (SdkException e)
            {
                if (!e.kind.equals("network") || type.equals("register"))
                    throw e;
                return offlineLogin(type, username, password, license);
            }
            var operation = obj("type", type, "appKey", o.appKey, "version", o.version, "sid",
                                o.systemId, "hash", o.buildHash, "username", username, "password",
                                password, "licenseKey", license, "device", deviceDetails());
            String signature =
                sign(json(obj("challenge", text(challenge, "payload"), "operation", operation)));
            operation.put("challengeId", text(challenge, "challengeId"));
            operation.put("signature", signature);
            Result result = request(c, "/v3/login", operation, false, false);
            c.check();
            try
            {
                appId = text(JSON.readTree(text(challenge, "payload")), "appId");
            }
            catch (IOException e)
            {
                throw fail("RESPONSE_INVALID", "Invalid challenge.", "security");
            }
            ObjectNode identity = ((ObjectNode)result.data().get("identity")).deepCopy();
            for (String[] pair : new String[][] {{"SID", "systemId"},
                                                 {"Email", "email"},
                                                 {"Plan", "plan"},
                                                 {"ExpiryDate", "expiry"},
                                                 {"Country", "country"},
                                                 {"IpAddress", "ipAddress"},
                                                 {"DeviceLimit", "deviceLimit"}})
                identity.set(pair[0], identity.get(pair[1]));
            identity.put("Username",
                         text(identity, "type").equals("user") ? text(identity, "name") : "");
            identity.put("LicenseKey", text(identity, "licenseKey"));
            userData = identity;
            token = text(result.data(), "token");
            sessionId = text(result.data(), "sessionId");
            identityId = text(result.data(), "identityId");
            String kind = type.equals("register") ? "user" : type;
            slot = slotOf(kind, username, license);
            byte[] salt = random(16);
            credential = JSON.createObjectNode();
            credential.put("kind", kind);
            credential.put("salt", Base64.getEncoder().encodeToString(salt));
            credential.put("verifier", kind.equals("device")
                                           ? ""
                                           : verifier(kind.equals("user") ? password : license, salt));
            lease(result.data());
            ObjectNode safe = ((ObjectNode)result.data()).deepCopy();
            safe.remove("token");
            startHeartbeat();
            String[] prompt = updatePrompt(safe, result.code(), result.message());
            if (prompt != null)
            {
                Thread shown = new Thread(() -> showUpdate(prompt), "authlyx-update");
                shown.setDaemon(true);
                shown.start();
            }
            return new Result(result.success(), result.code(), result.message(), safe,
                              result.requestId());
        });
    }

    private void lease(JsonNode data)
    {
        long value;
        try
        {
            value = Instant.parse(text(data, "accessDeadline")).toEpochMilli();
            if (value <= 0 || value > now() + 7200100)
                throw new IllegalArgumentException();
        }
        catch (Exception e)
        {
            SdkException error =
                fail("LEASE_INVALID", "The session deadline is invalid.", "security");
            invalidate(error);
            throw error;
        }
        deadline = value;
        ObjectNode refreshed =
            userData.isObject() ? ((ObjectNode)userData).deepCopy() : JSON.createObjectNode();
        for (String key : new String[] {"features", "featureValues", "metadata"})
        {
            if (data.has(key))
                refreshed.set(key, data.get(key).deepCopy());
        }
        userData = refreshed;
        heartbeatSeconds = Math.max(1, Math.min(3600, data.path("heartbeatSeconds").asDouble(600)));
        jitterSeconds = Math.max(0, Math.min(15, data.path("jitterSeconds").asDouble(15)));
    }

    public CompletableFuture<Result> checkSession()
    {
        return async(c -> {
            Result result = request(c, "/v3/session/check", obj(), true, true);
            lease(result.data());
            return result;
        });
    }

    private CompletableFuture<Result> protectedCall(String path, Object data, boolean retry)
    {
        return async(c -> {
            if (token != null && deadline <= now())
                lease(request(c, "/v3/session/check", obj(), true, true).data());
            return request(c, path, data, true, retry);
        });
    }

    private CompletableFuture<Void> complete(CompletableFuture<Result> operation,
                                             Consumer<Result> callback)
    {
        Objects.requireNonNull(callback, "A completion callback is required.");
        return operation
            .handle((result, failure) -> {
                if (failure == null)
                    return result;
                Throwable error =
                    failure instanceof CompletionException && failure.getCause() != null
                        ? failure.getCause()
                        : failure;
                return new Result(false,
                                  error instanceof SdkException sdk ? sdk.code : "CLIENT_ERROR",
                                  error.getMessage(), NullNode.instance,
                                  error instanceof SdkException sdk ? sdk.requestId : "");
            })
            .thenAccept(callback);
    }

    public CompletableFuture<Void> init(Consumer<Result> callback)
    {
        return complete(init(), callback);
    }

    public CompletableFuture<Void> licenseLogin(String key, Consumer<Result> callback)
    {
        return complete(licenseLogin(key), callback);
    }

    public CompletableFuture<Void> login(String username, String password,
                                         Consumer<Result> callback)
    {
        return complete(login(username, password), callback);
    }

    public CompletableFuture<Void> getVariable(String name, Consumer<Result> callback)
    {
        return complete(getVariable(name), callback);
    }

    public CompletableFuture<Void> getScriptWithCallback(String name, Consumer<Result> callback)
    {
        return complete(getScript(name, null), callback);
    }

    public CompletableFuture<Result> getMetadata()
    {
        return protectedCall("/v3/metadata/get", obj(), true);
    }

    public CompletableFuture<Result> getMetadata(String key)
    {
        return protectedCall("/v3/metadata/get", obj("key", key), true);
    }
    public CompletableFuture<Result> updateVariable(String name, String value)
    {
        return protectedCall("/v3/data/set", obj("name", name, "value", value), false);
    }
    public CompletableFuture<Result> getFeatures()
    {
        return protectedCall("/v3/features/list", obj(), true);
    }
    public CompletableFuture<Result> getFeature(String name)
    {
        return protectedCall("/v3/features/get", obj("name", name), true);
    }
    public CompletableFuture<Result> getAllMetadata()
    {
        return protectedCall("/v3/metadata/list", obj(), true);
    }
    public CompletableFuture<Result> checkMetadata(String key)
    {
        return protectedCall("/v3/metadata/check", obj("key", key), true);
    }
    public CompletableFuture<Result> sendWebhook(String name, Object data)
    {
        return protectedCall("/v3/webhooks/send", obj("event", name, "data", data), false);
    }

    public CompletableFuture<Result> setMetadata(String key, Object value)
    {
        return protectedCall("/v3/metadata/set", obj("key", key, "value", value), false);
    }

    public CompletableFuture<Result> checkFeature(String name)
    {
        return protectedCall("/v3/features/check", obj("name", name), true);
    }

    public CompletableFuture<Result> getVariable(String name)
    {
        return protectedCall("/v3/data/get", obj("name", name), true);
    }

    public CompletableFuture<Result> getScript(String name, Integer revision)
    {
        var data = obj("name", name);
        if (revision != null)
            data.put("revision", revision);
        return protectedCall("/v3/scripts/get", data, true).thenApply(result -> {
            try
            {
                String payload = text(result.data(), "signedPayload");
                JsonNode manifest = JSON.readTree(payload);
                if (manifest.has("issuedAt") || manifest.has("expiresAt"))
                {
                    if (!manifest.path("issuedAt").isIntegralNumber() ||
                        !manifest.path("expiresAt").isIntegralNumber() ||
                        manifest.path("issuedAt").asLong() > now() + 30000 ||
                        manifest.path("expiresAt").asLong() <= now() ||
                        manifest.path("expiresAt").asLong() <= manifest.path("issuedAt").asLong())
                        throw new IOException();
                }
                if (manifest.has("minimumRevision") &&
                    (!manifest.path("minimumRevision").isIntegralNumber() ||
                     manifest.path("revision").asInt() < manifest.path("minimumRevision").asInt()))
                    throw new IOException();
                String pem = o.scriptKeys.get(text(manifest, "keyId")),
                       content = text(result.data(), "content");
                if (pem == null || !verify(pem, payload, text(result.data(), "signature")) ||
                    !manifest.equals(result.data().path("manifest")) ||
                    !text(manifest, "appId").equals(appId) ||
                    !text(manifest, "name").equals(name) ||
                    (revision != null && manifest.path("revision").asInt() != revision) ||
                    !text(manifest, "sha256").equals(hash(content)) ||
                    manifest.path("bytes").asInt() !=
                        content.getBytes(StandardCharsets.UTF_8).length)
                    throw new IOException();
                return result;
            }
            catch (Exception e)
            {
                throw fail("SCRIPT_INVALID", "The script could not be verified.", "security");
            }
        });
    }

    public CompletableFuture<Result> saveOfflineAccess()
    {
        return async(c -> {
            if (token == null || credential == null)
                throw fail("NOT_SIGNED_IN", "Sign in online before saving offline access.",
                           "server");
            JsonNode challenge = request(c, "/v3/offline/challenge", obj(), true, false).data();
            String signature =
                sign(json(obj("challenge", text(challenge, "payload"), "operation",
                              obj("action", "offlinePermit", "sessionId", sessionId))));
            Result result =
                request(c, "/v3/offline/permit",
                        obj("challengeId", text(challenge, "challengeId"), "signature", signature),
                        true, false);
            ObjectNode record = JSON.valueToTree(
                obj("appId", appId, "identityId", identityId, "permit", result.data(),
                    "trustedTime", now(), "localTime", System.currentTimeMillis()));
            record.setAll(credential.deepCopy());
            record.set("userData", userData.deepCopy());
            if (!validRecord(record))
                throw fail("OFFLINE_INVALID", "The offline permit could not be verified.",
                           "security");
            try
            {
                o.storage.save(recordName(slot), json(record));
                List<String> list = slots();
                if (!list.contains(slot))
                    list.add(slot);
                saveSlots(list);
            }
            catch (IOException e)
            {
                throw fail("STORAGE_INVALID", "Could not save protected offline state.",
                           "storage");
            }
            return result;
        });
    }

    private boolean validOffline()
    {
        return offlineSession && validRecord(offline);
    }

    private boolean validRecord(JsonNode record)
    {
        try
        {
            if (record == null || disposed || loggingOut ||
                System.currentTimeMillis() < anchorWall ||
                System.currentTimeMillis() < record.path("localTime").asLong())
                return false;
            JsonNode permit = record.path("permit");
            String payload = text(permit, "signedPayload");
            if (payload.length() > 4096)
                return false;
            JsonNode claims = JSON.readTree(payload);
            String id = text(claims, "keyId"), pem = o.offlineKeys.get(id);
            long issued = claims.path("issuedAt").asLong(Long.MAX_VALUE),
                 expires = claims.path("expiresAt").asLong(Long.MIN_VALUE),
                 current = recordNow(record);
            return pem != null && hash(publicKey(pem).getEncoded()).equals(id) &&
                verify(pem, payload, text(permit, "signature")) &&
                text(claims, "type").equals("authlyx.offline.v1") &&
                text(claims, "appId").equals(text(record, "appId")) &&
                text(claims, "subjectId").equals(text(record, "identityId")) &&
                text(claims, "installationKeyHash").equals(keyHash) && issued <= current &&
                current < expires && expires > issued && expires - issued <= 2592000000L &&
                current >= record.path("trustedTime").asLong();
        }
        catch (Exception e)
        {
            return false;
        }
    }

    private void persist()
    {
        offline.put("trustedTime", recordNow(offline));
        offline.put("localTime", System.currentTimeMillis());
        try
        {
            o.storage.save(recordName(slot), json(offline));
        }
        catch (IOException e)
        {
            offline = null;
            offlineSession = false;
            throw fail("STORAGE_INVALID", "Could not save protected offline state.", "storage");
        }
    }

    public CompletableFuture<Boolean> hasOfflineAccess()
    {
        return async(c -> {
            if (!offlineSession)
                return slots().stream().anyMatch(item -> validRecord(loadRecord(item)));
            if (!validOffline())
                return false;
            try
            {
                persist();
                return true;
            }
            catch (SdkException e)
            {
                return false;
            }
        });
    }

    public CompletableFuture<Boolean> hasAccess()
    {
        return async(c -> {
            if (disposed || loggingOut)
                return false;
            if (token != null && deadline > now())
                return true;
            if (!validOffline())
                return false;
            try
            {
                persist();
                return true;
            }
            catch (SdkException e)
            {
                return false;
            }
        });
    }

    public CompletableFuture<Void> logout()
    {
        loggingOut = true;
        stopHeartbeat();
        return async(c -> {
            try
            {
                if (token != null)
                    request(c, "/v3/session/logout", obj(), true, false);
            }
            finally
            {
                stopHeartbeat();
                token = null;
                userData = JSON.createObjectNode();
                deadline = 0;
                clearOffline();
                credential = null;
                slot = null;
            }
            return null;
        }, true);
    }

    private synchronized void stopHeartbeat()
    {
        if (heartbeat != null)
        {
            heartbeat.cancel(false);
            heartbeat = null;
        }
    }

    private synchronized void startHeartbeat()
    {
        stopHeartbeat();
        if (o.manualHeartbeat || disposed || loggingOut || token == null)
            return;
        long delay =
            (long)(Math.max(1, heartbeatSeconds + (RANDOM.nextDouble() * 2 - 1) * jitterSeconds) *
                   1000);
        heartbeat = scheduler.schedule(()
                                           -> checkSession().whenComplete((v, e) -> {
            if (!disposed && !loggingOut && token != null)
                startHeartbeat();
        }),
                                       delay, TimeUnit.MILLISECONDS);
    }

    public CompletableFuture<Result> onResume()
    {
        return checkSession();
    }

    @Override public void close()
    {
        if (disposed)
            return;
        disposed = true;
        stopHeartbeat();
        for (var operation : operations)
            operation.cancel();
        scheduler.shutdownNow();
        worker.shutdown();
        token = null;
        userData = JSON.createObjectNode();
        deadline = 0;
    }

    public interface ProtectedStore
    {
        String load(String name) throws IOException;

        void save(String name, String value) throws IOException;

        void delete(String name) throws IOException;
    }

    public static final class MemoryStore implements ProtectedStore
    {
        private final ConcurrentHashMap<String, String> values = new ConcurrentHashMap<>();

        public String load(String name)
        {
            return values.get(name);
        }

        public void save(String name, String value)
        {
            values.put(name, value);
        }

        public void delete(String name)
        {
            values.remove(name);
        }
    }

    public static final class WindowsProtectedStore implements ProtectedStore
    {
        private final Path directory;
        private static final String SCRIPT =
            "$ErrorActionPreference='Stop';try{Add-Type -AssemblyName "
            + "System.Security;$x=[Console]::In.ReadToEnd()|ConvertFrom-Json;$v=[Convert]::" +
              "FromBase64String($x.value);$e=[Convert]::FromBase64String($x.entropy);if($x.mode"
            + " -eq "
            + "'protect'){$o=[Security.Cryptography.ProtectedData]::Protect($v,$e,[Security." +
              "Cryptography."
            + "DataProtectionScope]::CurrentUser)}else{$o=[Security.Cryptography.ProtectedData]::"
            + "Unprotect($v,$e,[Security.Cryptography.DataProtectionScope]::CurrentUser)};[" +
              "Console]::Out.Write([Convert]::ToBase64String($o))}catch{exit"
            + " 1}";

        public WindowsProtectedStore(Path directory) throws IOException
        {
            if (!System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows"))
                throw new IOException("Supply a platform-protected store.");
            this.directory = directory.toAbsolutePath();
            Files.createDirectories(this.directory);
        }

        private Path file(String name)
        {
            return directory.resolve(AuthlyX.hash(name) + ".dat");
        }

        private byte[] crypt(String name, byte[] value, String mode) throws IOException
        {
            Process process = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive",
                                                 "-WindowStyle", "Hidden", "-Command", SCRIPT)
                                  .redirectError(ProcessBuilder.Redirect.DISCARD)
                                  .start();
            try
            {
                try (var stream = process.getOutputStream())
                {
                    stream.write(AuthlyX.JSON.writeValueAsBytes(Map.of(
                        "mode", mode, "value", Base64.getEncoder().encodeToString(value), "entropy",
                        Base64.getEncoder().encodeToString(
                            name.getBytes(StandardCharsets.UTF_8)))));
                }
                var output = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try
                    {
                        return process.getInputStream().readNBytes(1500000);
                    }
                    catch (IOException e)
                    {
                        return new byte[0];
                    }
                });
                if (!process.waitFor(10, TimeUnit.SECONDS) || process.exitValue() != 0)
                    throw new IOException("Protected state could not be read or saved.");
                return Base64.getDecoder().decode(output.get(1, TimeUnit.SECONDS));
            }
            catch (Exception e)
            {
                throw new IOException("Protected storage is unavailable.");
            }
            finally
            {
                process.destroyForcibly();
            }
        }

        public String load(String name) throws IOException
        {
            Path file = file(name);
            if (!Files.exists(file))
                return null;
            byte[] bytes = Files.readAllBytes(file);
            if (bytes.length > 1048576)
                throw new IOException("Protected state is too large.");
            return new String(crypt(name, bytes, "unprotect"), StandardCharsets.UTF_8);
        }

        public void save(String name, String value) throws IOException
        {
            Path temp = Files.createTempFile(directory, ".authlyx-", ".tmp");
            try
            {
                Files.write(temp, crypt(name, value.getBytes(StandardCharsets.UTF_8), "protect"));
                Files.move(temp, file(name), StandardCopyOption.ATOMIC_MOVE,
                           StandardCopyOption.REPLACE_EXISTING);
            }
            finally
            {
                Files.deleteIfExists(temp);
            }
        }

        public void delete(String name) throws IOException
        {
            Files.deleteIfExists(file(name));
        }
    }
}
