# AuthlyX Java SDK

Official Java SDK and console example for AuthlyX V3 (3.0.0 beta).

Full documentation: https://docs.authlyx.dev

## Requirements

- Windows
- Java 17 or newer
- Maven

## Run the example

Put your app key and version in `src/main/java/app/authlyx/example/Main.java`:

```java
try (AuthlyX app = new AuthlyX("YOUR_APP_KEY", "1.0.0"))
```

Then run it:

```bat
mvn compile exec:java
```

You can find your app key under your app's credentials in the [dashboard](https://dash.authlyx.dev).

## Add it to your own project

Copy `src/main/java/app/authlyx/AuthlyX.java` into your project and add these dependencies:

```xml
<dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <version>2.22.4</version>
</dependency>
<dependency>
  <groupId>org.bouncycastle</groupId>
  <artifactId>bcprov-jdk18on</artifactId>
  <version>1.86</version>
</dependency>
```

```java
import app.authlyx.AuthlyX;

try (AuthlyX app = new AuthlyX("YOUR_APP_KEY", "1.0.0")) {
    app.initialize().join();
}
```

Every method returns a `CompletableFuture`. Calling `.join()` waits for the reply, so in a Swing or JavaFX app do that off the UI thread, or use `thenAccept`.

## Signing in

```java
app.login("YOUR_USERNAME", "YOUR_PASSWORD").join();
app.login("YOUR_LICENSE_KEY").join();
app.deviceLogin().join();
```

Device login signs in the current Windows user without a form. The device has to be approved in your app first. See [Device login](https://docs.authlyx.dev/guides/device-login).

After signing in, the account details are in `userData`:

```java
var user = app.userData;
String username = user.path("name").asText("");
String plan = user.path("plan").asText("");
String expiry = user.path("expiry").asText("");
```

Every method has its own page with examples under [SDK methods](https://docs.authlyx.dev/sdks/methods/login).

## Offline access

Once someone is signed in, saving offline access stores a signed permit on that PC:

```java
app.saveOfflineAccess().join();
boolean available = app.hasOfflineAccess().join();
```

If they open your app later without internet, they sign in with the same username and password or license key, and the SDK checks it against the saved permit. Each permit belongs to one app and one account, and signing out removes it. More in [Offline access](https://docs.authlyx.dev/guides/offline).

## Errors

When a request fails, the future completes with an `AuthlyX.SdkException` that has a `code` and a message you can show to the user. With `.join()` it arrives wrapped in a `CompletionException`, so read `getCause()` like the example does. All codes are listed in [Errors](https://docs.authlyx.dev/api-reference/errors).

## Coming from 2.4

V3 is a new SDK, not a drop-in update. Apps use an app key instead of the old owner ID, app name and secret, and the method names changed. Read [Move from V2 to V3](https://docs.authlyx.dev/api-reference/migration) before you switch.

## License

MIT. See `LICENSE.txt`.
