# AuthlyX Java SDK

This is a Java authentication SDK for desktop and Java applications that want simple integration with the AuthlyX API.

This folder is primarily for SDK users. The sample app here is only a reference example to help you integrate faster.

## Supported Targets

The SDK supports:

- Java 11+

## Install

This example project uses Maven and `gson`.

## Quick Start

```java
public static AuthlyX AuthlyXApp = new AuthlyX(
  "12345678",
  "MYAPP",
  "1.0.0",
  "your-secret"
);

/*
Optional:
- Set debug to false to disable SDK logs.
- Set api to your custom domain, for example: https://example.com/api/v2
*/
```

Then initialize:

```java
AuthlyXApp.Init();
```

## Optional Parameters

```java
public static AuthlyX AuthlyXApp = new AuthlyX(
  "12345678",
  "MYAPP",
  "1.0.0",
  "your-secret",
  false,
  "https://example.com/api/v2"
);
```

### Available options

- `debug`
  - Default: `true`
  - Set `false` to disable SDK logs

- `api`
  - Default: `https://authly.cc/api/v2`
  - Use this for your custom domain

## Available Methods

- `Init()`
- `Login(identifier, password = null, deviceType = null)`
- `Register(username, password, licenseKey, email = "")`
- `ChangePassword(oldPassword, newPassword)`
- `ExtendTime(username, licenseKey)`
- `GetVariable(key)`
- `SetVariable(key, value)`
- `Log(message)`
- `GetChats(channelName)`
- `SendChat(message, channelName = "general")`
- `ValidateSession()`

## Authentication Example

```java
// Username + password
AuthlyXApp.Login("username", "password");

// License key only
AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");

// Device login
AuthlyXApp.Login("YOUR_MOTHERBOARD_ID", null, "motherboard");
```

The SDK routes `Login(...)` automatically:

- `password + identifier` for username login
- `identifier only` for license login
- `deviceType + identifier` for device login

## Username Login Example

```java
AuthlyXApp.Login("username", "password");

if (AuthlyXApp.response.success) {
  System.out.println("Login success");
  System.out.println(AuthlyXApp.userData.Username);
  System.out.println(AuthlyXApp.userData.SubscriptionLevel);
} else {
  System.out.println(AuthlyXApp.response.message);
}
```

`userData.SubscriptionLevel` is populated automatically after username, license, and device authentication flows.

## License Login Example

```java
AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");

if (AuthlyXApp.response.success) {
  System.out.println("License login success");
} else {
  System.out.println(AuthlyXApp.response.message);
}
```

## Device Login Example

### Motherboard

```java
AuthlyXApp.Login("YOUR_MOTHERBOARD_ID", null, "motherboard");

if (AuthlyXApp.response.success) {
  System.out.println("Motherboard login success");
} else {
  System.out.println(AuthlyXApp.response.message);
}
```

### Processor

```java
AuthlyXApp.Login("YOUR_PROCESSOR_ID", null, "processor");

if (AuthlyXApp.response.success) {
  System.out.println("Processor login success");
} else {
  System.out.println(AuthlyXApp.response.message);
}
```

## Variable Example

```java
AuthlyXApp.SetVariable("theme", "dark");

String value = AuthlyXApp.GetVariable("theme");
System.out.println(value);
```

## Change Password Example

```java
AuthlyXApp.ChangePassword("oldpass", "newpass");

if (AuthlyXApp.response.success) {
  System.out.println("Password changed successfully");
} else {
  System.out.println(AuthlyXApp.response.message);
}
```

## Chat Example

```java
AuthlyXApp.SendChat("Hello world", "general");

String chats = AuthlyXApp.GetChats("general");
System.out.println(chats);
```

