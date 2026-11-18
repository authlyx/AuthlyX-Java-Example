package app.authlyx.example;

import app.authlyx.AuthlyX;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.Console;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public final class Main
{
    private static final Scanner INPUT = new Scanner(System.in);
    private static final boolean INTERACTIVE = System.console() != null;

    public static void main(String[] args)
    {
        title("Connecting...");
        try (AuthlyX app = new AuthlyX("test_09f6d82a741beb5078fbb11b49c178b3e03ec556a5d130fc", "1.0"))
        {
            String notice = "";
            while (true)
            {
                title("Connecting...");
                AuthlyX.Result initialized = app.initialize().join();
                if (initialized.ok())
                {
                    notice = initialized.code().equals("OFFLINE_MODE") ? initialized.message() : "";
                    break;
                }
                title("Could not connect");
                System.out.println(initialized.message());
                System.out.println("\n  1  Try again\n  0  Exit\n");
                if (!ask("Choose").equals("1"))
                    return;
            }
            while (notice != null)
            {
                notice = app.hasAccess().join() ? mainMenu(app, notice) : signIn(app, notice);
            }
        }
        catch (Exception error)
        {
            System.out.println(message(error));
            System.exit(1);
        }
    }

    private static String signIn(AuthlyX app, String notice)
    {
        title("Sign in");
        showNotice(notice);
        System.out.println("  1  Username and password\n  2  License key\n  3  This device\n  0  Exit\n");
        String choice = ask("Choose");
        try
        {
            switch (choice)
            {
            case "1" -> {
                String username = ask("Username");
                app.login(username, password()).join();
            }
            case "2" -> app.login(ask("License key")).join();
            case "3" -> app.deviceLogin().join();
            case "0", "" -> {
                return null;
            }
            default -> {
                return "Choose 1, 2, 3 or 0.";
            }
            }
            return "";
        }
        catch (CompletionException error)
        {
            return message(error);
        }
    }

    private static String mainMenu(AuthlyX app, String notice)
    {
        JsonNode user = app.userData;
        title("Signed in as " + text(user.path("name")) + "  |  " + text(user.path("plan")) +
              " plan  |  Expires " + expiry(user));
        showNotice(notice);
        System.out.println("  1  Account details          6  Check session\n"
                           + "  2  Read a variable          7  Send a log\n"
                           + "  3  Update a variable        8  Save offline access\n"
                           + "  4  Features and metadata    9  Sign out\n"
                           + "  5  Fetch a script           0  Exit\n");
        String choice = ask("Choose");
        try
        {
            switch (choice)
            {
            case "0", "" -> {
                return null;
            }
            case "1" -> showAccount(user);
            case "2" -> {
                String name = ask("Variable name");
                AuthlyX.Result result = run(app.getVariable(name), "Variable");
                row("Name", name);
                row("Value", text(result.data().path("value")));
            }
            case "3" -> {
                String name = ask("Variable name");
                String value = ask("New value");
                System.out.println(run(app.updateVariable(name, value), "Update a variable").message());
            }
            case "4" -> {
                AuthlyX.Result features = app.getFeatures().join();
                AuthlyX.Result metadata = run(app.getAllMetadata(), "Features and metadata");
                showList("Features", features.data().path("features"), "No features on this plan.");
                System.out.println();
                showList("Metadata", metadata.data().path("metadata"), "No metadata.");
            }
            case "5" -> {
                String name = ask("Script name");
                AuthlyX.Result result = run(app.getScript(name, null), "Script: " + name);
                System.out.println(text(result.data().path("content")));
            }
            case "6" -> System.out.println(run(app.checkSession(), "Session").message());
            case "7" -> {
                String message = ask("Log message");
                System.out.println(run(app.log(message), "Send a log").message());
            }
            case "8" -> System.out.println(run(app.saveOfflineAccess(), "Offline access").message());
            case "9" -> {
                app.logout().join();
                return "You are signed out.";
            }
            default -> {
                return "Choose one of the listed options.";
            }
            }
        }
        catch (CompletionException error)
        {
            title("Something went wrong");
            System.out.println(message(error));
        }
        pause();
        return "";
    }

    private static AuthlyX.Result run(CompletableFuture<AuthlyX.Result> request, String heading)
    {
        AuthlyX.Result result = request.join();
        title(heading);
        return result;
    }

    private static void showAccount(JsonNode user)
    {
        title("Account details");
        switch (user.path("type").asText())
        {
        case "license" -> row("License key", text(user.path("name")));
        case "device" -> row("Device", text(user.path("name")));
        default -> {
            row("Username", text(user.path("name")));
            if (!user.path("licenseKey").asText().isEmpty())
                row("License key", user.path("licenseKey").asText());
        }
        }
        row("Email", text(user.path("email")));
        row("Plan", text(user.path("plan")));
        row("Expires", expiry(user));
        JsonNode limit = user.path("deviceLimit");
        row("Device limit", limit.isNumber() && limit.asInt() == 0 ? "Unlimited" : text(limit));
        row("Registered", when(user.path("registeredAt")));
        row("Last sign-in", when(user.path("lastLogin")));
        row("System ID", text(user.path("systemId")));
        row("IP address", text(user.path("ipAddress")));
        row("Country", text(user.path("country")));
    }

    private static void showList(String heading, JsonNode values, String empty)
    {
        System.out.println(heading);
        if (!values.isObject() || values.isEmpty())
        {
            System.out.println("  " + empty);
            return;
        }
        for (Map.Entry<String, JsonNode> item : values.properties())
        {
            row(item.getKey(), text(item.getValue()));
        }
    }

    private static String text(JsonNode value)
    {
        if (value == null || value.isNull() || value.isMissingNode())
            return "-";
        if (value.isBoolean())
            return value.asBoolean() ? "Yes" : "No";
        if (value.isTextual())
            return value.asText().isEmpty() ? "-" : value.asText();
        return value.toString();
    }

    private static String when(JsonNode value)
    {
        String s = value.asText("");
        return s.length() >= 16 ? s.substring(0, 10) + " " + s.substring(11, 16) + " UTC" : text(value);
    }

    private static String expiry(JsonNode user)
    {
        String s = user.path("expiry").asText("");
        return user.path("expiry").isTextual() && s.length() >= 10 ? s.substring(0, 10) : "Never";
    }

    private static void row(String label, String value)
    {
        System.out.printf("  %-16s%s%n", label, value);
    }

    private static String message(Throwable error)
    {
        Throwable cause = error instanceof CompletionException && error.getCause() != null ? error.getCause() : error;
        return cause.getMessage();
    }

    private static void title(String text)
    {
        if (INTERACTIVE)
        {
            System.out.print("\033[H\033[2J");
            System.out.flush();
        }
        System.out.println("AuthlyX  |  Java example\n\n" + text + "\n");
    }

    private static void showNotice(String notice)
    {
        if (!notice.isEmpty())
            System.out.println(notice + "\n");
    }

    private static String ask(String label)
    {
        System.out.print(label + ": ");
        System.out.flush();
        if (!INPUT.hasNextLine())
            System.exit(0);
        return INPUT.nextLine().trim();
    }

    private static String password()
    {
        Console console = System.console();
        return console == null ? ask("Password") : new String(console.readPassword("Password: "));
    }

    private static void pause()
    {
        ask("\nPress Enter to go back");
    }
}
