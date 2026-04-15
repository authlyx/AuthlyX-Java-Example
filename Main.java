import java.util.Scanner;

public final class Main {
  public static AuthlyX AuthlyXApp = new AuthlyX(
    "12345678",
    "HI",
    "1.3",
    "qIBFoBJWQH4jaOZr6Sf8BJZyEVnT0LiN4QfRxJGn",
    true,
    "https://authly.cc/api/v2"
  );

  public static void main(String[] args) {
    System.out.println("==============================================");
    System.out.println("              AUTHLYX JAVA EXAMPLE            ");
    System.out.println("==============================================");
    System.out.println();

    System.out.println("Initializing AuthlyX connection...");
    boolean ok = AuthlyXApp.Init();
    if (!ok) {
      System.out.println("Init failed: " + AuthlyXApp.response.message);
      waitKey();
      return;
    }
    System.out.println("Init success.");

    Scanner sc = new Scanner(System.in);
    while (true) {
      System.out.println();
      System.out.println("1. Username + Password Login");
      System.out.println("2. License Login");
      System.out.println("3. Device Login");
      System.out.println("4. Get Variable");
      System.out.println("5. Set Variable");
      System.out.println("6. Validate Session");
      System.out.println("7. Show User Info");
      System.out.println("0. Exit");
      System.out.print("Choice: ");

      String choice = sc.nextLine().trim();
      if ("0".equals(choice)) break;

      switch (choice) {
        case "1": {
          System.out.print("Username: ");
          String u = sc.nextLine();
          System.out.print("Password: ");
          String p = sc.nextLine();
          boolean r = AuthlyXApp.Login(u, p, null);
          System.out.println(r ? "Login SUCCESS" : "Login FAILED");
          System.out.println("Message: " + AuthlyXApp.response.message);
          break;
        }
        case "2": {
          System.out.print("License Key: ");
          String k = sc.nextLine();
          boolean r = AuthlyXApp.Login(k);
          System.out.println(r ? "Login SUCCESS" : "Login FAILED");
          System.out.println("Message: " + AuthlyXApp.response.message);
          break;
        }
        case "3": {
          System.out.print("Device Type (motherboard/processor): ");
          String t = sc.nextLine();
          System.out.print("Device ID: ");
          String id = sc.nextLine();
          boolean r = AuthlyXApp.Login(id, null, t);
          System.out.println(r ? "Login SUCCESS" : "Login FAILED");
          System.out.println("Message: " + AuthlyXApp.response.message);
          break;
        }
        case "4": {
          System.out.print("Var key: ");
          String k = sc.nextLine();
          String v = AuthlyXApp.GetVariable(k);
          System.out.println("Value: " + v);
          break;
        }
        case "5": {
          System.out.print("Var key: ");
          String k = sc.nextLine();
          System.out.print("Var value: ");
          String v = sc.nextLine();
          boolean r = AuthlyXApp.SetVariable(k, v);
          System.out.println(r ? "SetVariable SUCCESS" : "SetVariable FAILED");
          System.out.println("Message: " + AuthlyXApp.response.message);
          break;
        }
        case "6": {
          boolean r = AuthlyXApp.ValidateSession();
          System.out.println(r ? "ValidateSession SUCCESS" : "ValidateSession FAILED");
          System.out.println("Message: " + AuthlyXApp.response.message);
          break;
        }
        case "7": {
          printUserInfo();
          break;
        }
        default:
          System.out.println("Invalid choice.");
      }
    }

    System.out.println("Bye.");
  }

  private static void printUserInfo() {
    AuthlyX.UserData u = AuthlyXApp.userData;
    System.out.println();
    System.out.println("==================================================");
    System.out.println("USER PROFILE");
    System.out.println("==================================================");
    System.out.println("Username: " + na(u.Username));
    System.out.println("Email: " + na(u.Email));
    System.out.println("License Key: " + na(u.LicenseKey));
    System.out.println("Subscription: " + na(u.Subscription));
    System.out.println("Subscription Level: " + na(u.SubscriptionLevel));
    System.out.println("Expiry Date: " + na(u.ExpiryDate));
    System.out.println("Days Left: " + u.DaysLeft);
    System.out.println("Last Login: " + na(u.LastLogin));
    System.out.println("Registered At: " + na(u.RegisteredAt));
    System.out.println("HWID/SID: " + na(u.Hwid));
    System.out.println("IP Address: " + na(u.IpAddress));
    System.out.println("==================================================");
  }

  private static String na(String s) {
    return (s == null || s.isBlank()) ? "N/A" : s;
  }

  private static void waitKey() {
    System.out.println("Press Enter to exit...");
    try {
      new Scanner(System.in).nextLine();
    } catch (Exception ignored) {
    }
  }
}

