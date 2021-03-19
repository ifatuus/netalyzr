import java.io.IOException;
import java.net.SocketException;
import java.net.URL;
import java.text.DecimalFormat;
import java.util.Date;
import java.util.Properties;

class NetalyzrCLI implements NetalyzrShell {
   Netalyzr neta = new Netalyzr(this);
   Properties config;
   String netaRoot = "netalyzr.icsi.berkeley.edu";
   long startTime;
   DecimalFormat twoDigitFmt = new DecimalFormat("00");
   String mode = "cli";
   boolean quiet = false;
   boolean simple;
   int lastLineLen;
   String lastMessage;

   NetalyzrCLI() {
      this.neta.debugStdout = false;
   }

   public static void main(String[] var0) {
      NetalyzrCLI var1 = new NetalyzrCLI();

      for(int var2 = 0; var2 < var0.length; ++var2) {
         if (var0[var2].equals("-d")) {
            var1.neta.debugStdout = true;
         }

         if (var0[var2].equals("-m") && var2 < var0.length - 1) {
            var1.mode = var0[var2 + 1] + "-cli";
         }

         if (var0[var2].equals("-q")) {
            var1.quiet = true;
         }

         if (var0[var2].equals("-s")) {
            var1.simple = true;
         }
      }

      var1.init();
      var1.start();
   }

   public void init() {
      try {
         URL var1 = new URL("http://" + this.netaRoot + "/analysis/m=" + this.mode);
         this.config = new Properties();
         this.config.load(var1.openStream());
      } catch (SocketException var5) {
         this.logErr("Failed to contact Netalyzr to retrieve the current configuration");
         this.logErr("");
         this.logErr("Caught Socket Exception " + var5);
         this.logErr("Java runtime: " + System.getProperty("java.version") + " from " + System.getProperty("java.vendor"));
         if ("Network is unreachable".equals(var5.getMessage()) && "Linux".equals(System.getProperty("os.name"))) {
            this.logErr("Try executing \"sudo sysctl -w net.ipv6.bindv6only=0\"");
            this.logErr("and re-run the command line client.");
         }

         System.exit(2);
      } catch (IOException var6) {
         this.logErr("Failed to contact Netalyzr to retrieve the current configuration");
         this.logErr("");
         this.logErr("Caught IOException " + var6);
         this.logErr("Java runtime: " + System.getProperty("java.version") + " from " + System.getProperty("java.vendor"));
         System.exit(2);
      }

      this.neta.init();
      String var7 = "ICSI Netalyzr CLI, build " + this.getBuildNumber();
      String var2 = this.neta.utcTime();
      String var3 = "ID " + this.getParameter("AGENT_ID");
      int var4 = Math.max(var7.length(), var3.length());
      this.log("==== " + this.neta.padString(var7, var4) + " ====");
      this.log("==== " + this.neta.padString(var2, var4) + " ====");
      this.log("==== " + this.neta.padString(var3, var4) + " ====");
      this.log("");
   }

   public void start() {
      this.startTime = (new Date()).getTime();
      this.neta.start();

      while(!this.neta.testsComplete) {
         try {
            Thread.sleep(1000L);
         } catch (InterruptedException var2) {
            break;
         }
      }

      System.exit(3);
   }

   public String getBackendHost() {
      return this.config.getProperty("NODE") + "." + this.netaRoot;
   }

   public int getBackendPort() {
      return 80;
   }

   public String getParameter(String var1) {
      return this.config.getProperty(var1);
   }

   public URL getResource(String var1) {
      return this.getClass().getResource(var1);
   }

   public int getBuildNumber() {
      return 57861;
   }

   public void enableRedraw() {
   }

   public void updateDisplay() {
      Date var1 = new Date((new Date()).getTime() - this.startTime);
      String var2 = var1.toString().substring(14, 19);
      if (!this.neta.initSucceeded) {
         this.logErr("Initialization failed:");
         this.logErr(this.neta.initFailureMsg);
         this.logErr("Please see the FAQ page for help + contact information.");
         System.exit(1);
      }

      if (!this.neta.isLatestVersion) {
         this.logErr("Sorry, you are using an outdated JAR.");
         this.logErr("Please retrieve the latest from this URL, and try again:");
         this.logErr("http://" + this.netaRoot + "/NetalyzrCLI.jar");
         System.exit(1);
      }

      String var3;
      if (this.neta.getCurTestIdx() < this.neta.getNumTests()) {
         Netalyzr.Test var4 = this.neta.getTest(this.neta.getCurTestIdx());
         var3 = var4.idleMsg + "...";
      } else {
         var3 = this.neta.idleMsg + "...";
      }

      if (!this.quiet) {
         if (this.simple) {
            var3 = var2 + " " + this.twoDigitFmt.format((long)this.neta.getCurTestIdx()) + "/" + this.twoDigitFmt.format((long)this.neta.getNumTests()) + "  " + var3;
            if (!var3.equals(this.lastMessage)) {
               System.out.print("\n" + var3);
               this.lastMessage = var3;
            }
         } else if (!this.neta.debugStdout) {
            System.out.print("\r");

            for(int var5 = 0; var5 < this.lastLineLen + 7; ++var5) {
               System.out.print(" ");
            }

            var3 = var2 + " " + this.twoDigitFmt.format((long)this.neta.getCurTestIdx()) + "/" + this.twoDigitFmt.format((long)this.neta.getNumTests()) + "  " + var3;
            System.out.print("\r" + var3);
            this.lastLineLen = var3.length();
         }
      }

   }

   public void complete(String var1) {
      this.log("\n");
      this.log("Tests complete, results available at:");
      this.log(var1);
      if (this.quiet) {
         System.out.print(var1 + "\n");
      }

      System.exit(0);
   }

   void logErr(String var1) {
      if (var1.equals("")) {
         System.err.println("");
      } else {
         System.err.println("*** " + var1);
      }

   }

   void log(String var1) {
      if (!this.quiet) {
         System.out.println(var1);
      }

   }
}
