import java.net.URL;

public interface NetalyzrShell {
   void init();

   void start();

   String getBackendHost();

   int getBackendPort();

   String getParameter(String var1);

   URL getResource(String var1);

   int getBuildNumber();

   void enableRedraw();

   void updateDisplay();

   void complete(String var1);
}
