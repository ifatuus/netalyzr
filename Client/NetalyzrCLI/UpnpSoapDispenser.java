import java.net.MalformedURLException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.Vector;

public class UpnpSoapDispenser {
   Netalyzr na;
   String sep = "\r\n";
   String soapReqHdrTmpl;
   String soapReqBodyTmpl;

   UpnpSoapDispenser(Netalyzr var1) {
      this.soapReqHdrTmpl = "POST {0} HTTP/1.1" + this.sep + "Content-Length: {1}" + this.sep + "Content-Type: text/xml; charset=\"utf-8\"" + this.sep + "User-Agent: {2}/{3} UPnP/1.1 Netalyzr/1.0" + this.sep + "SOAPACTION: \"{4}#{5}\"" + this.sep + "Connection: close " + this.sep + this.sep;
      this.soapReqBodyTmpl = "<?xml version=\"1.0\"?>" + this.sep + "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"" + this.sep + "            s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" + this.sep + "  <s:Body>" + this.sep + "    <u:{0} xmlns:u=\"{1}\">" + this.sep + "{2}    </u:{0}>" + this.sep + "  </s:Body>" + this.sep + "</s:Envelope>" + this.sep;
      this.na = var1;
   }

   String call(String var1, String var2, String var3, String[] var4) {
      URL var5;
      try {
         var5 = new URL(var1);
      } catch (MalformedURLException var7) {
         this.na.debug("HTTP GET failed, malformed URL");
         return null;
      }

      String var6 = this.composeRequest(var5, var2, var3, var4);
      return this.na.postHttpData(var1, var6);
   }

   private String composeRequest(URL var1, String var2, String var3, String[] var4) {
      String var5 = "";
      String var8;
      if (var4 != null) {
         for(int var6 = 0; var6 < var4.length; ++var6) {
            String[] var7 = var4[var6].split(":", 1);
            if (var7.length == 2) {
               var8 = var7[0].trim();
               String var9 = var7[1].trim();
               var5 = var5 + "      <" + var8.trim() + ">" + var9.trim() + "<" + var8.trim() + ">" + this.sep;
            }
         }
      }

      Vector var10 = new Vector();
      var10.add(var3);
      var10.add(var2);
      var10.add(var5);
      String var11 = MessageFormat.format(this.soapReqBodyTmpl, var10.toArray());
      var10 = new Vector();
      var10.add(var1.getFile());
      var10.add(Integer.toString(var11.length()));
      var10.add(System.getProperty("os.name"));
      var10.add(System.getProperty("os.version"));
      var10.add(var2);
      var10.add(var3);
      var8 = MessageFormat.format(this.soapReqHdrTmpl, var10.toArray());
      return var8 + var11;
   }
}
