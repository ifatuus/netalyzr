import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.EmptyStackException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Stack;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

public class UpnpDescription extends DefaultHandler {
   Netalyzr na;
   String descr;
   String upnpUrl;
   HashMap contents = new HashMap();
   HashMap calls = new HashMap();
   Stack ctxMaps = new Stack();
   Stack ctxNodes = new Stack();
   StringBuffer ctxChars = new StringBuffer();
   String ctxDevice;
   UpnpDescription.Service ctxService;

   public UpnpDescription(Netalyzr var1, String var2, String var3) {
      this.na = var1;
      this.descr = var2.trim();
      int var4 = this.descr.indexOf("<?");
      if (var4 >= 0) {
         this.descr = this.descr.substring(var4);
      }

      this.upnpUrl = var3;
      this.ctxMaps.push(this.contents);
   }

   public void parse() {
      try {
         SAXParserFactory var1 = SAXParserFactory.newInstance();
         var1.setNamespaceAware(true);
         SAXParser var2 = var1.newSAXParser();
         XMLReader var3 = var2.getXMLReader();
         var3.setContentHandler(this);
         var3.parse(new InputSource(new StringReader(this.descr)));
      } catch (IOException var4) {
         this.na.debug("XML parsing IO exception: " + var4);
      } catch (SAXException var5) {
         this.na.debug("XML parsing SAX exception: " + var5);
      } catch (ParserConfigurationException var6) {
         this.na.debug("XML parsing config exception: " + var6);
      }

   }

   public int call(String var1, String var2, String var3, String var4) {
      return this.call(var1, var2, var3, var4, (String[])null);
   }

   public int call(String var1, String var2, String var3, String var4, String[] var5) {
      String var6 = var2 + "/" + var3 + "/" + var4;
      ArrayList var7 = this.getServices(var2, var3);
      int var8 = 0;
      this.na.debug("UPnP call, context " + var1 + ", API " + var2 + "|" + var3 + "|" + var4);
      if (var7.size() == 0) {
         this.na.debug("UPnP device does not have service " + var6);
         return 0;
      } else {
         for(int var9 = 0; var9 < var7.size(); ++var9) {
            UpnpDescription.Service var10 = (UpnpDescription.Service)var7.get(var9);
            UpnpSoapDispenser var11 = new UpnpSoapDispenser(this.na);
            String var12 = var11.call(this.makeUrl(var10.ctrlPath), var10.type, var4, var5);
            if (var12 != null) {
               this.na.debug("UPnP call " + var6 + " succeeded");
               String var13 = "calls/" + var1 + "/" + var10.device.replace(":", ".") + "/" + var3 + "/" + var4;
               this.calls.put(var13, var12);
               ++var8;
            }
         }

         return var8;
      }
   }

   public byte[] produceZip() {
      ByteArrayOutputStream var1 = new ByteArrayOutputStream();
      ZipOutputStream var2 = new ZipOutputStream(var1);
      Stack var3 = new Stack();
      this.produceZipImpl(var2, var3, this.contents);
      Iterator var4 = this.calls.entrySet().iterator();

      while(var4.hasNext()) {
         Entry var5 = (Entry)var4.next();
         String var6 = (String)var5.getKey();
         String var7 = (String)var5.getValue();
         if (!var6.endsWith(".xml")) {
            var6 = var6 + ".xml";
         }

         try {
            var2.putNextEntry(new ZipEntry(this.na.agentID + "/" + var6));
            var2.write(var7.getBytes());
            var2.closeEntry();
         } catch (IOException var10) {
         }
      }

      try {
         var2.flush();
         var2.close();
         var1.flush();
      } catch (IOException var9) {
      }

      return var1.toByteArray();
   }

   public void startElement(String var1, String var2, String var3, Attributes var4) throws SAXException {
      String var5 = var2.toLowerCase();
      this.ctxNodes.push(var5);
      this.ctxChars = new StringBuffer();
      if (var5.equals("device")) {
         this.ctxMaps.push(new HashMap());
      } else if (var5.equals("service")) {
         this.ctxService = new UpnpDescription.Service();
      }

   }

   public void endElement(String var1, String var2, String var3) throws SAXException {
      try {
         String var4 = (String)this.ctxNodes.pop();
         if (var4.equals("controlurl")) {
            this.ctxService.ctrlPath = this.ctxChars.toString().trim();
         } else if (var4.equals("device")) {
            this.ctxMaps.pop();
            this.contents = (HashMap)this.ctxMaps.peek();
         } else if (var4.equals("devicetype")) {
            this.ctxDevice = this.ctxChars.toString().trim();
            this.contents.put(this.ctxDevice, this.ctxMaps.peek());
            this.contents = (HashMap)this.ctxMaps.peek();
         } else if (var4.equals("service")) {
            this.ctxService = null;
         } else if (var4.equals("servicetype")) {
            this.ctxService.device = this.ctxDevice;
            this.ctxService.type = this.ctxChars.toString().trim();
            this.contents.put(this.ctxService.type, this.ctxService);
            this.na.debug("Found UPnP service " + this.ctxService.type);
         } else if (var4.equals("scpdurl")) {
            this.ctxService.scpdPath = this.ctxChars.toString().trim();
            this.ctxService.scpdData = this.getServiceDescription(this.ctxService.scpdPath);
         }
      } catch (EmptyStackException var5) {
      }

   }

   public void characters(char[] var1, int var2, int var3) throws SAXException {
      this.ctxChars.append(var1, var2, var3);
   }

   private String getServiceDescription(String var1) {
      String var2 = this.makeUrl(var1);
      this.na.debug("SCPD grab from " + var2);
      return this.na.getHttpData(var2);
   }

   private ArrayList getServices(String var1, String var2) {
      ArrayList var3 = new ArrayList();
      this.getServicesImpl(var3, var1, var2, this.contents, false);
      return var3;
   }

   private void getServicesImpl(ArrayList var1, String var2, String var3, HashMap var4, boolean var5) {
      Iterator var6 = var4.entrySet().iterator();

      while(true) {
         Entry var8;
         String var9;
         do {
            if (!var6.hasNext()) {
               return;
            }

            var8 = (Entry)var6.next();
            var9 = (String)var8.getKey();
            if (var8.getValue() instanceof UpnpDescription.Service) {
               UpnpDescription.Service var7 = (UpnpDescription.Service)var8.getValue();
               if (var7.type.indexOf(var3) >= 0 && var5) {
                  var1.add(var7);
               }
            }
         } while(!(var8.getValue() instanceof HashMap));

         boolean var10 = false;
         if (var2.equals("*") || var9.indexOf(var2) >= 0) {
            var10 = true;
         }

         this.getServicesImpl(var1, var2, var3, (HashMap)var8.getValue(), var10);
      }
   }

   private void produceZipImpl(ZipOutputStream var1, Stack var2, HashMap var3) {
      Iterator var4 = var3.entrySet().iterator();
      StringBuffer var5 = new StringBuffer();

      for(int var6 = 0; var6 < var2.size(); ++var6) {
         var5.append(var2.elementAt(var6));
         var5.append("/");
      }

      String var12 = var5.toString();

      while(var4.hasNext()) {
         Entry var7 = (Entry)var4.next();
         String var8 = (String)var7.getKey();
         var8 = var8.replace(":", ".");
         if (var7.getValue() instanceof UpnpDescription.Service) {
            UpnpDescription.Service var9 = (UpnpDescription.Service)var7.getValue();
            if (var9.scpdData != null) {
               try {
                  if (!var8.endsWith(".xml")) {
                     var8 = var8 + ".xml";
                  }

                  var1.putNextEntry(new ZipEntry(this.na.agentID + "/scpd/" + var12 + var8));
                  var1.write(var9.scpdData.getBytes());
                  var1.closeEntry();
               } catch (IOException var11) {
               }
            }
         } else if (var7.getValue() instanceof HashMap) {
            var2.push(var8);
            this.produceZipImpl(var1, var2, (HashMap)var7.getValue());
            var2.pop();
         }
      }

   }

   private String makeUrl(String var1) {
      String var2;
      if (var1.startsWith("/")) {
         String var3 = this.upnpUrl.split("http://")[1];
         var3 = var3.split("/")[0];
         var2 = "http://" + var3 + var1;
      } else {
         var1 = "/" + var1;
         var1 = var1.replace("//", "/");
         var2 = this.upnpUrl + var1;
      }

      return var2;
   }

   class Service {
      String device = "unknown";
      String type = "unknown";
      String scpdPath;
      String scpdData;
      String ctrlPath;
   }
}
