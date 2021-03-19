public class UpnpIGD {
   private static int idCounter = 0;
   int id;
   String url;
   String addr;
   UpnpDescription descr;
   String status = "noloc";
   String ssdp = "";

   UpnpIGD() {
      this.id = idCounter++;
   }
}
