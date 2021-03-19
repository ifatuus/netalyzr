class NetalyzrStandardMode implements NetalyzrMode {
   Netalyzr neta;
   String name;

   NetalyzrStandardMode(Netalyzr var1, String var2) {
      this.neta = var1;
      this.name = var2;
   }

   public String getName() {
      return this.name;
   }

   public String getResultsURL() {
      this.neta.idleMsg = this.neta.getLocalString("testsComplete");
      return this.name.equals("standard") ? "http://" + this.neta.getHTTPServerName() + "/blank.html" : "http://" + this.neta.getHTTPServerName() + "/summary/id=" + this.neta.agentID;
   }

   public void customizeTests() {
   }
}
