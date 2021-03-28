class NetalyzrEmbeddedMode extends NetalyzrStandardMode {
   NetalyzrEmbeddedMode(Netalyzr var1, String var2) {
      super(var1, var2);
   }

   public String getResultsURL() {
      this.neta.idleMsg = this.neta.getLocalString("testsCompleteEmbedded");
      return "http://" + this.neta.getHTTPServerName() + "/summary/id=" + this.neta.agentID;
   }
}
