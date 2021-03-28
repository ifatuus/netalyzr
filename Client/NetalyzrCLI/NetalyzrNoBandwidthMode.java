import java.util.ArrayList;

class NetalyzrNoBandwidthMode extends NetalyzrStandardMode {
   NetalyzrNoBandwidthMode(Netalyzr var1) {
      super(var1, "nobw");
   }

   public String getResultsURL() {
      this.neta.idleMsg = this.neta.getLocalString("testsComplete");
      return "http://" + this.neta.getHTTPServerName() + "/summary/id=" + this.neta.agentID;
   }

   public void customizeTests() {
      ArrayList var1 = new ArrayList();

      for(int var2 = 0; var2 < this.neta.tests.size(); ++var2) {
         Netalyzr.Test var3 = (Netalyzr.Test)this.neta.tests.get(var2);
         if (!var3.testName.equals("checkUplink") && !var3.testName.equals("checkDownlink")) {
            var1.add(var3);
         } else {
            this.neta.skippedTests.add(this.neta.createSkippedTest(var3.testName));
         }
      }

      this.neta.tests = var1;
   }
}
