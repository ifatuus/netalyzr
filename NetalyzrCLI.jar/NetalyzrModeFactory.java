class NetalyzrModeFactory {
   public static NetalyzrMode get(Netalyzr var0, String var1) {
      if (var1 == null) {
         var1 = "standard";
      } else {
         var1 = var1.toLowerCase();
      }

      if (var1.equals("nobw")) {
         return new NetalyzrNoBandwidthMode(var0);
      } else {
         return (NetalyzrMode)(var1.equals("heise") ? new NetalyzrEmbeddedMode(var0, var1) : new NetalyzrStandardMode(var0, var1));
      }
   }
}
