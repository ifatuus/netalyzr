import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.PropertyResourceBundle;
import java.util.Random;
import java.util.TimeZone;
import java.util.Map.Entry;

public class Netalyzr {
   NetalyzrShell shell;
   NetalyzrMode mode;
   ArrayList tests;
   int currentTest;
   ArrayList skippedTests;
   String serverName;
   int serverPort;
   String netalyzrDomain;
   String nodeName;
   String nonce;
   String agentID;
   String idleMsg;
   String ipv6Server;
   String ipv4Server;
   PropertyResourceBundle l10nMsgs;
   String userAgent;
   String accept;
   String acceptLanguage;
   String acceptEncoding;
   String acceptCharset;
   String custDnsName;
   String custDnsAltName;
   String custDnsAddr;
   String dnsNxAddr;
   String globalClientAddr;
   int globalClientCheckedPort;
   ArrayList foundNatAddrs = new ArrayList();
   String localClientAddr;
   String globalHTTPAddr;
   String globalRawHTTPAddr;
   String proxyHost;
   int proxyPort;
   InetAddress trueIP;
   boolean acceptNSGlue;
   boolean ipv6DNSOK;
   long[] tcpSetupLatency;
   long[] tcpFirstSetupLatency;
   int tcpSetupCount;
   int tcpFirstSetupCount;
   int maxTcpSetupCount;
   String tcpSetups;
   String httpTimings;
   HashSet contactedTcpPorts;
   ArrayList nameLookups = new ArrayList();
   ArrayList addrLookups = new ArrayList();
   public static final String[] expectedResponseHeaders = new String[]{"Server", "Date", "ICSI-Client-Addr", "ConTent-Type", "Content-LenGth", "Last-ModIfied", "Set-CooKIE", "ConnEction"};
   boolean isLatestVersion;
   boolean initSucceeded = false;
   String initFailureMsg;
   public boolean testsRunning = false;
   public boolean testsComplete = false;
   public boolean canDoRestrictedLookup;
   public boolean canDoUnrestrictedLookup;
   public boolean canDoRawTCP;
   public boolean canDoRawUDP;
   public boolean canDoRawHTTP;
   public boolean canDoV6;
   InetAddress v6server;
   InetAddress v4server;
   public boolean startedPingTest;
   int transcodeCount = 1;
   public boolean debugStdout = true;
   StringBuffer debugOutput = new StringBuffer();
   long debugStartTime;
   volatile Thread processThread;
   static DecimalFormat tsFormatter = new DecimalFormat("000.000");
   Random rng;
   boolean canSendFragmentedUDP = false;
   int v6SendMTU;
   Hashtable upnpIGDs = new Hashtable();
   public static int[] proxyPortsToTest = new int[]{21, 22, 25, 80, 110, 135, 139, 143, 161, 443, 445, 465, 585, 587, 993, 995, 1194, 1723, 5060, 6881, 9001};
   public ArrayList tracebackProxyPorts = new ArrayList();
   public static String[] expectedParameters = new String[]{"ACCEPT", "ACCEPT_LANGUAGE", "ACCEPT_ENCODING", "ACCEPT_CHARSET", "AGENT_ID", "ALTERNATE_SERVER", "ALTERNATE_SERVER_PORT", "CACHED_NAME", "CUST_DNS_DOMAIN", "CUST_DNS_ALT_DOMAIN", "CUST_DNS_ADDR", "DNS_ECHO_PORT", "DNS_SERVER", "EXE_FILE", "EXE_LENGTH", "FAKE_VIRUS_FILE", "FAKE_VIRUS_LENGTH", "FRAGMENT_ECHO_PORT", "FRAGMENT_ECHO_PORT_V6", "IMAGE_LENGTH", "INVALID_DNS_NAME", "INVALID_DNS_DOMAIN", "LANG", "MODE", "MP3_FILE", "MP3_LENGTH", "REPORT_SERVER", "REPORT_SERVER_PORT", "TCP_ECHO_PORT", "TORRENT_FILE", "TORRENT_LENGTH", "UDP_BUFFER_PORT", "UDP_ECHO_PORT", "UNCACHED_NAME", "USER_AGENT", "VALID_DNS_NAME"};
   int printParseIntCount = 0;

   Netalyzr(NetalyzrShell var1) {
      this.shell = var1;
   }

   public void init() {
      try {
         this.init_impl();
      } catch (Throwable var3) {
         this.initFailureMsg = "";
         StackTraceElement[] var2 = var3.getStackTrace();
         if (var2 != null && var2.length > 0) {
            this.initFailureMsg = this.initFailureMsg + var2[0].getFileName() + "@" + var2[0].getLineNumber() + ": ";
         }

         this.initFailureMsg = this.initFailureMsg + var3.getClass().getName();
      }

   }

   private boolean init_l10n() {
      String var1 = this.shell.getParameter("LANG");
      if (var1 == null) {
         var1 = "en-US";
      }

      String[] var2 = var1.split("-");
      String var3 = var2[0];
      String var4 = null;
      ArrayList var5 = new ArrayList();
      String var6 = "Netalyzr";
      if (var2.length == 2) {
         var4 = var2[1];
      } else {
         var4 = var3.toUpperCase();
      }

      if (var3.length() != 2 || !Character.isLetter(var3.charAt(0)) || !Character.isLetter(var3.charAt(1))) {
         var3 = "en";
         var4 = "US";
      }

      this.debug("Given locale " + var1 + ", resulting language/country: " + var3 + "/" + var4);
      if (var4 != null && var4.length() == 2 && Character.isLetter(var4.charAt(0)) && Character.isLetter(var4.charAt(1))) {
         var5.add(var6 + "_" + var3 + "_" + var4 + ".properties");
      }

      var5.add(var6 + "_" + var3 + ".properties");
      var5.add(var6 + "_en_US.properties");

      for(int var7 = 0; var7 < var5.size(); ++var7) {
         String var8 = (String)var5.get(var7);
         URL var9 = this.shell.getResource("/" + var8);
         if (var9 != null && var9.getProtocol().toLowerCase().equals("jar")) {
            try {
               InputStream var10 = var9.openStream();
               this.l10nMsgs = new PropertyResourceBundle(var10);
               this.debug("Language " + var1 + " localized as per " + var8);
               break;
            } catch (Exception var11) {
               this.debug("Caught exception during localization process " + var11);
            }
         }
      }

      return this.l10nMsgs != null;
   }

   void init_impl() {
      this.debugStartTime = (new Date()).getTime();
      this.mode = NetalyzrModeFactory.get(this, this.shell.getParameter("MODE"));
      String var1 = "Welcome to the ICSI Netalyzr, build " + this.shell.getBuildNumber();
      String var2 = "Client-side transcript";
      String var3 = this.utcTime();
      String var4 = "Test mode: " + this.mode.getName() + ", via " + this.mode.getClass().getName();
      String var5 = "ID " + this.shell.getParameter("AGENT_ID");
      int var6 = Math.max(Math.max(var1.length(), var4.length()), var5.length());
      this.debug("==== " + this.padString(var1, var6) + " ====");
      this.debug("==== " + this.padString(var2, var6) + " ====");
      this.debug("==== " + this.padString(var3, var6) + " ====");
      this.debug("==== " + this.padString(var4, var6) + " ====");
      this.debug("==== " + this.padString(var5, var6) + " ====");
      this.debug("");
      this.debug("Java runtime: " + System.getProperty("java.version") + " from " + System.getProperty("java.vendor"));
      if (!this.init_l10n()) {
         this.idleMsg = "Error during language localization.";
      } else {
         this.idleMsg = this.getLocalString("testsComplete");
         this.v6SendMTU = -1;
         this.rng = new Random();
         byte[] var7 = new byte[4];
         this.tcpSetupLatency = new long[64];
         this.tcpFirstSetupLatency = new long[64];
         this.tcpSetupCount = 0;
         this.tcpFirstSetupCount = 0;
         this.maxTcpSetupCount = 64;
         this.tcpSetups = "";
         this.httpTimings = "";
         this.contactedTcpPorts = new HashSet();
         this.userAgent = this.shell.getParameter("USER_AGENT");
         this.accept = this.shell.getParameter("ACCEPT");
         this.acceptLanguage = this.shell.getParameter("ACCEPT_LANGUAGE");
         this.acceptEncoding = this.shell.getParameter("ACCEPT_ENCODING");
         this.acceptCharset = this.shell.getParameter("ACCEPT_CHARSET");
         this.agentID = this.shell.getParameter("AGENT_ID");
         this.nonce = "u" + Integer.toString((int)(Math.random() * 20000.0D));
         this.serverName = this.shell.getBackendHost();
         this.serverPort = this.shell.getBackendPort();
         this.netalyzrDomain = this.shell.getParameter("CUST_DNS_DOMAIN");
         this.ipv4Server = this.shell.getParameter("IPV4_SERVER");
         this.ipv6Server = this.shell.getParameter("IPV6_SERVER");
         this.nodeName = this.serverName.split("\\.")[0];
         this.acceptNSGlue = false;
         this.ipv6DNSOK = false;
         if (this.nodeName.compareToIgnoreCase("www") == 0) {
            this.nodeName = "none";
         }

         if (this.serverPort == -1) {
            this.serverPort = 80;
         }

         this.debug("Main host: " + this.serverName + ":" + this.serverPort);
         this.debug("Node: " + this.nodeName);
         this.custDnsName = this.nonce + "." + this.nodeName + "." + this.shell.getParameter("CUST_DNS_DOMAIN");
         this.custDnsAltName = this.nonce + "." + this.shell.getParameter("CUST_DNS_ALT_DOMAIN");
         this.custDnsAddr = this.shell.getParameter("CUST_DNS_ADDR");
         this.dnsNxAddr = "";
         this.globalClientAddr = "0.0.0.0";
         this.localClientAddr = "0.0.0.0";
         this.globalHTTPAddr = "0.0.0.0";
         this.globalRawHTTPAddr = "0.0.0.0";
         this.proxyHost = null;
         this.proxyPort = -1;
         this.tracebackProxyPorts.add(new Integer(80));
         this.isLatestVersion = true;
         this.makeTests();
         this.mode.customizeTests();
         this.initTests();
         DNSMessage.netalyzrInstance = this;
         this.initSucceeded = true;
      }
   }

   public void start() {
      if (this.isLatestVersion && this.initSucceeded && this.processThread == null && !this.testsRunning) {
         Runnable var1 = new Runnable() {
            public void run() {
               Netalyzr.this.testsRunning = true;
               if (Netalyzr.this.runTests()) {
                  Netalyzr.this.reportResults();
               }

               Netalyzr.this.testsRunning = false;
               Netalyzr.this.testsComplete = true;
            }
         };
         this.processThread = new Thread(var1);
         this.processThread.start();
      }

   }

   public void stop() {
      this.processThread = null;
   }

   public int getNumTests() {
      return this.tests.size();
   }

   public int getCurTestIdx() {
      return this.currentTest;
   }

   public Netalyzr.Test getTest(int var1) {
      return (Netalyzr.Test)this.tests.get(var1);
   }

   public Netalyzr.Test createSkippedTest(String var1) {
      return new Netalyzr.ModeSkippedTest(var1);
   }

   void makeTests() {
      this.tests = new ArrayList();
      this.skippedTests = new ArrayList();
      this.tests.add(new Netalyzr.Test("checkBrowserParameters") {
         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() {
            return 4;
         }

         String getPostResults() {
            String var1 = "\n";

            try {
               var1 = var1 + "\nuserAgent=" + Netalyzr.this.safeUrlEncode(Netalyzr.this.userAgent, "US-ASCII");
               var1 = var1 + "\naccept=" + Netalyzr.this.safeUrlEncode(Netalyzr.this.accept, "US-ASCII");
               var1 = var1 + "\nacceptLanguage=" + Netalyzr.this.safeUrlEncode(Netalyzr.this.acceptLanguage, "US-ASCII");
               var1 = var1 + "\nacceptEncoding=" + Netalyzr.this.safeUrlEncode(Netalyzr.this.acceptEncoding, "US-ASCII");
               var1 = var1 + "\nacceptCharset=" + Netalyzr.this.safeUrlEncode(Netalyzr.this.acceptCharset, "US-ASCII");
               var1 = var1 + "\n";
            } catch (UnsupportedEncodingException var3) {
            }

            return var1;
         }
      });
      this.tests.add(new Netalyzr.Test("checkLatest") {
         public static final int TEST_ERROR_MALFORMED_URL = 64;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() throws IOException {
            Netalyzr.this.debug("My version is " + Netalyzr.this.shell.getBuildNumber());
            Netalyzr.this.debug("Getting connection for");

            try {
               Netalyzr.this.debug("http://" + Netalyzr.this.getHTTPServerName() + "/version/m=" + Netalyzr.this.mode.getName() + "/id=" + Netalyzr.this.agentID + "/ver=" + Netalyzr.this.shell.getBuildNumber());
               HttpURLConnection var1 = (HttpURLConnection)((HttpURLConnection)(new URL("http://" + Netalyzr.this.getHTTPServerName() + "/version/m=" + Netalyzr.this.mode.getName() + "/id=" + Netalyzr.this.agentID + "/ver=" + Netalyzr.this.shell.getBuildNumber())).openConnection());
               InputStream var2 = var1.getInputStream();
               ByteArrayOutputStream var3 = new ByteArrayOutputStream();
               int var4 = var1.getContentLength();
               if (var4 < 0) {
                  Netalyzr.this.debug("No content length received.");
                  return 66;
               } else {
                  byte[] var5 = new byte[4096];

                  while(var3.size() < var4) {
                     int var6 = var2.read(var5);
                     if (var6 < 0) {
                        Netalyzr.this.debug("Error while reading document.");
                        return 34;
                     }

                     var3.write(var5, 0, var6);
                  }

                  String var9 = var3.toString().trim();
                  int var7 = Netalyzr.this.parseInt(var9);
                  if (var7 > Netalyzr.this.shell.getBuildNumber()) {
                     Netalyzr.this.isLatestVersion = false;
                     Netalyzr.this.debug("Netalyzr version mismatch, we have " + Netalyzr.this.shell.getBuildNumber() + ", should be " + var7);
                     Netalyzr.this.debug("*** Aborting. ***");
                  } else {
                     Netalyzr.this.debug("Netalyzr version verified.");
                  }

                  return 4;
               }
            } catch (MalformedURLException var8) {
               Netalyzr.this.debug("Error!");
               return 66;
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkLocalAddr") {
         int num_conns;
         HashSet localAddrs;
         String localPorts;
         String globalPorts;
         String interfaceAddrs;
         String interfaceAddrsHostname;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.localAddrs = new HashSet();
            this.interfaceAddrs = "";
            this.interfaceAddrsHostname = "";
            this.localPorts = "";
            this.globalPorts = "";
            this.timeout = 30000L;
            this.num_conns = 10;
         }

         int runImpl() throws IOException {
            String var1 = Netalyzr.this.serverName;
            int var2 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("TCP_ECHO_PORT"));
            if (var2 < 0) {
               return 34;
            } else {
               int[] var3 = new int[]{var2, 22, 465, 585, 993, 995};

               int var6;
               for(int var4 = 0; var4 < var3.length; ++var4) {
                  Netalyzr.TCPTestArgs var5 = Netalyzr.this.new TCPTestArgs(0);
                  var5.timeoutMilliSecs = 6000;
                  var6 = Netalyzr.this.checkTCP(var1, var3[var4], var5);
                  if (var6 == 4) {
                     Netalyzr.this.debug("Connection to test server on port " + var3[var4] + " succeeded");
                     Netalyzr.this.debug("Using this port for echo tests");
                     var2 = var3[var4];
                     break;
                  }

                  Netalyzr.this.debug("Connection " + var4 + " failed returned result code " + var6);
               }

               boolean var16 = false;
               int var17 = 0;

               for(var6 = 0; var6 < this.num_conns; ++var6) {
                  Netalyzr.TCPTestArgs var7 = Netalyzr.this.new TCPTestArgs(32);

                  int var8;
                  try {
                     var8 = Netalyzr.this.checkTCP(var1, var2, var7);
                     if (var8 != 4) {
                        Netalyzr.this.debug("Connection " + var6 + " failed with result code " + var8);

                        try {
                           Thread.sleep(500L);
                        } catch (InterruptedException var13) {
                        }
                        continue;
                     }

                     ++var17;
                  } catch (ThreadDeath var15) {
                     if (var6 < 3) {
                        return 0;
                     }

                     this.num_conns = var6 + 1;
                  }

                  if (Netalyzr.this.localClientAddr.equals("0.0.0.0")) {
                     Netalyzr.this.localClientAddr = "" + var7.localAddr;
                  }

                  Netalyzr.this.debug("Local socket is " + var7.localAddr + ":" + var7.localPort);
                  this.localAddrs.add(var7.localAddr);
                  this.localPorts = this.localPorts + Integer.toString(var7.localPort);
                  if (var6 < this.num_conns - 1) {
                     this.localPorts = this.localPorts + ",";
                  }

                  Netalyzr.this.debug("Now getting global port");
                  var8 = var7.recvData.indexOf(":");
                  if (var8 < 0) {
                     Netalyzr.this.debug("Received data invalid: \"" + var7.recvData + "\"");
                  } else {
                     Netalyzr.this.debug("Global port is " + var7.recvData.substring(var8 + 1));

                     try {
                        int var9 = Integer.parseInt(var7.recvData.substring(var8 + 1).trim());
                        this.globalPorts = this.globalPorts + Integer.toString(var9);
                        if (var6 < this.num_conns - 1) {
                           this.globalPorts = this.globalPorts + ",";
                        }
                     } catch (NumberFormatException var12) {
                        Netalyzr.this.debug("Global port number failed to parse");
                     }

                     if (!var16) {
                        if (var7.recvData == null) {
                           Netalyzr.this.debug("No data read from echo server");
                        } else {
                           Netalyzr.this.globalClientAddr = var7.recvData.substring(0, var8);
                           Netalyzr.this.globalClientCheckedPort = var2;
                           Netalyzr.this.tracebackProxyPorts.add(new Integer(var2));
                           Netalyzr.this.debug("Global IP address is " + Netalyzr.this.globalClientAddr);
                           Netalyzr.this.debug("Fetched using port " + Netalyzr.this.globalClientCheckedPort);
                           var16 = true;
                        }
                     }
                  }
               }

               if (!var16) {
                  Netalyzr.this.debug("Failed to extract global IP address in " + var17 + " attempts");
                  return 66;
               } else {
                  Netalyzr.this.debug("Successfully connected " + var17 + " of " + this.num_conns + " times to " + var1 + ":" + var2);
                  Netalyzr.this.debug("Now attempting to walk the interface list");

                  try {
                     Enumeration var18 = NetworkInterface.getNetworkInterfaces();

                     while(var18.hasMoreElements()) {
                        NetworkInterface var19 = (NetworkInterface)var18.nextElement();
                        Netalyzr.this.debug("Display name: " + var19.getName());
                        this.interfaceAddrs = this.interfaceAddrs + Netalyzr.this.safeUrlEncode(var19.getName(), "UTF-8");
                        this.interfaceAddrsHostname = this.interfaceAddrsHostname + Netalyzr.this.safeUrlEncode(var19.getName(), "UTF-8");
                        Enumeration var20 = var19.getInetAddresses();

                        while(var20.hasMoreElements()) {
                           InetAddress var21 = (InetAddress)var20.nextElement();
                           String var10 = var21.getHostAddress();
                           String var11 = var21.getHostName();
                           this.interfaceAddrs = this.interfaceAddrs + '!' + var10;
                           this.interfaceAddrsHostname = this.interfaceAddrsHostname + '!' + var10 + '^' + var11;
                           Netalyzr.this.debug(" IP: " + var10);
                           Netalyzr.this.debug(" hostname: " + var11);
                        }

                        if (var18.hasMoreElements()) {
                           this.interfaceAddrs = this.interfaceAddrs + ",";
                           this.interfaceAddrsHostname = this.interfaceAddrsHostname + ",";
                        }
                     }
                  } catch (Exception var14) {
                     Netalyzr.this.debug("Caught exception " + var14);
                  }

                  return 4;
               }
            }
         }

         String getPostResults() {
            String var1 = "";
            Iterator var2 = this.localAddrs.iterator();

            while(var2.hasNext()) {
               var1 = var1 + var2.next();
               if (var2.hasNext()) {
                  var1 = var1 + ",";
               }
            }

            if (Netalyzr.this.globalClientAddr.equals("0.0.0.0")) {
               return "globalAddr=" + Netalyzr.this.globalHTTPAddr + "\nlocalAddr=" + var1 + "\ninterfaceAddrs=" + this.interfaceAddrs + "\ninterfaceAddrsHostname=" + this.interfaceAddrsHostname + "\nlocalPorts=" + this.localPorts + "\nglobalPorts=" + this.globalPorts + "\n";
            } else {
               return "globalAddr=" + Netalyzr.this.globalClientAddr + "\nlocalAddr=" + var1 + "\ninterfaceAddrs=" + this.interfaceAddrs + "\ninterfaceAddrsHostname=" + this.interfaceAddrsHostname + "\nlocalPorts=" + this.localPorts + "\nglobalPorts=" + this.globalPorts + "\n";
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkUDP") {
         Netalyzr.UDPTestArgs udpArgs;
         String largeUDPSend;
         String largeUDPRecv;
         int largeUDPRecvMTU;
         int largeUDPSendMTU;
         String largeUDPSend1471;
         String largeUDPRecv1471;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.udpArgs = Netalyzr.this.new UDPTestArgs();
            this.largeUDPSend = "False";
            this.largeUDPRecv = "False";
            this.largeUDPSend1471 = "False";
            this.largeUDPRecv1471 = "True";
         }

         int runImpl() throws IOException {
            String var1 = Netalyzr.this.serverName;
            int var2 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_ECHO_PORT"));
            int var3 = Netalyzr.this.checkUDP(var1, var2, this.udpArgs);
            if (var3 == 4) {
               Netalyzr.this.debug("Can perform raw UDP access");
               Netalyzr.this.canDoRawUDP = true;
            } else {
               Netalyzr.this.debug("Can not perform raw UDP access");
            }

            if (Netalyzr.this.canDoRawUDP) {
               String var4 = "000.000 1 0 ";
               int var5 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_BUFFER_PORT"));

               for(var4 = "000.000 1 0 "; var4.length() < 1471; var4 = var4 + ".") {
               }

               Netalyzr.this.debug("Testing the ability to send a 1471B UDP packet");
               Netalyzr.UDPTestArgs var6 = Netalyzr.this.new UDPTestArgs(1, 10, var4.getBytes());
               if (Netalyzr.this.checkUDP(var1, var5, var6) == 4) {
                  Netalyzr.this.debug("Can send a 1471B UDP packet");
                  this.largeUDPSend1471 = "True";
               } else {
                  Netalyzr.this.debug("Unable to send a 1471B UDP packet");
                  Netalyzr.this.debug("So trying once more");
                  var6 = Netalyzr.this.new UDPTestArgs(1, 10, var4.getBytes());
                  if (Netalyzr.this.checkUDP(var1, var5, var6) == 4) {
                     Netalyzr.this.debug("Able to go the second time");
                     this.largeUDPSend1471 = "Linux";
                  } else {
                     Netalyzr.this.debug("Full send MTU hole");
                  }
               }

               for(var4 = "000.000 1 0 "; var4.length() < 2000; var4 = var4 + ".") {
               }

               Netalyzr.this.debug("Testing the ability to send a large UDP packet (2000 bytes)");
               var6 = Netalyzr.this.new UDPTestArgs(1, 10, var4.getBytes());
               Netalyzr.this.checkUDP(var1, var5, var6);
               int var8;
               int var9;
               int var10;
               if (Netalyzr.this.checkUDP(var1, var5, var6) == 4) {
                  Netalyzr.this.debug("Can send UDP fragments successfully");
                  this.largeUDPSend = "True";
                  this.largeUDPSendMTU = 2000;
                  Netalyzr.this.canSendFragmentedUDP = true;
               } else {
                  this.idleMsg = Netalyzr.this.getLocalString("checkUDPMTU");
                  Netalyzr.this.shell.enableRedraw();
                  this.timeout = 30000L;
                  Netalyzr.this.debug("Can not successfully send UDP fragments");
                  Netalyzr.this.debug("Trying to discover maximum MTU");
                  var8 = 0;
                  var9 = 2000;
                  var10 = 1000;

                  while(true) {
                     if (var8 >= var9 - 1) {
                        Netalyzr.this.debug("Found maximum working value " + var8);
                        Netalyzr.this.debug("Failure at " + var9);
                        this.largeUDPSendMTU = var8;
                        break;
                     }

                     Netalyzr.this.debug("Works: " + var8);
                     Netalyzr.this.debug("Fails: " + var9);
                     Netalyzr.this.debug("At:    " + var10);

                     for(var4 = "000.000 1 0 "; var4.length() < var10; var4 = var4 + ".") {
                     }

                     var6 = Netalyzr.this.new UDPTestArgs(1, 5, var4.getBytes());
                     if (Netalyzr.this.checkUDP(var1, var5, var6) == 4) {
                        var8 = var10;
                        Netalyzr.this.debug("Able to get the packet");
                     } else {
                        Netalyzr.this.debug("Not able to get the reply");
                        var9 = var10;
                     }

                     var10 = (var9 - var8) / 2 + var8;
                  }
               }

               Netalyzr.this.debug("Testing the ability to receive a 1471B UDP");
               Netalyzr.this.debug("reply from our server");
               var4 = "000.000 0 1471";
               Netalyzr.UDPTestArgs var7 = Netalyzr.this.new UDPTestArgs(1, 10, var4.getBytes());
               if (Netalyzr.this.checkUDP(var1, var5, var7) == 4) {
                  Netalyzr.this.debug("Can receive a 1471B UDP packet");
                  this.largeUDPRecv1471 = "True";
               } else {
                  Netalyzr.this.debug("Unable to receive a 1471B UDP packet");
               }

               Netalyzr.this.debug("Testing the ability to receive a large UDP packet (2000 bytes)");
               var4 = "000.000 0 2000";
               var7 = Netalyzr.this.new UDPTestArgs(1, 5, var4.getBytes());
               if (Netalyzr.this.checkUDP(var1, var5, var7) == 4) {
                  Netalyzr.this.debug("Can receive UDP fragments successfully");
                  this.largeUDPRecv = "True";
                  this.largeUDPRecvMTU = 2000;
               } else {
                  this.idleMsg = Netalyzr.this.getLocalString("checkUDPFragMTU");
                  Netalyzr.this.shell.enableRedraw();
                  this.timeout = 30000L;
                  Netalyzr.this.debug("Can not successfully receive large UDP");
                  Netalyzr.this.debug("Trying to discover practical UDP MTU");
                  var8 = 0;
                  var9 = 1999;

                  for(var10 = 1000; var8 < var9 - 1; var10 = (var9 - var8) / 2 + var8) {
                     Netalyzr.this.debug("Works: " + var8);
                     Netalyzr.this.debug("Fails: " + var9);
                     Netalyzr.this.debug("At:    " + var10);
                     var4 = "000.000 0 " + var10;
                     var7 = Netalyzr.this.new UDPTestArgs(1, 10, var4.getBytes());
                     if (Netalyzr.this.checkUDP(var1, var5, var7) == 4) {
                        var8 = var10;
                        Netalyzr.this.debug("Able to get the packet");
                     } else {
                        Netalyzr.this.debug("Not able to get the reply");
                        var9 = var10;
                     }
                  }

                  Netalyzr.this.debug("Found maximum working value " + var8);
                  Netalyzr.this.debug("Failure at " + var9);
                  this.largeUDPRecvMTU = var8;
               }
            }

            return var3;
         }

         String getPostResults() {
            if (this.udpArgs.numRecv == 0) {
               return "";
            } else {
               String var1 = "";
               String var2 = "";

               for(int var3 = 0; var3 < this.udpArgs.numRecv; ++var3) {
                  var1 = var1 + this.udpArgs.localAddrs[var3];
                  var2 = var2 + Integer.toString(this.udpArgs.localPorts[var3]);
                  if (var3 < this.udpArgs.numRecv - 1) {
                     var1 = var1 + ",";
                     var2 = var2 + ",";
                  }
               }

               return "localUDPAddrs=" + var1 + "\nlocalUDPPorts=" + var2 + "\nlargeUDPSend=" + this.largeUDPSend + "\nlargeUDPRecv=" + this.largeUDPRecv + "\nlargeUDPRecvMTU=" + this.largeUDPRecvMTU + "\nlargeUDPSendMTU=" + this.largeUDPSendMTU + "\nlargeUDPRecv1471=" + this.largeUDPRecv1471 + "\nlargeUDPSend1471=" + this.largeUDPSend1471 + "\n";
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkUPnP") {
         String upnpSupport = "False";
         String upnpAttempted = "False";
         String upnpStatus = "bcnotex";

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 5000L;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.isNatted()) {
               this.ignoreResult = true;
               return 0;
            } else {
               String var1 = "upnp:rootdevice";
               var1 = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
               Netalyzr.this.debug("Attempting to create a multicast socket");
               String var2 = "M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nST: " + var1 + "\r\nMX:3\r\n\r\n";
               Netalyzr.this.debug("Broadcast message:");
               Netalyzr.this.debug(var2);
               this.upnpStatus = "bcerr";
               InetAddress var3 = InetAddress.getByName("239.255.255.250");
               MulticastSocket var4 = new MulticastSocket();
               var4.joinGroup(var3);
               var4.setSoTimeout(3000);
               DatagramPacket var5 = new DatagramPacket(var2.getBytes(), var2.length(), var3, 1900);

               for(int var6 = 0; var6 < 3; ++var6) {
                  var4.send(var5);
                  Netalyzr.this.debug("Sent query Message");
                  this.upnpAttempted = "True";
                  if (!this.upnpStatus.equals("bcrx")) {
                     this.upnpStatus = "bctx";
                  }

                  try {
                     for(int var7 = 0; var7 < 5; ++var7) {
                        UpnpIGD var8 = this.readDevice(var4);
                        if (Netalyzr.this.upnpIGDs.get(var8.addr) != null) {
                           Netalyzr.this.debug("Device already known, skipping.");
                        } else {
                           Netalyzr.this.upnpIGDs.put(var8.addr, var8);
                           this.upnpStatus = "bcrx";
                           if (var8.url != null && var8.url.startsWith("http://")) {
                              Netalyzr.this.debug("Fetching UPnP device description");
                              var8.status = "nosrv";
                              if (this.readUpnpDescription(var8)) {
                                 Netalyzr.this.debug("UPnP-determined NAT address: " + var8.addr);
                                 Netalyzr.this.foundNatAddrs.add(var8.addr);
                              }
                           }
                        }
                     }
                  } catch (SocketTimeoutException var9) {
                     Netalyzr.this.debug("Got timeout");
                  }
               }

               Netalyzr.this.debug("Leaving group");
               var4.leaveGroup(var3);
               var4.close();
               return 4;
            }
         }

         UpnpIGD readDevice(MulticastSocket var1) throws SocketTimeoutException, IOException {
            byte[] var2 = new byte[8096];
            DatagramPacket var3 = new DatagramPacket(var2, var2.length);
            Netalyzr.this.debug("Trying to receive multicast socket reply");
            var1.receive(var3);
            String var4 = new String(var2, 0, var3.getLength());
            Netalyzr.this.debug("Received reply of length " + var3.getLength() + " from IP '" + var3.getAddress() + "'");
            Netalyzr.this.debug(var4);
            UpnpIGD var5 = new UpnpIGD();
            var5.ssdp = var4;
            var5.addr = var3.getAddress().getHostAddress();
            String[] var6 = var4.split("\r\n");

            for(int var7 = 0; var7 < var6.length; ++var7) {
               String[] var8 = var6[var7].split(":", 2);
               if (var8[0].toLowerCase().equals("location") && var8.length > 1) {
                  Netalyzr.this.debug("Response contained UPnP location URL: " + var8[1]);
                  var5.url = var8[1].trim();
                  return var5;
               }
            }

            Netalyzr.this.debug("No UPnP location URL identified in response");
            return null;
         }

         boolean readUpnpDescription(UpnpIGD var1) throws IOException {
            Netalyzr.this.debug("First attempting to upload SSDP description");
            if (!var1.ssdp.equals("")) {
               Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=upnp_" + var1.id + "_ssdp", var1.ssdp);
            }

            Netalyzr.this.debug("SSDP description uploaded");
            String var2 = Netalyzr.this.getHttpData(var1.url);
            if (var2 == null) {
               return false;
            } else {
               var1.status = "datarx";
               Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=upnp_" + var1.id + "_descr", var2);
               Netalyzr.this.debug("Successfully posted UPnP content");
               this.upnpSupport = "True";
               UpnpDescription var3 = new UpnpDescription(Netalyzr.this.getNetalyzr(), var2, var1.url);
               var1.descr = var3;
               var3.parse();
               String[][] var4 = new String[][]{{"linkprops", "*", "WANCommonInterfaceConfig", "GetCommonLinkProperties"}, {"ip-conninfo", "*", "WANIPConnection", "GetConnectionTypeInfo"}, {"ip-status", "*", "WANIPConnection", "GetStatusInfo"}, {"ip-ipaddr", "*", "WANIPConnection", "GetExternalIPAddress"}, {"ppp-conninfo", "*", "WANPPPConnection", "GetConnectionTypeInfo"}, {"ppp-status", "*", "WANPPPConnection", "GetStatusInfo"}, {"ppp-ipaddr", "*", "WANPPPConnection", "GetExternalIPAddress"}};

               for(int var5 = 0; var5 < var4.length; ++var5) {
                  var3.call(var4[var5][0], var4[var5][1], var4[var5][2], var4[var5][3]);
               }

               return true;
            }
         }

         String getPostResults() {
            StringBuffer var1 = new StringBuffer();
            Iterator var2 = Netalyzr.this.upnpIGDs.entrySet().iterator();
            var1.append("\nupnpSupport=" + this.upnpSupport);
            var1.append("\nupnpAttempted=" + this.upnpAttempted);
            var1.append("\nupnpStatus=" + this.upnpStatus);

            while(var2.hasNext()) {
               Entry var3 = (Entry)var2.next();
               UpnpIGD var4 = (UpnpIGD)var3.getValue();
               var1.append("\nupnpDev" + var4.id + "Addr=" + var4.addr);
               var1.append("\nupnpDev" + var4.id + "Url=" + var4.url);
               var1.append("\nupnpDev" + var4.id + "Status=" + var4.status + "\n");
            }

            return var1.toString();
         }
      });
      this.tests.add(new Netalyzr.Test("checkClock") {
         Netalyzr.UDPTestArgs udpArgs;
         String serverTS;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.udpArgs = Netalyzr.this.new UDPTestArgs();
            this.serverTS = "";
         }

         int runImpl() throws IOException {
            String var1 = Netalyzr.this.serverName;
            int var2 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_ECHO_PORT"));
            if (!Netalyzr.this.canDoRawUDP) {
               this.ignoreResult = true;
               return 1;
            } else {
               byte[] var3 = Netalyzr.this.getUDPData(var1, var2, this.udpArgs);
               if (var3 != null) {
                  Netalyzr.this.debug("Able to get clock drift data");
                  this.serverTS = (new String(var3)).split(" ")[0];
                  return 4;
               } else {
                  Netalyzr.this.debug("Can Not Perform Raw UDP Access");
                  this.ignoreResult = true;
                  return 1;
               }
            }
         }

         String getPostResults() {
            return "\nsendPacketTS=" + this.udpArgs.sendPacketTS + "\nrecvPacketTS=" + this.udpArgs.recvPacketTS + "\nserverTS=" + this.serverTS + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkDrop") {
         Netalyzr.NetProbeStats stats;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 100L;
         }

         int runImpl() throws IOException {
            int var1 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_BUFFER_PORT"));
            if (!Netalyzr.this.canDoRawUDP) {
               this.ignoreResult = true;
               return 1;
            } else {
               Netalyzr.this.startedPingTest = false;
               this.stats = Netalyzr.this.new NetProbeStats(Netalyzr.this.serverName, Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_BUFFER_PORT")), 200);
               this.stats.run();
               if (this.stats.status != 4) {
                  this.ignoreResult = true;
               }

               return this.stats.status;
            }
         }

         String getPostResults() {
            return this.stats != null && this.stats.status == 4 ? "backgroundRTT=" + this.stats.avgRTT + "\nbackgroundSendCount=" + this.stats.sendCount + "\nbackgroundRecvCount=" + this.stats.recvCount + "\nbackgroundServerRecvCount=" + this.stats.serverRecvCount + "\nbackgroundReorder=" + this.stats.reorderCount + "\nbackgroundDup=" + this.stats.dupCount + "\nbackgroundLossBurst=" + this.stats.lossBurstCount + "\nbackgroundLostBurstLength=" + this.stats.lossBurstLength + "\n" : "";
         }
      });
      this.tests.add(new Netalyzr.Test("checkURL") {
         public static final int TEST_ERROR_MALFORMED_URL = 64;
         String proxyHint;
         ArrayList addlHdrs;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.proxyHint = null;
            this.addlHdrs = new ArrayList();
         }

         int runImpl() throws IOException {
            String var1 = null;
            int var2 = -1;

            try {
               HttpURLConnection var3 = (HttpURLConnection)(new URL("http://" + Netalyzr.this.getHTTPServerName() + "/proxy/id=" + Netalyzr.this.agentID + "/mode=proxy")).openConnection();
               var3.setInstanceFollowRedirects(true);
               Netalyzr.this.debug("Response code " + var3.getResponseCode());
               Map var4 = var3.getHeaderFields();
               if (var4 != null) {
                  Iterator var5 = var4.entrySet().iterator();

                  label89:
                  while(true) {
                     Entry var6;
                     String var7;
                     do {
                        if (!var5.hasNext()) {
                           break label89;
                        }

                        var6 = (Entry)var5.next();
                        var7 = (String)var6.getKey();
                     } while(var7 == null);

                     boolean var8 = true;

                     for(int var9 = 0; var9 < Netalyzr.expectedResponseHeaders.length; ++var9) {
                        if (var7.toLowerCase().startsWith(Netalyzr.expectedResponseHeaders[var9].toLowerCase())) {
                           var8 = false;
                           break;
                        }
                     }

                     if (var8) {
                        this.addlHdrs.add(var6.getKey() + ": " + var6.getValue());
                     }
                  }
               }

               Netalyzr.this.globalHTTPAddr = var3.getHeaderField("ICSI-Client-Addr");
               Netalyzr.this.debug("Global client addr via HTTP is " + Netalyzr.this.globalHTTPAddr);
               String var12 = var3.getHeaderField("Via");
               String[] var15;
               if (var12 != null) {
                  String[] var13 = var12.split(" +");
                  if (var13.length >= 2) {
                     var15 = var13[1].split(":");
                     if (var15.length == 1) {
                        var1 = var13[1];
                        var2 = 80;
                     } else {
                        var1 = var15[0];
                        var2 = Netalyzr.this.parseInt(var15[1]);
                     }

                     this.proxyHint = "via";
                  }
               }

               String var14;
               if (var1 == null || var2 < 0) {
                  var14 = var3.getHeaderField("X-Cache-Lookup");
                  if (var14 != null) {
                     var15 = var14.split(" +");
                     String[] var17 = var15[var15.length - 1].split(":");
                     if (var17.length == 1) {
                        var1 = var15[1];
                        var2 = 80;
                     } else {
                        var1 = var17[0];
                        var2 = Netalyzr.this.parseInt(var17[1]);
                     }

                     this.proxyHint = "xcl";
                  }
               }

               if (var1 != null && var2 >= 0) {
                  Netalyzr.this.debug("Suspecting proxy at " + var1 + ":" + var2 + ", verifying.");
                  var14 = "GET http://" + Netalyzr.this.getHTTPServerName() + "/conn/id=" + Netalyzr.this.agentID + " HTTP/1.1\r\nHost: " + Netalyzr.this.serverName + ":" + Netalyzr.this.serverPort + "\r\nUser-AgEnt: " + Netalyzr.this.userAgent + "\r\nAccept: " + Netalyzr.this.accept + "\r\nAccept-Language: " + Netalyzr.this.acceptLanguage + "\r\nAccept-Encoding: " + Netalyzr.this.acceptEncoding + "\r\nAccept-Charset: " + Netalyzr.this.acceptCharset + "\r\nConnEction: close\r\n\r\n";
                  Netalyzr.HttpResponse var16 = Netalyzr.this.new HttpResponse();

                  try {
                     if (Netalyzr.this.checkRawHTTP(var1, var2, var14, var16) == 4) {
                        if (var16.getHeader("ICSI-Client-Addr") != null) {
                           Netalyzr.this.debug("Proxy confirmed via ICSI-Client-Addr header.");
                           Netalyzr.this.proxyHost = var1;
                           Netalyzr.this.proxyPort = var2;
                        }

                        if (Netalyzr.this.proxyHost == null) {
                           byte[] var18 = var16.getEntity();
                           if (var18 != null) {
                              String var19 = new String(var18);
                              if (var19.indexOf(Netalyzr.this.agentID) >= 0) {
                                 Netalyzr.this.debug("Proxy confirmed via ID string in payload.");
                                 Netalyzr.this.proxyHost = var1;
                                 Netalyzr.this.proxyPort = var2;
                              }
                           }
                        }
                     }
                  } catch (IOException var10) {
                     Netalyzr.this.debug("Proxy host connection failed");
                  }
               }

               return 4;
            } catch (MalformedURLException var11) {
               return 66;
            }
         }

         String getPostResults() {
            String var1 = "";
            if (Netalyzr.this.proxyHost != null && Netalyzr.this.proxyPort > 0) {
               var1 = var1 + "brProxyHost=" + Netalyzr.this.proxyHost + "\nbrProxyPort=" + Netalyzr.this.proxyPort + "\nbrProxyHint=" + this.proxyHint + "\n";
            }

            if (this.addlHdrs.size() > 0) {
               var1 = var1 + "hlAddlHdrs=";

               try {
                  for(int var2 = 0; var2 < this.addlHdrs.size(); ++var2) {
                     var1 = var1 + Netalyzr.this.safeUrlEncode((String)this.addlHdrs.get(var2), "US-ASCII");
                     if (var2 < this.addlHdrs.size() - 1) {
                        var1 = var1 + ",";
                     }
                  }
               } catch (UnsupportedEncodingException var3) {
               }

               var1 = var1 + "\n";
            }

            return var1;
         }
      });
      this.tests.add(new Netalyzr.Test("checkLowHTTP") {
         public static final int TEST_INVALID_CONTENT = 64;
         int contentLength;
         ArrayList addlHdrs;
         ArrayList changedHdrs;
         ArrayList removedHdrs;
         ArrayList addlBrowserHdrs;
         ArrayList changedBrowserHdrs;
         ArrayList removedBrowserHdrs;
         boolean changedContent;
         boolean reorderedHdrs;
         String cookie;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.addlHdrs = new ArrayList();
            this.changedHdrs = new ArrayList();
            this.removedHdrs = new ArrayList();
            this.addlBrowserHdrs = new ArrayList();
            this.changedBrowserHdrs = new ArrayList();
            this.removedBrowserHdrs = new ArrayList();
            this.changedContent = false;
            this.contentLength = -1;
            this.reorderedHdrs = false;
            Netalyzr.this.canDoRawHTTP = false;
         }

         int runImpl() throws IOException {
            String var1 = "GET http://" + Netalyzr.this.getHTTPServerName();
            var1 = var1 + "/proxy/id=" + Netalyzr.this.agentID + "/mode=direct HTTP/1.1";
            String[] var2 = new String[]{"HoSt: " + Netalyzr.this.serverName + ":" + Netalyzr.this.serverPort, "User-AgEnt: " + Netalyzr.this.userAgent, "AcCept: " + Netalyzr.this.accept, "AccEpt-Language: " + Netalyzr.this.acceptLanguage, "AccEPt-Encoding: " + Netalyzr.this.acceptEncoding, "AccEPT-Charset: " + Netalyzr.this.acceptCharset, "CooKIE: netAlyzer=FoO", "ReferEr: http://www.netalyzEr.icsi.berkeley.EDu/bogus.html", "IncLuDeAboGuShTTPHeAder: yes We CaN", "ConnEction: keep-alive"};

            for(int var3 = 0; var3 < var2.length; ++var3) {
               var1 = var1 + "\r\n" + var2[var3];
            }

            var1 = var1 + "\r\n\r\n";
            Netalyzr.HttpResponse var17 = Netalyzr.this.new HttpResponse();

            int var4;
            try {
               var4 = Netalyzr.this.checkRawHTTP(Netalyzr.this.serverName, Netalyzr.this.serverPort, var1, var17);
            } catch (IOException var16) {
               Netalyzr.this.debug("Raw HTTP connection is unavailable");
               return 18;
            }

            if (var4 != 4) {
               return var4;
            } else {
               Netalyzr.this.canDoRawHTTP = true;
               List var5 = var17.getHeaderList();
               Map var6 = var17.getHeaderFields();

               int var7;
               for(var7 = 0; var7 < var5.size(); ++var7) {
                  Netalyzr.this.debug("Header " + var7 + " is " + var5.get(var7));
               }

               this.cookie = var17.getHeader("set-cookie");

               for(var7 = 0; var7 < Netalyzr.expectedResponseHeaders.length; ++var7) {
                  if (var6.containsKey(Netalyzr.expectedResponseHeaders[var7].toLowerCase())) {
                     if (var7 < var5.size() && !Netalyzr.expectedResponseHeaders[var7].toLowerCase().startsWith(((String)var5.get(var7)).toLowerCase())) {
                        Netalyzr.this.debug("Header reordered: " + Netalyzr.expectedResponseHeaders[var7]);
                        Netalyzr.this.debug("Found instead: " + var5.get(var7));
                        this.reorderedHdrs = true;
                     }
                  } else {
                     this.removedHdrs.add(Netalyzr.expectedResponseHeaders[var7]);
                  }
               }

               String var18 = "";

               String var9;
               for(Iterator var8 = var5.iterator(); var8.hasNext(); var18 = var18 + var9 + ": " + var6.get(var9.toLowerCase()) + "\n") {
                  var9 = (String)var8.next();
                  boolean var10 = true;
                  boolean var11 = true;

                  for(int var12 = 0; var12 < Netalyzr.expectedResponseHeaders.length; ++var12) {
                     if (var9.startsWith(Netalyzr.expectedResponseHeaders[var12])) {
                        var11 = false;
                     }

                     if (var9.toLowerCase().startsWith(Netalyzr.expectedResponseHeaders[var12].toLowerCase())) {
                        var10 = false;
                        break;
                     }
                  }

                  if (var10) {
                     Netalyzr.this.debug("Unsolicited header found: " + var9);
                     this.addlHdrs.add(var9 + ": " + var6.get(var9.toLowerCase()));
                  } else if (var11) {
                     Netalyzr.this.debug("Changed header found: " + var9);
                     this.changedHdrs.add(var9 + ": " + var6.get(var9.toLowerCase()));
                  }
               }

               Netalyzr.this.globalRawHTTPAddr = var17.getHeader("ICSI-Client-Addr");
               this.contentLength = var17.getContentLength();
               byte[] var19 = var17.getEntity();
               if (var19 != null) {
                  String var20 = new String(var19);
                  String[] var21 = var20.split("\n");
                  String var22 = "<HTML><HEAD><TITLE>ProxyResults</TITLE></HEAD><BODY>";
                  if (!var21[0].equals(var22)) {
                     Netalyzr.this.debug("Got " + var21[0]);
                     Netalyzr.this.debug("But was expecting " + var22);
                     this.changedContent = true;
                  }

                  int var13;
                  for(var13 = 0; var13 < var2.length; ++var13) {
                     if (var21.length < 3 + 2 * var13) {
                        this.changedContent = true;
                        break;
                     }

                     if (!var21[1 + 2 * var13].equals("<P>")) {
                        this.changedContent = true;
                        Netalyzr.this.debug("Unexpectedly got :" + var21[1 + 2 * var13]);
                        Netalyzr.this.debug("But was expecting: <P>");
                     }

                     String[] var14 = var21[2 + 2 * var13].split("Header: ");
                     if (var14.length != 2) {
                        this.changedContent = true;
                        Netalyzr.this.debug("Unexpectedly Got :" + var21[2 + 2 * var13]);
                        Netalyzr.this.debug("line_data.length is :" + var14.length);
                     } else if (!var14[1].equals(var2[var13])) {
                        this.changedContent = true;
                        Netalyzr.this.debug("Unexpectedly Got :" + var21[2 + 2 * var13]);

                        for(int var15 = 0; var15 < var14.length; ++var15) {
                           Netalyzr.this.debug("Data[" + var15 + "] = \"" + var14[var15] + "\"");
                           Netalyzr.this.debug("Len is " + var14[var15].length());
                        }

                        Netalyzr.this.debug("expectd = \"" + var2[var13] + "\"");
                        Netalyzr.this.debug("Len is " + var2[var13].length());
                     }
                  }

                  for(var13 = 0; var13 < var21.length; ++var13) {
                     Netalyzr.this.debug("Line " + var13 + ":" + var21[var13]);
                  }
               }

               Netalyzr.this.debug("Attempting to post all HTTP content to the server");
               Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=raw_http_content", var17.getRawContent(), "application/octet-stream");
               Netalyzr.this.debug("Successfully posted content");
               return 4;
            }
         }

         String getPostResults() {
            String var1 = "";
            if (!Netalyzr.this.canDoRawHTTP) {
               return "";
            } else {
               if (Netalyzr.this.globalRawHTTPAddr != null && !Netalyzr.this.globalRawHTTPAddr.equals("0.0.0.0")) {
                  var1 = var1 + "globalRawHTTPAddr=" + Netalyzr.this.globalRawHTTPAddr + "\n";
               }

               var1 = var1 + "rawContentLength=" + this.contentLength + "\n";

               try {
                  if (this.cookie != null) {
                     var1 = var1 + "manCookie=" + Netalyzr.this.safeUrlEncode(this.cookie, "US-ASCII") + '\n';
                  } else {
                     var1 = var1 + "manCookie=NONE\n";
                  }
               } catch (UnsupportedEncodingException var3) {
               }

               if (this.changedContent) {
                  var1 = var1 + "manChangedContent=True\n";
               }

               int var2;
               if (this.changedHdrs.size() > 0) {
                  var1 = var1 + "manChangedHdrs=";

                  for(var2 = 0; var2 < this.changedHdrs.size(); ++var2) {
                     var1 = var1 + this.changedHdrs.get(var2);
                     if (var2 < this.changedHdrs.size() - 1) {
                        var1 = var1 + ",";
                     }
                  }

                  var1 = var1 + '\n';
               }

               if (this.removedHdrs.size() > 0) {
                  var1 = var1 + "manRemovedHdrs=";

                  for(var2 = 0; var2 < this.removedHdrs.size(); ++var2) {
                     var1 = var1 + this.removedHdrs.get(var2);
                     if (var2 < this.removedHdrs.size() - 1) {
                        var1 = var1 + ",";
                     }
                  }

                  var1 = var1 + '\n';
               }

               if (this.reorderedHdrs) {
                  var1 = var1 + "manReorderedHdrs=True\n";
               }

               if (this.addlHdrs.size() > 0) {
                  var1 = var1 + "manAddlHdrs=";

                  try {
                     for(var2 = 0; var2 < this.addlHdrs.size(); ++var2) {
                        var1 = var1 + Netalyzr.this.safeUrlEncode((String)this.addlHdrs.get(var2), "US-ASCII");
                        if (var2 < this.addlHdrs.size() - 1) {
                           var1 = var1 + ",";
                        }
                     }
                  } catch (UnsupportedEncodingException var4) {
                  }

                  var1 = var1 + "\n";
               }

               return var1;
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkLowProxyBug") {
         public static final int TEST_INVALID_CONTENT = 64;
         boolean badContent;
         String cookie;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.badContent = false;
         }

         void testQuery(String var1, String[] var2, String var3) throws IOException {
            Netalyzr.this.debug("Fetching query :" + var1);

            for(int var4 = 0; var4 < var2.length; ++var4) {
               var1 = var1 + "\r\n" + var2[var4];
               Netalyzr.this.debug("header: " + var2[var4]);
            }

            var1 = var1 + "\r\n\r\n";
            Netalyzr.HttpResponse var13 = Netalyzr.this.new HttpResponse();
            int var5 = Netalyzr.this.checkRawHTTP(Netalyzr.this.serverName, Netalyzr.this.serverPort, var1, var13);
            if (var5 != 4) {
               Netalyzr.this.debug("Proxy test had content rejected");
            } else {
               Netalyzr.this.debug("Raw content:");
               Netalyzr.this.debug(new String(var13.getRawContent()));
               int var6 = var13.getContentLength();
               byte[] var7 = var13.getEntity();
               String var8 = var13.getHeader("location");
               Netalyzr.this.debug("Got result code " + var13.getResponseCode());
               if (var8 != null && var8.indexOf("google") != -1 && var13.getResponseCode() == 302) {
                  Netalyzr.this.debug("Got a 302 redirect to a different google page");
                  this.badContent = true;
               }

               if (var7 != null) {
                  String var9 = new String(var7);
                  String[] var10 = var9.split("\n");
                  String var11 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">";
                  if (var10[0].equals(var11)) {
                     Netalyzr.this.debug("Got expected response of " + var10[0]);
                  } else {
                     for(int var12 = 0; var12 < var10.length; ++var12) {
                        if (var10[var12].contains("<title>Google</title>")) {
                           this.badContent = true;
                        }
                     }

                     Netalyzr.this.debug("Unexpected response of " + var10[0]);
                  }
               }

               if (this.badContent) {
                  Netalyzr.this.debug("Content was bad.  Attempting to post bad content to the server");
                  Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=proxy_bug_" + var3, new String(var13.getRawContent()));
                  Netalyzr.this.debug("Successfully posted changed content");
               }

            }
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoRawHTTP) {
               this.ignoreResult = true;
               return 0;
            } else {
               String var1 = "GET / HTTP/1.1";
               String[] var2 = new String[]{"Host: www.google.com", "User-Agent: " + Netalyzr.this.userAgent, "Accept: " + Netalyzr.this.accept, "Accept-Language: " + Netalyzr.this.acceptLanguage, "Accept-Encoding: " + Netalyzr.this.acceptEncoding, "AccepT-Charset: " + Netalyzr.this.acceptCharset, "Connection: keep-alive"};
               this.testQuery("GET / HTTP/1.1", var2, "_proxy_bug_1");
               this.testQuery("GET http://www.google.com/ HTTP/1.1", var2, "_proxy_bug_2");
               return 4;
            }
         }

         String getPostResults() {
            String var1 = "";
            if (this.badContent) {
               var1 = var1 + "\nmanBadContent=True\n";
            }

            return var1;
         }
      });
      this.tests.add(new Netalyzr.Test("checkMalformedHTTP") {
         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoRawHTTP) {
               this.ignoreResult = true;
               return 0;
            } else {
               String var1 = "ICSI /icsi/id=" + Netalyzr.this.agentID + " HTTP/1.1\r\n\r\n";
               Netalyzr.HttpResponse var2 = Netalyzr.this.new HttpResponse();
               boolean var3 = true;
               int var4;
               if (Netalyzr.this.proxyHost != null && Netalyzr.this.proxyPort >= 0) {
                  Netalyzr.this.debug("Routing via " + Netalyzr.this.proxyHost + ":" + Netalyzr.this.proxyPort);
                  var4 = Netalyzr.this.checkRawHTTP(Netalyzr.this.proxyHost, Netalyzr.this.proxyPort, var1, var2);
               } else {
                  Netalyzr.this.debug("Routing directly.");
                  var4 = Netalyzr.this.checkRawHTTP(Netalyzr.this.serverName, Netalyzr.this.serverPort, var1, var2);
               }

               if (var4 != 4) {
                  Netalyzr.this.debug("HTTP connection failed");
                  return var4;
               } else if (var2.getHeader("ICSI-Client-Addr") == null) {
                  Netalyzr.this.debug("ICSI-Client-Addr header not found");
                  return 66;
               } else {
                  return 4;
               }
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkRestrictedDNS") {
         public static final int TEST_WRONG_NAME_FOUND = 64;
         String remoteIP = "";

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() throws IOException {
            String var1 = "www." + Netalyzr.this.custDnsName;
            Netalyzr.this.debug("Attempting to look up " + var1);

            try {
               Netalyzr.this.trueIP = InetAddress.getByName(var1);
               Netalyzr.this.debug(var1 + " looked up successfully.");
               this.remoteIP = Netalyzr.this.trueIP.getHostAddress();
               Netalyzr.this.debug("Remote IP: " + this.remoteIP);
               Netalyzr.this.debug("CustDnsAddr: " + Netalyzr.this.custDnsAddr);
               if (!this.remoteIP.equals(Netalyzr.this.custDnsAddr)) {
                  Netalyzr.this.debug("Problem!  The server address is not what it should be!");
                  return 66;
               } else {
                  Netalyzr.this.canDoRestrictedLookup = true;
                  return 4;
               }
            } catch (UnknownHostException var3) {
               Netalyzr.this.debug(var1 + " lookup failed.");
               return 10;
            } catch (SecurityException var4) {
               Netalyzr.this.debug(var1 + " Security check failed.");
               return 1;
            }
         }

         String getPostResults() {
            return "\nrestrictedDNSIP=" + this.remoteIP + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkUnrestrictedDNS") {
         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() throws IOException {
            String var1 = "return-false.abcd" + Netalyzr.this.custDnsAltName;

            try {
               InetAddress.getByName(var1);
               Netalyzr.this.debug(var1 + " looked up successfully.");
               Netalyzr.this.canDoUnrestrictedLookup = true;
               return 4;
            } catch (UnknownHostException var3) {
               Netalyzr.this.debug(var1 + " lookup failed.");
               return 0;
            } catch (SecurityException var4) {
               Netalyzr.this.debug(var1 + " Security check failed.");
               return 1;
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkIPv6DNS") {
         InetAddress v6only;
         InetAddress[] v6group;
         InetAddress v4v6only;
         InetAddress[] v4v6group;
         InetAddress[] google;
         InetAddress[] googlev6;
         InetAddress[] comcast6;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 20000L;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               return 0;
            } else {
               this.v6group = new InetAddress[0];
               this.v4v6group = new InetAddress[0];
               this.google = new InetAddress[0];
               this.googlev6 = new InetAddress[0];
               this.comcast6 = new InetAddress[0];

               try {
                  this.v6only = InetAddress.getByName("ipv6-only.a" + Netalyzr.this.custDnsName);
               } catch (Exception var11) {
                  Netalyzr.this.debug("Got exception " + var11);
               }

               try {
                  this.v6group = InetAddress.getAllByName("ipv6-only.b" + Netalyzr.this.custDnsName);
                  InetAddress var1 = InetAddress.getByName("cafe:babe:66::1");
                  if (this.v6group != null && this.v6group.length == 1) {
                     byte[] var2 = this.v6group[0].getAddress();
                     byte[] var3 = var1.getAddress();
                     boolean var4 = true;

                     for(int var5 = 0; var5 < 16; ++var5) {
                        var4 = var4 && var3[var5] == var2[var5];
                     }

                     Netalyzr.this.ipv6DNSOK = var4;
                     Netalyzr.this.debug("ref: " + var1.getHostAddress());
                     Netalyzr.this.debug("DNS: " + this.v6group[0].getHostAddress());
                  }
               } catch (Exception var12) {
                  Netalyzr.this.debug("Got exception " + var12);
               }

               Netalyzr.this.debug("Can do V6 DNS OK: " + Netalyzr.this.ipv6DNSOK);

               try {
                  this.v4v6only = InetAddress.getByName("ipv4-ipv6.c" + Netalyzr.this.custDnsName);
               } catch (Exception var10) {
                  Netalyzr.this.debug("Got exception " + var10);
               }

               try {
                  this.v4v6group = InetAddress.getAllByName("ipv4-ipv6.d" + Netalyzr.this.custDnsName);
               } catch (Exception var9) {
                  Netalyzr.this.debug("Got exception " + var9);
               }

               try {
                  this.google = InetAddress.getAllByName("www.google.com");
               } catch (Exception var8) {
                  Netalyzr.this.debug("Got exception " + var8);
               }

               try {
                  this.googlev6 = InetAddress.getAllByName("ipv6.google.com");
               } catch (Exception var7) {
                  Netalyzr.this.debug("Got exception " + var7);
               }

               try {
                  this.comcast6 = InetAddress.getAllByName("www.comcast6.net");
               } catch (Exception var6) {
                  Netalyzr.this.debug("Got exception " + var6);
               }

               if (this.v6only != null) {
                  Netalyzr.this.debug("V6 only:" + this.v6only.getHostAddress());
               }

               int var13;
               for(var13 = 0; var13 < this.v6group.length; ++var13) {
                  Netalyzr.this.debug("V6 group:" + this.v6group[var13].getHostAddress());
               }

               if (this.v4v6only != null) {
                  Netalyzr.this.debug("V4 only:" + this.v4v6only.getHostAddress());
               }

               for(var13 = 0; var13 < this.v4v6group.length; ++var13) {
                  Netalyzr.this.debug("V4 group:" + this.v4v6group[var13].getHostAddress());
               }

               for(var13 = 0; var13 < this.comcast6.length; ++var13) {
                  Netalyzr.this.debug("comcast6.net group:" + this.comcast6[var13].getHostAddress());
               }

               for(var13 = 0; var13 < this.google.length; ++var13) {
                  Netalyzr.this.debug("Google group:" + this.google[var13].getHostAddress());
               }

               for(var13 = 0; var13 < this.googlev6.length; ++var13) {
                  Netalyzr.this.debug("IPv6.google group:" + this.googlev6[var13].getHostAddress());
               }

               return 4;
            }
         }

         String getPostResults() {
            String var1 = "\n";
            var1 = var1 + "DNSLookupV6Only=";

            int var2;
            for(var2 = 0; var2 < this.v6group.length; ++var2) {
               var1 = var1 + this.v6group[var2].getHostAddress();
               if (var2 < this.v6group.length - 1) {
                  var1 = var1 + ",";
               }
            }

            var1 = var1 + "\nDNSLookupV6Single=" + this.v6only;
            var1 = var1 + "\nDNSLookupV4V6Single=" + this.v4v6only;
            var1 = var1 + "\nDNSLookupV4V6=";

            for(var2 = 0; var2 < this.v4v6group.length; ++var2) {
               var1 = var1 + this.v4v6group[var2].getHostAddress();
               if (var2 < this.v4v6group.length - 1) {
                  var1 = var1 + ",";
               }
            }

            var1 = var1 + "\nDNSLookupGoogleV6=";

            for(var2 = 0; var2 < this.googlev6.length; ++var2) {
               var1 = var1 + this.googlev6[var2].getHostAddress();
               if (var2 < this.googlev6.length - 1) {
                  var1 = var1 + ",";
               }
            }

            var1 = var1 + "\nDNSLookupGoogle=";

            for(var2 = 0; var2 < this.google.length; ++var2) {
               var1 = var1 + this.google[var2].getHostAddress();
               if (var2 < this.google.length - 1) {
                  var1 = var1 + ",";
               }
            }

            var1 = var1 + "\nDNSLookupComcast6=";

            for(var2 = 0; var2 < this.comcast6.length; ++var2) {
               var1 = var1 + this.comcast6[var2].getHostAddress();
               if (var2 < this.comcast6.length - 1) {
                  var1 = var1 + ",";
               }
            }

            return var1;
         }
      });
      this.tests.add(new Netalyzr.Test("checkV6") {
         String v6data;
         String v4data;
         long[] v6latency;
         long[] v4latency;
         boolean v6works;
         boolean v4works;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.v6data = "";
            this.v4data = "";
            this.v6latency = new long[10];
            this.v4latency = new long[10];
            this.v6works = false;
            this.v4works = false;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.ipv6DNSOK) {
               Netalyzr.this.debug("No IPv6 DNS, so not executing test");
               return 2;
            } else {
               new StringBuffer();
               Netalyzr.this.v6server = InetAddress.getByName("ipv6-node." + Netalyzr.this.custDnsName);
               InetAddress var2 = InetAddress.getByName("ipv4-node." + Netalyzr.this.custDnsName);
               Netalyzr.TCPTestArgs var3 = Netalyzr.this.new TCPTestArgs(1200);
               Netalyzr.this.debug("Checking TCP for tcpServer: " + Netalyzr.this.v6server);
               int var4 = Netalyzr.this.checkTCP((String)Netalyzr.this.v6server.getHostAddress(), 1947, var3, false);
               if (var3.recvData != null) {
                  this.v6data = Netalyzr.this.safeUrlEncode(var3.recvData, "UTF-8");
                  this.v6works = true;
               }

               Netalyzr.this.debug("Local address is " + var3.localAddr);
               Netalyzr.this.debug("Remote adddress is " + var3.remoteAddr);
               Netalyzr.this.debug("Data received: " + this.v6data);
               var3 = Netalyzr.this.new TCPTestArgs(1200);
               Netalyzr.this.debug("Now checking for V4 server: " + var2);
               var4 = Netalyzr.this.checkTCP((String)var2.getHostAddress(), 1947, var3, false);
               if (var3.recvData != null) {
                  this.v4data = Netalyzr.this.safeUrlEncode(var3.recvData, "UTF-8");
                  this.v4works = true;
               }

               Netalyzr.this.debug("Local address is " + var3.localAddr);
               Netalyzr.this.debug("Remote adddress is " + var3.remoteAddr);
               Netalyzr.this.debug("Data received: " + this.v4data);
               if (this.v6works && this.v4works) {
                  Netalyzr.this.canDoV6 = true;

                  for(int var5 = 0; var5 < 10; ++var5) {
                     var3 = Netalyzr.this.new TCPTestArgs(1200);
                     long var6 = (new Date()).getTime();
                     var4 = Netalyzr.this.checkTCP((String)var2.getHostAddress(), 1947, var3, false);
                     this.v4latency[var5] = (new Date()).getTime() - var6;
                     var3 = Netalyzr.this.new TCPTestArgs(1200);
                     var6 = (new Date()).getTime();
                     var4 = Netalyzr.this.checkTCP((String)Netalyzr.this.v6server.getHostAddress(), 1947, var3, false);
                     this.v6latency[var5] = (new Date()).getTime() - var6;
                  }
               }

               return Netalyzr.this.canDoV6 ? 4 : 2;
            }
         }

         String getPostResults() {
            String var1 = "";
            var1 = var1 + "\nv6Response=" + this.v6data;
            var1 = var1 + "\nv4Response=" + this.v4data;
            if (this.v6works && this.v4works) {
               var1 = var1 + "\nv6latency=";

               int var2;
               for(var2 = 0; var2 < 9; ++var2) {
                  var1 = var1 + this.v6latency[var2] + ",";
               }

               var1 = var1 + this.v6latency[9];
               var1 = var1 + "\nv4latency=";

               for(var2 = 0; var2 < 9; ++var2) {
                  var1 = var1 + this.v4latency[var2] + ",";
               }

               var1 = var1 + this.v4latency[9];
            }

            return var1 + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkHiddenProxies") {
         StringBuffer proxiedPorts = new StringBuffer();
         StringBuffer unproxiedPorts = new StringBuffer();
         InetAddress nonResponsiveIP;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               return 0;
            } else {
               String var1 = "nonresponsive." + Netalyzr.this.custDnsName;
               this.nonResponsiveIP = InetAddress.getByName(var1);
               Netalyzr.this.debug("Nonresponsive name/IP address is " + var1 + "/" + this.nonResponsiveIP);

               for(int var2 = 0; var2 < Netalyzr.proxyPortsToTest.length; ++var2) {
                  Netalyzr.this.debug("Attempting to check port " + Netalyzr.proxyPortsToTest[var2]);

                  try {
                     InetSocketAddress var3 = new InetSocketAddress(this.nonResponsiveIP, Netalyzr.proxyPortsToTest[var2]);
                     Socket var4 = new Socket();
                     long var5 = (new Date()).getTime();
                     var4.connect(var3, 500);
                     var5 = (new Date()).getTime() - var5;
                     Netalyzr.this.debug("connected to '" + var3 + "' in " + var5 + " ms");
                     if (this.proxiedPorts.length() > 0) {
                        this.proxiedPorts.append(",");
                     }

                     this.proxiedPorts.append(Netalyzr.proxyPortsToTest[var2]);
                     this.proxiedPorts.append("/" + var5);
                     Netalyzr.this.tracebackProxyPorts.add(new Integer(Netalyzr.proxyPortsToTest[var2]));

                     try {
                        var4.close();
                     } catch (Exception var8) {
                        Netalyzr.this.debug("Caught exception on closing " + var8);
                     }
                  } catch (Exception var9) {
                     Netalyzr.this.debug("Connection failed: " + var9);
                     if (this.unproxiedPorts.length() > 0) {
                        this.unproxiedPorts.append(",");
                     }

                     this.unproxiedPorts.append(Netalyzr.proxyPortsToTest[var2]);
                  }
               }

               return 4;
            }
         }

         public String getPostResults() {
            return "\ncheckedPortsWithProxies=" + this.proxiedPorts + "\ncheckedPortsWithoutProxies=" + this.unproxiedPorts + "\ncheckedNonResponsiveIP=" + this.nonResponsiveIP + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkProxyTraceroute") {
         int connectTimeoutMillis = 30000;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 5000L;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               return 0;
            } else {
               for(int var1 = 0; var1 < Netalyzr.this.tracebackProxyPorts.size(); ++var1) {
                  int var2 = (Integer)Netalyzr.this.tracebackProxyPorts.get(var1);
                  this.proxyTraceroute(var2, "ipv4-proxy-server." + Netalyzr.this.custDnsName, "IPv4");
                  if (Netalyzr.this.canDoV6) {
                     this.proxyTraceroute(var2, "ipv6-proxy-server." + Netalyzr.this.custDnsName, "IPv6");
                  }
               }

               return 4;
            }
         }

         private void proxyTraceroute(int var1, String var2, String var3) {
            Netalyzr.this.debug("Executing proxy traceroute from host " + var2 + " port " + var1);
            if (var1 != 80) {
               try {
                  InetSocketAddress var4 = new InetSocketAddress(var2, var1);
                  Socket var5 = new Socket();
                  long var6 = (new Date()).getTime();
                  var5.connect(var4, this.connectTimeoutMillis);
                  var6 = (new Date()).getTime() - var6;
                  Netalyzr.this.debug("connected to '" + var4 + "' in " + var6 + " ms");
                  var5.close();
               } catch (Exception var9) {
                  Netalyzr.this.debug("Caught exception " + var9);
                  Netalyzr.this.debugStackTrace(var9);
               }
            }

            Netalyzr.this.debug("Now fetching HTTP data");
            String var10 = "GET /port=" + var1 + " HTTP/1.1\r\nHost: " + var2 + "\r\nUser-AgEnt: " + Netalyzr.this.userAgent + "\r\nAccept: " + Netalyzr.this.accept + "\r\nAccept-Language: " + Netalyzr.this.acceptLanguage + "\r\nAccept-Encoding: " + Netalyzr.this.acceptEncoding + "\r\nAccept-Charset: " + Netalyzr.this.acceptCharset + "\r\nConnEction: close\r\n\r\n";
            Netalyzr.HttpResponse var11 = Netalyzr.this.new HttpResponse();

            try {
               InetSocketAddress var12 = new InetSocketAddress(var2, 80);
               if (Netalyzr.this.checkRawHTTP(var12, var10, var11, this.connectTimeoutMillis) == 4) {
                  Netalyzr.this.debug("Got HTTP response, uploading results");
                  Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=proxyTraceroute" + var3 + "Port" + var1, var11.getEntity(), "text/html");
                  Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=proxyTraceroute" + var3 + "Port" + var1 + "withHeaders", new String(var11.getRawContent()));
               } else {
                  Netalyzr.this.debug("Didn't get a full response but trying upload anyway");
                  Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=proxyTraceroute" + var3 + "Port" + var1, new String(var11.getRawContent()));
               }
            } catch (Exception var8) {
               Netalyzr.this.debug("Caught exception " + var8);
               Netalyzr.this.debugStackTrace(var8);
            }

         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSMTU") {
         String name = "ednspadding-";
         int dnsMTU;
         boolean ok513;
         boolean ok1281;
         boolean ok1473;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 60000L;
            this.dnsMTU = 0;
            this.ok513 = false;
            this.ok1281 = false;
            this.ok1473 = false;
         }

         int runImpl() {
            Netalyzr.this.debug("Checking that the name is working");
            if (Netalyzr.this.isTrueName(this.name + "0.xdnsmtu" + Netalyzr.this.custDnsName)) {
               Netalyzr.this.debug("Can look up base name OK");
               Netalyzr.this.debug("Prefetching the three most common failures");
               Thread var1 = new Thread() {
                  public void run() {
                     if (Netalyzr.this.isTrueName(name + 513 + ".qdnsmtu" + Netalyzr.this.custDnsName)) {
                        Netalyzr.this.debug("Able to get 513B value");
                        ok513 = true;
                     } else {
                        Netalyzr.this.debug("Not able to get 513B value");
                        ok513 = false;
                     }

                  }
               };
               var1.start();
               var1 = new Thread() {
                  public void run() {
                     if (Netalyzr.this.isTrueName(name + 1281 + ".qdnsmtueoeu" + Netalyzr.this.custDnsName)) {
                        Netalyzr.this.debug("Able to get 1281B value");
                        ok1281 = true;
                     } else {
                        Netalyzr.this.debug("Not able to get 1281B value");
                        ok1281 = false;
                     }

                  }
               };
               var1.start();
               var1 = new Thread() {
                  public void run() {
                     if (Netalyzr.this.isTrueName(name + 1473 + ".qdnsmtu" + Netalyzr.this.custDnsName)) {
                        Netalyzr.this.debug("Able to get 1473B value");
                        ok1473 = true;
                     } else {
                        Netalyzr.this.debug("Not able to get 1473B value");
                        ok1473 = false;
                     }

                  }
               };
               var1.start();

               try {
                  Thread.sleep(1000L);
               } catch (InterruptedException var5) {
               }

               if (Netalyzr.this.isTrueName(this.name + 4000 + ".ydnsmtu" + Netalyzr.this.custDnsName)) {
                  Netalyzr.this.debug("Able to get the maximum value");
                  this.dnsMTU = 4000;
                  return 4;
               } else {
                  int var2 = 0;
                  int var3 = 4000;
                  if (!this.ok1473) {
                     var3 = 1473;
                     Netalyzr.this.debug("Wasn't able to get 1473B");
                  }

                  if (!this.ok1281) {
                     var3 = 1281;
                     Netalyzr.this.debug("Wasn't able to get 1281B");
                  }

                  if (!this.ok513) {
                     var3 = 513;
                     Netalyzr.this.debug("Wasn't able to get 513B");
                  }

                  int var4 = (var3 - var2) / 2 + var2;
                  Netalyzr.this.debug("Not able to get the maximum");
                  Netalyzr.this.debug("Beginning binary search to find the actual max");
                  this.idleMsg = Netalyzr.this.getLocalString("checkDNSMTUSearch");
                  Netalyzr.this.shell.enableRedraw();

                  for(; var2 < var3 - 1; var4 = (var3 - var2) / 2 + var2) {
                     Netalyzr.this.debug("Works: " + var2);
                     Netalyzr.this.debug("Fails: " + var3);
                     Netalyzr.this.debug("At:    " + var4);
                     if (Netalyzr.this.isTrueName(this.name + var4 + ".dnsmtu" + var4 + Netalyzr.this.custDnsName)) {
                        var2 = var4;
                     } else {
                        var3 = var4;
                     }
                  }

                  Netalyzr.this.debug("Found maximum working value " + var2);
                  Netalyzr.this.debug("Failure at " + var3);
                  this.dnsMTU = var2;
                  return 4;
               }
            } else {
               Netalyzr.this.debug("This name isn't working, so not executing this test");
               return 0;
            }
         }

         String getPostResults() {
            return "\ndnsPracticalMTU=" + this.dnsMTU + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkImportantNames") {
         String[] names;
         String[] results;

         {
            this.names = Names.names;
         }

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 35000L;
         }

         String fetchName(String var1) {
            String var2;
            try {
               var2 = InetAddress.getByName(var1).getHostAddress();
               if (var2 != "") {
                  return var2;
               }
            } catch (Exception var4) {
            }

            Netalyzr.this.debug("Failed to fetch name.  Retrying once for " + var1);

            try {
               var2 = InetAddress.getByName(var1).getHostAddress();
               if (var2 != "") {
                  return var2;
               }
            } catch (Exception var3) {
            }

            Netalyzr.this.debug("Failed to fetch name.  Giving up " + var1);
            return "";
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               String var10 = Netalyzr.this.sortLines(this.getPostResultsInternal());
               Netalyzr.this.debug("Post string results:\n" + var10);
               Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/log/id=" + Netalyzr.this.agentID, var10);
               this.ignoreResult = true;
               return 1;
            } else {
               this.results = new String[this.names.length];
               int var1 = 0;
               this.idleMsg = Netalyzr.this.getLocalString("checkImportantNamesStart");
               Netalyzr.this.shell.enableRedraw();
               long var2 = (new Date()).getTime();

               for(final int var4 = 0; var4 < this.names.length; ++var4) {
                  if ((this.names.length - var4) % 5 == 0) {
                     this.idleMsg = Netalyzr.this.getLocalString("checkImportantNamesCounting", new Object[]{new Integer(this.names.length - var4)});
                     Netalyzr.this.shell.enableRedraw();
                  }

                  Thread var6 = new Thread() {
                     public void run() {
                        results[var4] = fetchName(names[var4]);
                     }
                  };
                  var6.start();

                  try {
                     Thread.sleep(100L);
                  } catch (InterruptedException var9) {
                  }
               }

               boolean var11 = false;

               int var12;
               for(int var5 = 0; !var11; var5 = var12) {
                  var12 = 0;
                  var1 = 0;

                  try {
                     Thread.sleep(200L);
                  } catch (InterruptedException var8) {
                  }

                  for(int var7 = 0; var7 < this.names.length; ++var7) {
                     if (this.results[var7] == null) {
                        ++var12;
                     } else if (this.results[var7] != "") {
                        ++var1;
                     }
                  }

                  this.timeout = 100L;
                  if (var12 == 0 || (new Date()).getTime() - var2 > 20000L) {
                     var11 = true;
                  }

                  if (var12 != var5) {
                     if (var12 == 1) {
                        this.idleMsg = Netalyzr.this.getLocalString("checkImportantNamesWaitOne");
                     } else {
                        this.idleMsg = Netalyzr.this.getLocalString("checkImportantNamesWaitN", new Object[]{new Integer(var12)});
                     }

                     Netalyzr.this.shell.enableRedraw();
                  }
               }

               this.idleMsg = Netalyzr.this.getLocalString("checkImportantNamesPost");
               Netalyzr.this.shell.enableRedraw();
               this.timeout += 10000L;
               String var13 = Netalyzr.this.sortLines(this.getPostResultsInternal());
               Netalyzr.this.debug("Post string results:\n" + var13);
               Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/log/id=" + Netalyzr.this.agentID, var13);
               if (var1 == 0) {
                  return 2;
               } else if (var1 == this.names.length) {
                  return 4;
               } else {
                  return 6;
               }
            }
         }

         String getPostResultsInternal() {
            String var1 = "";
            if (!Netalyzr.this.globalClientAddr.equals("0.0.0.0")) {
               var1 = var1 + "globalAddr=" + Netalyzr.this.globalClientAddr + "\n";
            }

            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               return var1;
            } else {
               String var2 = null;

               for(int var3 = 0; var3 < this.names.length; ++var3) {
                  if (this.results[var3] != null && this.results[var3] != "") {
                     var1 = var1 + this.names[var3] + "=" + this.results[var3] + "\n";
                  } else if (var2 == null) {
                     var2 = "\nunfoundNames=" + this.names[var3];
                  } else {
                     var2 = var2 + "," + this.names[var3];
                  }
               }

               return var1 + var2 + "\n";
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkMTU") {
         int sendMTU;
         int recvMTU;
         String pathMTUProblem;
         String bottleneckIP;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.pathMTUProblem = "false";
            this.bottleneckIP = "";
         }

         int runImpl() throws IOException {
            int var1 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("FRAGMENT_ECHO_PORT"));
            String var2 = Netalyzr.this.serverName;
            if (!Netalyzr.this.canDoRawUDP) {
               this.ignoreResult = true;
               return 1;
            } else {
               this.sendMTU = -1;
               String var4 = "fragment ";

               for(int var5 = 0; var5 < 200; ++var5) {
                  var4 = var4 + "1234567890";
               }

               Netalyzr.this.debug("Attempting to send a packet with");
               Netalyzr.this.debug("fragmentation of " + var4.length() + " bytes");
               Netalyzr.UDPTestArgs var3 = Netalyzr.this.new UDPTestArgs(1, 10, var4.getBytes());
               byte[] var9 = Netalyzr.this.getUDPData(var2, var1, var3);
               if (var9 != null) {
                  Netalyzr.this.debug("Got a reply back, so working");
                  this.sendMTU = Netalyzr.this.parseInt(new String(var9));
                  Netalyzr.this.debug("Send packet MTU is " + this.sendMTU);
               } else {
                  Netalyzr.this.debug("No reply back");
               }

               Netalyzr.this.debug("Now looking for the receive MTU. Trying 1500 first");
               var4 = "mtu 1500 64";
               Netalyzr.this.debug("MSG: " + var4);
               var3 = Netalyzr.this.new UDPTestArgs(1, 10, var4.getBytes());
               var9 = Netalyzr.this.getUDPData(var2, var1, var3);
               this.pathMTUProblem = "False";
               if (var9 == null) {
                  Netalyzr.this.debug("No data received, so a path MTU problem");
                  this.pathMTUProblem = "True";
               } else {
                  if (!(new String(var9)).startsWith("bad")) {
                     Netalyzr.this.debug("Path MTU is >= 1500B");
                     this.recvMTU = 1500;
                     return 4;
                  }

                  Netalyzr.this.debug("Response is " + new String(var9));
                  Netalyzr.this.debug("Path MTU is <1500B");
               }

               Netalyzr.this.debug("Beginning binary search to find the path MTU");
               int var6 = 0;
               int var7 = 1500;

               for(int var8 = (var7 - var6) / 2 + var6; var6 < var7 - 1; var8 = (var7 - var6) / 2 + var6) {
                  Netalyzr.this.debug("Works: " + var6);
                  Netalyzr.this.debug("Fails: " + var7);
                  Netalyzr.this.debug("At:    " + var8);
                  var4 = "mtu " + var8 + " 64";
                  Netalyzr.this.debug("Message: " + var4);
                  var3 = Netalyzr.this.new UDPTestArgs(1, 5, var4.getBytes());
                  var9 = Netalyzr.this.getUDPData(var2, var1, var3);
                  if (var9 == null) {
                     var7 = var8;
                     Netalyzr.this.debug("Silent failure");
                  } else if ((new String(var9)).startsWith("bad")) {
                     var7 = var8;
                     Netalyzr.this.debug("Responsive failure");
                     Netalyzr.this.debug("Response is " + new String(var9));
                     this.bottleneckIP = (new String(var9)).split(" ")[2];
                  } else {
                     Netalyzr.this.debug("Success");
                     var6 = var8;
                  }
               }

               this.recvMTU = var6;
               Netalyzr.this.debug("Final MTU is " + this.recvMTU);
               return 4;
            }
         }

         String getPostResults() {
            return "\nsendPathMTU=" + this.sendMTU + "\nrecvPathMTU=" + this.recvMTU + "\npathMTUProblem=" + this.pathMTUProblem + "\nbottleneckIP=" + this.bottleneckIP + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkContentFilters") {
         null.FilterTestResult[] filterTests;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRawHTTP) {
               this.ignoreResult = true;
               return 0;
            } else {
               this.filterTests = new null.FilterTestResult[3];
               this.filterTests[0] = new null.FilterTestResult("exe", "EXE");
               this.filterTests[1] = new null.FilterTestResult("mp3", "MP3");
               this.filterTests[2] = new null.FilterTestResult("torrent", "TORRENT");
               return 4;
            }
         }

         String getPostResults() {
            String var1 = "";
            boolean var2 = false;

            for(int var3 = 0; var3 < this.filterTests.length; ++var3) {
               if (this.filterTests[var3] != null) {
                  var1 = var1 + this.filterTests[var3].getPostResults();
               }
            }

            if (var1.equals("")) {
               var1 = var1 + "\nnoFiletypeModifications=True\n";
            }

            var1 = var1 + "\n";
            return var1;
         }

         class FilterTestResult {
            String fileName;
            int fileLength;
            String testName;
            boolean filtered;
            boolean modified;
            String encoding;
            int length;

            public FilterTestResult(String var2, String var3) {
               this.testName = var2;
               this.fileName = Netalyzr.this.shell.getParameter(var3 + "_FILE");
               this.fileLength = Integer.parseInt(Netalyzr.this.shell.getParameter(var3 + "_LENGTH"));
               Netalyzr.this.debug("\nFetching file " + this.fileName + " of length " + this.fileLength);
               this.modified = false;
               this.filtered = false;
               this.encoding = null;
               this.length = 0;
               String var4 = "GET http://" + Netalyzr.this.getHTTPServerName() + "/file/id=" + Netalyzr.this.agentID + "/name=" + this.fileName + " HTTP/1.1";
               Netalyzr.this.debug("query is " + var4);
               String[] var5 = new String[]{"HoSt: " + Netalyzr.this.serverName + ":" + Netalyzr.this.serverPort, "User-AgEnt: " + Netalyzr.this.userAgent, "AcCept: " + Netalyzr.this.accept, "AccEpt-Language: " + Netalyzr.this.acceptLanguage, "AccEPt-Encoding: " + Netalyzr.this.acceptEncoding, "AccEPT-Charset: " + Netalyzr.this.acceptCharset, "CooKIE: netAlyzer=FoO", "ConnEction: keep-alive"};

               for(int var6 = 0; var6 < var5.length; ++var6) {
                  var4 = var4 + "\r\n" + var5[var6];
               }

               var4 = var4 + "\r\n\r\n";
               Netalyzr.HttpResponse var14 = Netalyzr.this.new HttpResponse();

               try {
                  int var7 = Netalyzr.this.checkRawHTTP(Netalyzr.this.serverName, Netalyzr.this.serverPort, var4, var14);
                  if (var7 != 4) {
                     Netalyzr.this.debug("Fetch failed");
                     this.filtered = true;
                     return;
                  }
               } catch (IOException var13) {
                  Netalyzr.this.debug("Got I/O exception on file fetch");
                  this.filtered = true;
                  return;
               }

               long var15 = (long)var14.getContentLength();
               Netalyzr.this.debug("Got response code " + var14.getResponseCode() + ", length is " + var15);
               byte[] var9 = var14.getEntity();
               if (var9 == null) {
                  Netalyzr.this.debug("Failed to load file properly");
                  this.modified = true;
               } else {
                  List var10 = var14.getHeaderList();
                  Map var11 = var14.getHeaderFields();

                  for(int var12 = 0; var12 < var10.size(); ++var12) {
                     Netalyzr.this.debug("Header " + var12 + " is " + var10.get(var12));
                  }

                  this.length = var9.length;
                  if (var9.length != this.fileLength) {
                     Netalyzr.this.debug("File fetched, but length returned is " + var9.length + " rather than " + this.fileLength);
                     this.modified = true;
                     this.encoding = var14.getHeader("content-encoding");
                     Netalyzr.this.debug("Uploading response");
                     Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=modified_" + this.fileName + "/dummy=ignore.txt", var14.getRawContent(), "application/octet-stream");
                     ++Netalyzr.this.transcodeCount;
                     Netalyzr.this.debug("Successfully posted changed content");
                  } else {
                     Netalyzr.this.debug("Test file fetched successfully");
                  }
               }
            }

            public String getPostResults() {
               if (this.encoding != null) {
                  try {
                     return "\n" + this.testName + "Modified=true\n" + this.testName + "Encoding=" + Netalyzr.this.safeUrlEncode(this.encoding, "US-ASCII") + "\n" + this.testName + "Length=" + this.length + "\n" + this.testName + "ExpectedLength=" + this.fileLength + "\n";
                  } catch (UnsupportedEncodingException var2) {
                  }
               }

               if (this.modified) {
                  return "\n" + this.testName + "Modified=true\n";
               } else {
                  return this.filtered ? "\n" + this.testName + "Filtered=true\n" : "";
               }
            }
         }
      });
      this.tests.add(new Netalyzr.Test("check404Rewriting") {
         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         void fetchPage(String var1) {
            try {
               String var2 = "/notfound/mode-" + var1 + "/" + Netalyzr.this.agentID + ".html";
               Netalyzr.this.debug("Fetching " + var1 + " 404 message via " + var2);
               Netalyzr.HttpResponse var3 = Netalyzr.this.new HttpResponse();
               String var4 = "GET " + var2 + " HTTP/1.1\r\nHost: " + Netalyzr.this.getHTTPServerName() + "\r\nUser-Agent: " + Netalyzr.this.userAgent + "\r\nAccept: " + Netalyzr.this.accept + "\r\nAccept-Language: " + Netalyzr.this.acceptLanguage + "\r\nAccept-Encoding: \r\nAccept-Charset: " + Netalyzr.this.acceptCharset + "\r\nConnection: close\r\n\r\n";
               int var5 = Netalyzr.this.checkRawHTTP(Netalyzr.this.serverName, Netalyzr.this.serverPort, var4, var3);
               byte[] var6 = var3.getRawContent();
               int var7 = var6 != null ? var6.length : 0;
               if (var5 == 4) {
                  Netalyzr.this.debug("Fetch succeeded: " + var7 + " bytes retrieved.");
               } else if (var5 == 66) {
                  Netalyzr.this.debug("Fetch failed with HTTP format violation: " + var7 + " bytes retrieved.");
               } else {
                  Netalyzr.this.debug("Fetch failed with unknown error: " + var7 + " bytes retrieved.");
               }

               if (var6 != null) {
                  Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=" + var1 + "_404", new String(var6));
                  Netalyzr.this.debug("Successfully posted 404 content");
               }

               Netalyzr.this.debug("");
            } catch (Exception var8) {
               Netalyzr.this.debug("Failed to fetch URL: exception " + var8);
            }

         }

         int runImpl() {
            if (!Netalyzr.this.canDoRawHTTP) {
               this.ignoreResult = true;
               return 0;
            } else {
               this.fetchPage("plain");
               this.fetchPage("apache");
               this.fetchPage("custom");
               return 4;
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkHTTPCache") {
         public static final int TEST_ERROR_MALFORMED_URL = 64;
         public static final int TEST_ERROR_ENTITY = 128;
         public static final int TEST_SUCCESS_UNCACHED_STRONG_MATCH = 64;
         public static final int TEST_SUCCESS_UNCACHED_WEAK_MATCH = 128;
         public static final int TEST_SUCCESS_CACHED_WEAK_MATCH = 256;
         public static final int TEST_SUCCESS_CACHED_STRONG_MATCH = 512;
         MessageDigest md5;
         String eTag;
         String lastMod;
         boolean pragmaNoCache;
         boolean ccNoCache;
         boolean ccNoStore;
         String resultCodes;
         boolean transcoded;
         String idleMsgBase = Netalyzr.this.getLocalString("checkHTTPCache");

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.resultCodes = "";
            this.timeout = 90000L;
            this.clearState();
            this.transcoded = false;

            try {
               this.md5 = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException var2) {
               this.initSuccess = false;
            }

         }

         void clearState() {
            this.lastMod = null;
            this.eTag = null;
            this.pragmaNoCache = this.ccNoCache = this.ccNoStore = false;
         }

         null.DigestResult getImageDigest(String var1) throws MalformedURLException, IOException {
            int var2 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("IMAGE_LENGTH"));
            String var3 = "GET http://" + Netalyzr.this.getHTTPServerName() + var1 + " HTTP/1.1";
            Netalyzr.this.debug("Requesting " + var3);
            var3 = var3 + "\r\nHost: " + Netalyzr.this.serverName + ":" + Netalyzr.this.serverPort + "\r\nUser-AgEnt: " + Netalyzr.this.userAgent + "\r\nAccept: " + Netalyzr.this.accept + "\r\nAccept-Language: " + Netalyzr.this.acceptLanguage + "\r\nAccept-Encoding: " + Netalyzr.this.acceptEncoding + "\r\nAccept-Charset: " + Netalyzr.this.acceptCharset + "\r\nConnEction: keep-alive\r\n";
            if (this.lastMod != null) {
               var3 = var3 + "If-Modified-Since: " + this.lastMod + "\r\n";
            }

            if (this.eTag != null) {
               var3 = var3 + "If-None-Match: " + this.eTag + "\r\n";
            }

            if (this.pragmaNoCache) {
               var3 = var3 + "Pragma: no-cache\r\n";
            }

            if (this.ccNoCache || this.ccNoStore) {
               var3 = var3 + "Cache-Control: ";
               if (this.ccNoCache) {
                  var3 = var3 + "no-cache";
               }

               if (this.ccNoCache && this.ccNoStore) {
                  var3 = var3 + ",";
               }

               if (this.ccNoStore) {
                  var3 = var3 + "no-store";
               }

               var3 = var3 + "\r\n";
            }

            var3 = var3 + "\r\n";
            Netalyzr.HttpResponse var4 = Netalyzr.this.new HttpResponse();
            if (Netalyzr.this.proxyHost != null && Netalyzr.this.proxyPort >= 0) {
               Netalyzr.this.debug("Routing via " + Netalyzr.this.proxyHost + ":" + Netalyzr.this.proxyPort);
               if ((Netalyzr.this.checkRawHTTP(Netalyzr.this.proxyHost, Netalyzr.this.proxyPort, var3, var4) & 2) != 0) {
                  return null;
               }
            } else {
               Netalyzr.this.debug("Routing directly.");
               if ((Netalyzr.this.checkRawHTTP(Netalyzr.this.serverName, Netalyzr.this.serverPort, var3, var4) & 2) != 0) {
                  return null;
               }
            }

            this.lastMod = var4.getHeader("Last-Modified");
            this.eTag = var4.getHeader("ETag");
            long var5 = (long)var4.getContentLength();
            null.DigestResult var7 = new null.DigestResult(var4.getResponseCode(), var5);
            Netalyzr.this.debug("Got response code " + var4.getResponseCode());
            Netalyzr.this.debug("Len is " + var5);
            if (var5 < 0L) {
               return var7;
            } else {
               if (var5 != (long)var2) {
                  this.transcoded = true;
                  Netalyzr.this.debug("Did not get expected size on image response");
                  Netalyzr.this.debug("Uploading response");
                  Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=transcoded_image" + Netalyzr.this.transcodeCount, var4.getRawContent(), "application/octet-stream");
                  ++Netalyzr.this.transcodeCount;
                  Netalyzr.this.debug("Successfully posted changed content");
               }

               byte[] var8 = var4.getEntity();
               if (var8 != null && (long)var8.length == var5) {
                  this.md5.reset();
                  this.md5.update(var8);
                  var7.digest = this.md5.digest();
                  return var7;
               } else {
                  Netalyzr.this.debug("Failed to load image from " + var1 + ", got " + var8.length + "/" + var5);
                  return var7;
               }
            }
         }

         int compareImageDigests(String var1, String var2) throws MalformedURLException, IOException {
            null.DigestResult var3 = this.getImageDigest(var1);
            null.DigestResult var4 = this.getImageDigest(var1);
            if (var3 != null && var4 != null && var3.digest != null) {
               this.resultCodes = this.resultCodes + "\nresultCode" + var2 + "1=" + var3.responseCode;
               this.resultCodes = this.resultCodes + "\nresultLength" + var2 + "1=" + var3.len;
               this.resultCodes = this.resultCodes + "\nresultCode" + var2 + "2=" + var4.responseCode;
               this.resultCodes = this.resultCodes + "\nresultLength" + var2 + "2=" + var4.len;
               if (var4.responseCode == 304) {
                  Netalyzr.this.debug("Second value returned a 304 (unchanged)");
                  this.resultCodes = this.resultCodes + "\nresultMatch" + var2 + "=match";
                  return 1;
               } else {
                  Netalyzr.this.debug("Digest for the first image is  " + (new BigInteger(var3.digest)).toString(16));
                  Netalyzr.this.debug("Digest for the second image is " + (new BigInteger(var4.digest)).toString(16));
                  if (MessageDigest.isEqual(var3.digest, var4.digest)) {
                     Netalyzr.this.debug("Digest values were equal");
                     this.resultCodes = this.resultCodes + "\nresultMatch" + var2 + "=match";
                     return 1;
                  } else {
                     Netalyzr.this.debug("Digest values are not equal");
                     this.resultCodes = this.resultCodes + "\nresultMatch" + var2 + "=mismatch";
                     return -1;
                  }
               }
            } else {
               if (var3 == null) {
                  Netalyzr.this.debug("DR1 is null");
                  this.resultCodes = this.resultCodes + "\nresultCode" + var2 + "1=null";
                  this.resultCodes = this.resultCodes + "\nresultLength" + var2 + "1=null";
               } else if (var3.digest == null) {
                  this.resultCodes = this.resultCodes + "\nresultCode" + var2 + "1=" + var3.responseCode;
                  this.resultCodes = this.resultCodes + "\nresultLength" + var2 + "1=" + var3.len;
                  Netalyzr.this.debug("DR1 digest is null");
               }

               if (var4 == null) {
                  this.resultCodes = this.resultCodes + "\nresultCode" + var2 + "2=null";
                  this.resultCodes = this.resultCodes + "\nresultLength" + var2 + "2=null";
                  Netalyzr.this.debug("DR2 is null");
               } else {
                  this.resultCodes = this.resultCodes + "\nresultCode" + var2 + "2=" + var4.responseCode;
                  this.resultCodes = this.resultCodes + "\nresultLength" + var2 + "2=" + var4.len;
               }

               this.resultCodes = this.resultCodes + "\nresultMatch" + var2 + "=failed";
               return 0;
            }
         }

         int runImpl() throws IOException {
            int var1 = 0;
            if (!Netalyzr.this.canDoRawHTTP) {
               this.ignoreResult = true;
               return 0;
            } else {
               try {
                  this.idleMsg = this.idleMsgBase + " " + Netalyzr.this.getLocalString("checkHTTPCacheSU");
                  Netalyzr.this.shell.enableRedraw();
                  String var3 = "/image/id=" + Netalyzr.this.agentID + "~1/mode=uncached-strong.jpg";
                  this.clearState();
                  this.pragmaNoCache = this.ccNoCache = this.ccNoStore = true;
                  int var2;
                  if ((var2 = this.compareImageDigests(var3, "UncachedStrong")) == 0) {
                     Netalyzr.this.debug("Error on comparing image digests");
                     return 130;
                  }

                  if (var2 == 1) {
                     var1 |= 64;
                  }

                  this.idleMsg = this.idleMsgBase + " " + Netalyzr.this.getLocalString("checkHTTPCacheWU");
                  Netalyzr.this.shell.enableRedraw();
                  var3 = "/image/id=" + Netalyzr.this.agentID + "~2/mode=uncached-weak.jpg";
                  this.clearState();
                  if ((var2 = this.compareImageDigests(var3, "UncachedWeak")) == 0) {
                     return 130;
                  }

                  if (var2 == 1) {
                     var1 |= 128;
                  }

                  this.idleMsg = this.idleMsgBase + " " + Netalyzr.this.getLocalString("checkHTTPCacheWC");
                  Netalyzr.this.shell.enableRedraw();
                  var3 = "/image/id=" + Netalyzr.this.agentID + "~3/mode=cached-weak.jpg";
                  this.clearState();
                  if ((var2 = this.compareImageDigests(var3, "CachedWeak")) == 0) {
                     return 130;
                  }

                  if (var2 == 1) {
                     var1 |= 256;
                  }

                  this.idleMsg = this.idleMsgBase + " " + Netalyzr.this.getLocalString("checkHTTPCacheSC");
                  Netalyzr.this.shell.enableRedraw();
                  var3 = "/image/id=" + Netalyzr.this.agentID + "~4/mode=cached-strong.jpg";
                  this.clearState();
                  if ((var2 = this.compareImageDigests(var3, "cachedStrong")) == 0) {
                     return 130;
                  }

                  if (var2 == 1) {
                     var1 |= 512;
                  }
               } catch (MalformedURLException var5) {
                  return 66;
               }

               return 6 | var1;
            }
         }

         String getPostResults() {
            this.resultCodes = this.resultCodes + "\n";
            return this.transcoded ? "\nimageTranscoded=True\n" + this.resultCodes : this.resultCodes;
         }

         class DigestResult {
            public int responseCode;
            public byte[] digest;
            public long len;

            DigestResult(int var2, long var3) {
               this.responseCode = var2;
               this.digest = null;
               this.len = var3;
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkGlue") {
         String gluePolicy = "";

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 4000L;
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               this.gluePolicy = "none";
               Netalyzr.this.debug("Checking for direct acceptance of glue");

               try {
                  if (Netalyzr.this.isTrueName("glue.glue1" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.glue1" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct glue entry");
                     this.gluePolicy = "exact";
                  }

                  if (Netalyzr.this.isTrueName("glue.glue1-b" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.glue1-b" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct glue entry");
                     this.gluePolicy = "exact";
                  }

                  if (Netalyzr.this.isTrueName("glue-internal.glue2" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.internal.glue2" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct internal glue entry");
                     this.gluePolicy = "internal";
                  }

                  if (Netalyzr.this.isTrueName("glue-internal.glue2-b" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.internal.glue2-b" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct internal glue entry");
                     this.gluePolicy = "internal";
                  }

                  if (Netalyzr.this.isTrueName("glue-external.glue3" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.glue3" + Netalyzr.this.custDnsAltName)) {
                     Netalyzr.this.debug("Will accept EXTERNAL GLUE!  AHHH!");
                     this.gluePolicy = "external";
                     return 2;
                  }

                  if (Netalyzr.this.isTrueName("glue-external.glue3-b" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.glue3-b" + Netalyzr.this.custDnsAltName)) {
                     Netalyzr.this.debug("Will accept EXTERNAL GLUE!  AHHH!");
                     this.gluePolicy = "external";
                     return 2;
                  }
               } catch (ThreadDeath var2) {
               }

               Netalyzr.this.debug("Glue policy is: " + this.gluePolicy);
               return 4;
            }
         }

         String getPostResults() {
            return "\ngluePolicyDesc=" + this.gluePolicy + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkCname") {
         String cnameAccepting = "";
         String cnameList = "";

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               this.cnameAccepting = "none";
               Netalyzr.this.debug("Checking for CNAME behavior");

               try {
                  if (Netalyzr.this.isTrueName("cname-ns.cname4" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will chase a CNAME involving an NS entry");
                     this.cnameAccepting = "ns";
                     this.cnameList = "ns";
                  }

                  if (Netalyzr.this.isTrueName("cname.cname1" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct cname entry");
                     this.cnameAccepting = "exact";
                     if (this.cnameList.length() != 0) {
                        this.cnameList = this.cnameList + ",";
                     }

                     this.cnameList = this.cnameList + "exact";
                  }

                  if (Netalyzr.this.isTrueName("cname-internal.cname2" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will chase an internal CNAME entry");
                     this.cnameAccepting = "internal";
                     if (this.cnameList.length() != 0) {
                        this.cnameList = this.cnameList + ",";
                     }

                     this.cnameList = this.cnameList + "internal";
                  }

                  if (Netalyzr.this.isTrueName("cname-external.cname3" + Netalyzr.this.custDnsName)) {
                     this.cnameAccepting = "external";
                     Netalyzr.this.debug("Will chase an external CNAME on the first try");
                     if (this.cnameList.length() != 0) {
                        this.cnameList = this.cnameList + ",";
                     }

                     this.cnameList = this.cnameList + "external";
                  } else if (Netalyzr.this.isTrueName("cname-external.cname3-b" + Netalyzr.this.custDnsName)) {
                     this.cnameAccepting = "external2";
                     Netalyzr.this.debug("Will chase an external CNAME on the second try");
                     if (this.cnameList.length() != 0) {
                        this.cnameList = this.cnameList + ",";
                     }

                     this.cnameList = this.cnameList + "external2";
                  }
               } catch (ThreadDeath var2) {
               }

               Netalyzr.this.debug("Cname policy is: " + this.cnameAccepting);
               return 4;
            }
         }

         String getPostResults() {
            return "\ncnameAcceptingPolicyDesc=" + this.cnameAccepting + "\ncnameAcceptingPolicyList=" + this.cnameList + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkGlueNs") {
         String glue_nsPolicy = "";

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               this.glue_nsPolicy = "none";
               Netalyzr.this.debug("Checking for direct acceptance of glue");

               try {
                  if (Netalyzr.this.isTrueName("glue-ns.glue-ns1" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.glue-ns1" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct glue_ns entry");
                     this.glue_nsPolicy = "exact";
                     Netalyzr.this.acceptNSGlue = true;
                  }

                  if (Netalyzr.this.isTrueName("glue-ns.glue-ns1-b" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.glue-ns1-b" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct glue_ns entry");
                     this.glue_nsPolicy = "exact";
                     Netalyzr.this.acceptNSGlue = true;
                  }

                  if (Netalyzr.this.isTrueName("glue-ns-internal.glue-ns2" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.internal.glue-ns2" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct internal glue_ns entry");
                     this.glue_nsPolicy = "internal";
                  }

                  if (Netalyzr.this.isTrueName("glue-ns-internal.glue-ns2-b" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.internal.glue-ns2-b" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Will accept a direct internal glue_ns entry");
                     this.glue_nsPolicy = "internal";
                  }

                  if (Netalyzr.this.isTrueName("glue-ns-external.glue-ns3" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.glue-ns3" + Netalyzr.this.custDnsAltName)) {
                     Netalyzr.this.debug("Will accept EXTERNAL GLUE_NS!  AHHH!");
                     this.glue_nsPolicy = "external";
                     return 2;
                  }

                  if (Netalyzr.this.isTrueName("glue-ns-external.glue-ns3-b" + Netalyzr.this.custDnsName) && Netalyzr.this.isTrueName("return-false.glue-ns3-b" + Netalyzr.this.custDnsAltName)) {
                     Netalyzr.this.debug("Will accept EXTERNAL GLUE_NS!  AHHH!");
                     this.glue_nsPolicy = "external";
                     return 2;
                  }
               } catch (ThreadDeath var2) {
               }

               Netalyzr.this.debug("Glue policy for NS is: " + this.glue_nsPolicy);
               return 4;
            }
         }

         String getPostResults() {
            return "\ngluensPolicyDesc=" + this.glue_nsPolicy + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("check0x20") {
         boolean support0x20;
         boolean pass0x20;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.support0x20 = false;
            this.pass0x20 = false;
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else if (Netalyzr.this.isTrueName("0x20.0x20test" + Netalyzr.this.custDnsName)) {
               Netalyzr.this.debug("Resolver uses 0x20");
               this.support0x20 = true;
               return 4;
            } else if (Netalyzr.this.isTrueName("0x20.0x20test-2" + Netalyzr.this.custDnsName)) {
               Netalyzr.this.debug("Resolver uses 0x20");
               this.support0x20 = true;
               return 4;
            } else {
               Netalyzr.this.debug("Resolver does not use 0x20");
               if (Netalyzr.this.isTrueName("0x20.0x20PaSSthRough" + Netalyzr.this.custDnsName)) {
                  Netalyzr.this.debug("Resolver passes 0x20 packets through");
                  this.pass0x20 = true;
               } else if (Netalyzr.this.isTrueName("0x20.0x20PaSSthRough_2" + Netalyzr.this.custDnsName)) {
                  Netalyzr.this.debug("Resolver passes 0x20 packets through");
                  this.pass0x20 = true;
               } else {
                  Netalyzr.this.debug("Resolver does not pass through 0x20");
               }

               return 4;
            }
         }

         String getPostResults() {
            String var1 = "";
            if (this.support0x20) {
               return "\nsupport0x20=True\npolicy0x20=support\n";
            } else {
               return this.pass0x20 ? "\npass0x20=True\npolicy0x20=pass\n" : "\npolicy0x20=strip\n";
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSANY") {
         boolean isAny;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.isAny = false;
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               if (Netalyzr.this.isTrueName("any.anytest" + Netalyzr.this.custDnsName)) {
                  Netalyzr.this.debug("Resolver uses ANY for A records");
                  this.isAny = true;
               } else if (Netalyzr.this.isTrueName("any.anytest-b" + Netalyzr.this.custDnsName)) {
                  Netalyzr.this.debug("Resolver uses ANY for A records");
                  this.isAny = true;
               } else {
                  Netalyzr.this.debug("Resolver does not use ANY records for its lookups for A records");
               }

               return 4;
            }
         }

         String getPostResults() {
            String var1 = "";
            return this.isAny ? "\nusesDNSANY=True\n" : "\nusesDNSANY=False\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSAAAA") {
         boolean isAAAA;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.isAAAA = false;
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               Netalyzr.this.isTrueName("ipv6-set.ipv6" + Netalyzr.this.custDnsName);

               try {
                  Thread.sleep(2000L);
               } catch (InterruptedException var3) {
               }

               if (Netalyzr.this.isTrueName("ipv6-check.ipv6" + Netalyzr.this.custDnsName)) {
                  Netalyzr.this.debug("Resolver queries for AAAA records");
                  this.isAAAA = true;
                  return 4;
               } else {
                  Netalyzr.this.debug("Resolver is not querying for V6 by default but trying a second try");
                  Netalyzr.this.isTrueName("ipv6-set.ipv6-b" + Netalyzr.this.custDnsName);

                  try {
                     Thread.sleep(2000L);
                  } catch (InterruptedException var2) {
                  }

                  if (Netalyzr.this.isTrueName("ipv6-check.ipv6-b" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Resolver queries for AAAA records");
                     this.isAAAA = true;
                  } else {
                     Netalyzr.this.debug("Resolver is not querying for V6 by default");
                  }

                  return 4;
               }
            }
         }

         String getPostResults() {
            String var1 = "";
            return this.isAAAA ? "\nusesDNSAAAA=True\n" : "\nusesDNSAAAA=False\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkEDNS") {
         String response;
         int edns_mtu;
         String edns_large;
         String edns_medium;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.response = "none";
            this.edns_mtu = 0;
            this.edns_large = "Untested";
            this.edns_medium = "Untested";
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               if (Netalyzr.this.isTrueName("has-edns.edns" + Netalyzr.this.custDnsName)) {
                  this.response = "EDNS";
                  Netalyzr.this.debug("Server uses EDNS");
               } else {
                  if (!Netalyzr.this.isTrueName("has-edns.edns-b" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("Server does not use EDNS, so not probing further");
                     return 4;
                  }

                  this.response = "EDNS";
                  Netalyzr.this.debug("Server uses EDNS");
               }

               if (Netalyzr.this.isTrueName("wants-dnssec.dnssec" + Netalyzr.this.custDnsName)) {
                  this.response = "DNSSEC";
               } else if (Netalyzr.this.isTrueName("wants-dnssec.dnssec-b" + Netalyzr.this.custDnsName)) {
                  this.response = "DNSSEC";
               }

               try {
                  if (Netalyzr.this.canDoUnrestrictedLookup) {
                     Netalyzr.this.debug("Trying to get self reported MTU");
                     String var1 = "edns-mtu.edns2" + Netalyzr.this.custDnsName;
                     InetAddress var9 = InetAddress.getByName(var1);
                     String var10 = var9.getHostAddress();
                     String[] var11 = var10.split("\\.");
                     int var12 = Netalyzr.this.parseInt(var11[2]) * 256 + Netalyzr.this.parseInt(var11[3]);
                     Netalyzr.this.debug("EDNS MTU is " + var12);
                     this.edns_mtu = var12;
                  }
               } catch (UnknownHostException var8) {
                  Netalyzr.this.debug("Got unknown host exception, trying a second time");

                  try {
                     String var2 = "edns-mtu.edns2" + Netalyzr.this.custDnsName;
                     InetAddress var3 = InetAddress.getByName(var2);
                     String var4 = var3.getHostAddress();
                     String[] var5 = var4.split("\\.");
                     int var6 = Netalyzr.this.parseInt(var5[2]) * 256 + Netalyzr.this.parseInt(var5[3]);
                     Netalyzr.this.debug("EDNS MTU is " + var6);
                     this.edns_mtu = var6;
                  } catch (UnknownHostException var7) {
                     Netalyzr.this.debug("Got a second failure");
                  }
               }

               Netalyzr.this.debug("Checking EDNS medium");
               this.edns_medium = "False";
               if (Netalyzr.this.isTrueName("edns-medium.medium-edns" + Netalyzr.this.custDnsName)) {
                  this.edns_medium = "True";
               } else if (Netalyzr.this.isTrueName("edns-medium.medium-edns-b" + Netalyzr.this.custDnsName)) {
                  this.edns_medium = "True";
               }

               Netalyzr.this.debug("Checking EDNS large");
               this.edns_large = "False";
               if (Netalyzr.this.isTrueName("edns-large.large-edns" + Netalyzr.this.custDnsName)) {
                  this.edns_large = "True";
               } else if (Netalyzr.this.isTrueName("edns-large.large-edns-b" + Netalyzr.this.custDnsName)) {
                  this.edns_large = "True";
               }

               return 4;
            }
         }

         String getPostResults() {
            return "\nednsStatus=" + this.response + "\nednsMTU=" + this.edns_mtu + "\nednsLarge=" + this.edns_large + "\nednsMedium=" + this.edns_medium + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSTCP") {
         String dnsTcp;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.dnsTcp = "";
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               boolean var1 = false;
               long var2 = (new Date()).getTime();
               if (Netalyzr.this.isTrueName("truncate.tcpfailover" + Netalyzr.this.custDnsName)) {
                  this.dnsTcp = "tcp";
                  Netalyzr.this.debug("Successful TCP failover");
                  return 4;
               } else {
                  long var4 = (new Date()).getTime();
                  if (var4 < var2 + 1000L) {
                     this.dnsTcp = "ignored";
                     Netalyzr.this.debug("TCP failover request ignored");
                  } else {
                     this.dnsTcp = "failed";
                     Netalyzr.this.debug("TCP failover timeud out");
                  }

                  return 4;
               }
            }
         }

         String getPostResults() {
            return "\ndnsTCPStatus=" + this.dnsTcp + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSTTL") {
         boolean ttl_0;
         boolean ttl_1;
         boolean failed;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.ttl_0 = false;
            this.ttl_1 = false;
            this.failed = false;
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               boolean var1 = false;
               if (Netalyzr.this.acceptNSGlue) {
                  Netalyzr.this.debug("Accepts glue records: able to perform full test");
                  Netalyzr.this.isTrueName("ttl-0.ttl0test" + Netalyzr.this.custDnsName);

                  try {
                     Thread.sleep(1000L);
                  } catch (InterruptedException var4) {
                  }

                  if (Netalyzr.this.isTrueName("return-false.ttl0test" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("The server cached a record with TTL 0");
                     this.ttl_0 = true;
                  } else {
                     Netalyzr.this.debug("The server did not cache a record with TTL 0");
                  }

                  Netalyzr.this.isTrueName("ttl-1.ttl0test" + Netalyzr.this.custDnsName);

                  try {
                     Thread.sleep(2500L);
                  } catch (InterruptedException var3) {
                  }

                  if (Netalyzr.this.isTrueName("return-false.ttl1test" + Netalyzr.this.custDnsName)) {
                     Netalyzr.this.debug("The server cached a record with TTL 1");
                     this.ttl_1 = true;
                  } else {
                     Netalyzr.this.debug("The server did not cache a record with TTL 1");
                  }

                  return 4;
               } else {
                  Netalyzr.this.debug("Not able to perform this test");
                  Netalyzr.this.debug("Because the DNS server doesn't accept glue records");
                  this.failed = true;
                  return 4;
               }
            }
         }

         String getPostResults() {
            String var1 = "";
            if (this.failed) {
               return "\nttl_uncheckable=True";
            } else {
               if (this.ttl_0) {
                  var1 = var1 + "\nttl0_cached=True";
               } else {
                  var1 = var1 + "\nttl0_cached=False";
               }

               if (this.ttl_1) {
                  var1 = var1 + "\nttl1_cached=True";
               } else {
                  var1 = var1 + "\nttl1_cached=False";
               }

               return var1 + "\n";
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSV6Server") {
         String result = "False";

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 2000L;
         }

         int runImpl() {
            if (Netalyzr.this.isTrueName("ipv6-dns.ipv6test" + Netalyzr.this.custDnsName)) {
               Netalyzr.this.debug("Able to look up from an IPv6-only nameserver");
               this.result = "True";
            } else {
               Netalyzr.this.debug("Not able to look up from an IPv6-only nameserver");
            }

            return 4;
         }

         String getPostResults() {
            return "\ndnsServerV6Support=" + this.result + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSPerformance") {
         int cachedLookups;
         int uncachedLookups;
         long cachedLookupTime;
         long uncachedLookupTime;
         long serverLookups;
         long serverLookupTime;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.cachedLookups = 0;
            this.uncachedLookups = 0;
            this.cachedLookupTime = 0L;
            this.uncachedLookupTime = 0L;
            this.serverLookups = 0L;
            this.serverLookupTime = 0L;
            this.timeout = 60000L;
         }

         int runImpl() {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               return 1;
            } else {
               byte var1 = 0;
               if (Netalyzr.this.acceptNSGlue) {
                  Netalyzr.this.debug("Accepts glue records: able to perform full test");
               } else {
                  Netalyzr.this.debug("Only able to check uncached latency");
               }

               long var2 = (new Date()).getTime();

               int var11;
               try {
                  for(var11 = 0; var11 < 10; ++var11) {
                     var2 = (new Date()).getTime();
                     Netalyzr.this.isTrueName("glue-ns.performance-test" + var11 + Netalyzr.this.custDnsName);
                     ++this.uncachedLookups;
                     this.uncachedLookupTime += (new Date()).getTime() - var2;
                     if (Netalyzr.this.acceptNSGlue) {
                        var2 = (new Date()).getTime();
                        if (Netalyzr.this.isTrueName("return-false.performance_test" + var11 + Netalyzr.this.custDnsName)) {
                           ++this.cachedLookups;
                           this.cachedLookupTime += (new Date()).getTime() - var2;
                        }
                     }
                  }
               } catch (ThreadDeath var10) {
                  if (var1 < 3) {
                     return 2;
                  }

                  return 4;
               }

               if (!Netalyzr.this.canDoUnrestrictedLookup) {
                  return 4;
               } else {
                  try {
                     for(var11 = 0; var11 < 10; ++var11) {
                        String var4 = "latency-set.perftest-latency" + var11 + Netalyzr.this.custDnsName;
                        Netalyzr.this.debug("Performance test: looking up " + var4);
                        InetAddress var5 = InetAddress.getByName(var4);
                        String var6 = var5.getHostAddress();
                        Netalyzr.this.debug("Got result of " + var6);
                        String[] var7 = var6.split("\\.");
                        if (Netalyzr.this.parseInt(var7[0]) != 192 || Netalyzr.this.parseInt(var7[1]) != 150) {
                           Netalyzr.this.debug("Unknown response");
                           return 4;
                        }

                        int var8 = Netalyzr.this.parseInt(var7[2]) * 256 + Netalyzr.this.parseInt(var7[3]);
                        ++this.serverLookups;
                        this.serverLookupTime += (long)var8;
                        Netalyzr.this.debug("Server lookup took " + var8 + " ms");
                     }
                  } catch (UnknownHostException var9) {
                     Netalyzr.this.debug("Got a failure in this test");
                  }

                  return 4;
               }
            }
         }

         String getPostResults() {
            String var1 = "";
            var1 = var1 + "\nuncachedLookupCount=" + this.uncachedLookups;
            var1 = var1 + "\ncachedLookupCount=" + this.cachedLookups;
            var1 = var1 + "\nserverLookupCount=" + this.serverLookups;
            var1 = var1 + "\nuncachedLookupTime=" + this.uncachedLookupTime;
            var1 = var1 + "\ncachedLookupTime=" + this.cachedLookupTime;
            var1 = var1 + "\nserverLookupTime=" + this.serverLookupTime;
            var1 = var1 + "\n";
            return var1;
         }
      });
      this.tests.add(new Netalyzr.Test("checkExternalDNSProxy") {
         Netalyzr.UDPTestArgs udpArgs;
         String dnsProxyReply;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.dnsProxyReply = "none";
            this.timeout = 100L;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoRawUDP) {
               this.ignoreResult = true;
               return 0;
            } else if (Netalyzr.this.globalClientAddr.equals("0.0.0.0")) {
               Netalyzr.this.debug("No known client address, not performing test");
               this.ignoreResult = true;
               return 0;
            } else {
               String var1 = Netalyzr.this.globalClientAddr;
               this.udpArgs = Netalyzr.this.new UDPTestArgs(1, 10, var1.getBytes());
               String var2 = Netalyzr.this.serverName;
               int var3 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("DNS_ECHO_PORT"));
               this.udpArgs.debugStatus();
               Netalyzr.this.debug("UDP server " + var2);
               byte[] var4 = Netalyzr.this.getUDPData(var2, var3, this.udpArgs);
               if (var4 != null) {
                  Netalyzr.this.debug("Got a reply back, so working");
                  this.dnsProxyReply = new String(var4);
               } else {
                  Netalyzr.this.debug("No reply back");
               }

               Netalyzr.this.debug("Status is " + this.dnsProxyReply);
               return 4;
            }
         }

         String getPostResults() {
            return "\nexternalDNSProxyStatus=" + this.dnsProxyReply + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkRawDNS") {
         boolean dnsProxy = false;
         String largeDNS = "Unknown";
         String mediumDNS = "Unknown";
         String smallDNS = "Unknown";
         String dnsChanges = "";
         String dnsDirectText = "Unknown";
         String dnsDirectIcsi = "Unknown";
         String dnsDirectIcsi2 = "Unknown";
         String dnsDirectIpv6 = "Unknown";
         String dnsDirectRecursiveOnly = "Unknown";
         String dnsDirectNxdomain = "Unknown";
         String dnsDirectTruncation = "Unknown";

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 30000L;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoRawUDP) {
               this.ignoreResult = true;
               return 0;
            } else {
               boolean var1 = false;
               byte[] var2 = new byte[1];
               Netalyzr.this.new UDPTestArgs(1, 5, var2);
               String var4 = Netalyzr.this.serverName;
               Netalyzr.this.debug("Checking to see if it can get large DNS packets");
               DNSMessage var5 = Netalyzr.this.checkDNSFetch(var4, "ednspadding-1800.edns1." + Netalyzr.this.custDnsName, 1, true, 4000);
               if (var5 != null && var5.datagramSize == 1800) {
                  Netalyzr.this.debug("Able to do large packets fine");
                  this.largeDNS = "True";
               } else if (var5 != null) {
                  Netalyzr.this.debug("Large DNS packets were manipulated!");
                  this.largeDNS = "Manipulated";
               } else {
                  Netalyzr.this.debug("Large DNS requests are blocked.  Grr");
                  this.largeDNS = "False";
               }

               Netalyzr.this.debug("Checking to see if it can get medium DNS packets");
               var5 = Netalyzr.this.checkDNSFetch(var4, "ednspadding-1100.edns2." + Netalyzr.this.custDnsName, 1, true, 4000);
               if (var5 != null && var5.rcode == 0) {
                  Netalyzr.this.debug("Able to do medium sized packets fine");
                  this.mediumDNS = "True";
               } else {
                  Netalyzr.this.debug("Medium sized DNS requests are blocked.  Grr");
                  this.mediumDNS = "False";
               }

               Netalyzr.this.debug("Checking to see if it can get small EDNS packets");
               var5 = Netalyzr.this.checkDNSFetch(var4, "ednspadding-300.edns3." + Netalyzr.this.custDnsName, 1, true, 4000);
               if (var5 != null && var5.rcode == 0) {
                  Netalyzr.this.debug("Able to do small sized packets fine");
                  this.smallDNS = "True";
               } else {
                  Netalyzr.this.debug("Small sized DNS requests are blocked.  Grr");
                  this.smallDNS = "False";
               }

               Netalyzr.this.debug("Checking to see if truncation works");
               var5 = Netalyzr.this.checkDNSFetch(var4, "truncate.tcpfailover." + Netalyzr.this.custDnsName, 1, false, 0);
               if (var5 != null && var5.rcode == 0) {
                  Netalyzr.this.debug("Able to do truncation");
                  this.dnsDirectTruncation = "True";
               } else {
                  Netalyzr.this.debug("Not able to failover to TCP");
                  this.dnsDirectTruncation = "False";
               }

               Netalyzr.this.debug("Checking if TXT records are received OK");
               String[] var6 = new String[]{"this is a test", "of two TXT records"};
               this.dnsDirectText = Netalyzr.this.checkDNSFetch(var4, "txt.direct1." + Netalyzr.this.custDnsName, 16, true, (String[])var6) ? "True" : "False";
               Netalyzr.this.debug("Checking if ICSI records are received OK");
               Netalyzr.this.debug("Keeping it as a meta test (TYPE169)");
               this.dnsDirectIcsi = Netalyzr.this.checkDNSFetch(var4, "txt.direct2." + Netalyzr.this.custDnsName, 169, true, (String[])var6) ? "True" : "False";
               Netalyzr.this.debug("Non-meta (TYPE1169)");
               this.dnsDirectIcsi2 = Netalyzr.this.checkDNSFetch(var4, "txt.directicsi." + Netalyzr.this.custDnsName, 1169, true, (String[])var6) ? "True" : "False";
               Netalyzr.this.debug("Checking if IPv6 records are received OK");
               this.dnsDirectIpv6 = Netalyzr.this.checkDNSFetch(var4, "ipv6-node.direct3." + Netalyzr.this.custDnsName, 28, true, (InetAddress)((Inet6Address)InetAddress.getByName(Netalyzr.this.ipv6Server))) ? "True" : "False";
               String var7 = "www.atestofnx" + Netalyzr.this.rng.nextInt() + "aoeuaoe" + Netalyzr.this.rng.nextInt() + "aoe.com";
               Netalyzr.this.debug("Checking for in-path NXDOMAIN wildcarding via direct query for " + var7);
               DNSMessage var8 = Netalyzr.this.checkDNSFetch(var4, var7, 1, true, 0);
               this.dnsDirectNxdomain = "";
               if (var8 != null && var8.answer.length > 0 && var8.answer[0].rtype == 1) {
                  Netalyzr.this.debug("In-path wildcarding detected");
                  this.dnsDirectNxdomain = this.dnsDirectNxdomain + ((DNSMessage.DNSRdataIP)var8.answer[0].rdata).rdata.getHostAddress();

                  try {
                     Netalyzr.this.debug("Attempting to fetch the page");
                     InetAddress var9 = ((DNSMessage.DNSRdataIP)var8.answer[0].rdata).rdata;
                     String var10 = "GET http://" + var7 + "/ HTTP/1.1\r\nHost: " + var7 + "\r\nUser-Agent: " + Netalyzr.this.userAgent + "\r\nAccept: " + Netalyzr.this.accept + "\r\nAccept-Language: " + Netalyzr.this.acceptLanguage + "\r\nAccept-Encoding: " + Netalyzr.this.acceptEncoding + "\r\nAccept-Charset: " + Netalyzr.this.acceptCharset + "\r\nConnection: close\r\n\r\n";
                     Netalyzr.HttpResponse var11 = Netalyzr.this.new HttpResponse();
                     Netalyzr.this.debug("Fetching http://" + var7 + " ...");
                     int var12 = Netalyzr.this.checkRawHTTP((InetAddress)var9, 80, var10, var11);
                     byte[] var13 = var11.getRawContent();
                     int var14 = var13 != null ? var13.length : 0;
                     if (var12 == 4) {
                        Netalyzr.this.debug("Fetch succeeded: " + var14 + " bytes retrieved.");
                     } else if (var12 == 66) {
                        Netalyzr.this.debug("Fetch failed with HTTP format violation: " + var14 + " bytes retrieved.");
                     } else {
                        Netalyzr.this.debug("Fetch failed with unknown error: " + var14 + " bytes retrieved.");
                     }

                     if (var13 != null) {
                        Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=directnxpage", new String(var13));
                        Netalyzr.this.debug("Successfully posted NXDOMAIN content");
                     }
                  } catch (Exception var24) {
                     Netalyzr.this.debug("Failed to fetch URL: exception " + var24);
                  }
               } else {
                  Netalyzr.this.debug("no in-path wildcarding detected");
               }

               DNSMessage var26 = null;

               try {
                  var26 = new DNSMessage("entropy.rawtest." + Netalyzr.this.custDnsName, 1);
               } catch (DNSMessage.DNSError var23) {
                  Netalyzr.this.debug("Caught DNS error " + var23);
               }

               var26.rd = true;
               var2 = var26.pack();
               Netalyzr.UDPTestArgs var3 = Netalyzr.this.new UDPTestArgs(1, 5, var2);
               var4 = Netalyzr.this.serverName;
               Netalyzr.this.debug("Sending DNS request with known expected result");
               byte[] var27 = Netalyzr.this.getUDPData(var4, 53, var3);
               if (var27 != null) {
                  String var28 = new String(var27);
                  Netalyzr.this.debug("Input is");
                  var26.print();

                  try {
                     var5 = new DNSMessage(var27);
                     Netalyzr.this.debug("Reply is");
                     var5.print();
                  } catch (DNSMessage.DNSError var22) {
                     Netalyzr.this.debug("DNS error");
                  }

                  String[] var30 = var28.split("status");
                  Netalyzr.this.debug("Split on 'status': length " + var30.length);
                  boolean var31 = false;
                  boolean var32 = false;
                  if (var30.length >= 2) {
                     Netalyzr.this.debug("Succesfully got status line");
                     var1 = true;
                     String var15 = var30[1].split("done")[0];

                     try {
                        String var16 = var15.split("ad=")[1].split("-end")[0].replace('-', '.');
                        Netalyzr.this.debug("Address from DNS is " + var16);
                        if (!Netalyzr.this.globalClientAddr.equals("0.0.0.0") && !var16.equals(Netalyzr.this.globalClientAddr)) {
                           Netalyzr.this.debug("The DNS request came to our server from " + var16);
                           Netalyzr.this.debug("But we expected it to come from " + Netalyzr.this.globalClientAddr);
                        } else {
                           Netalyzr.this.debug("Address matches OK");
                           var31 = true;
                        }

                        String var17 = var15.split("id=")[1].split("-end")[0];
                        Netalyzr.this.debug("ID from DNS is " + var17);
                        if (Integer.parseInt(var17) == var26.id) {
                           Netalyzr.this.debug("ID matches OK");
                           var32 = true;
                        } else {
                           Netalyzr.this.debug("This is not the expected ID.");
                           this.dnsChanges = this.dnsChanges + "\ndnsChangedID=" + var17;
                           this.dnsProxy = true;
                        }

                        try {
                           var26 = new DNSMessage("entropy.rawtest3." + Netalyzr.this.custDnsName, 1);
                        } catch (DNSMessage.DNSError var21) {
                           Netalyzr.this.debug("Caught DNS error " + var21);
                        }

                        var26.rd = false;
                        var2 = var26.pack();
                        Netalyzr.this.debug("Seeing if non-recursive requests are broken");
                        var3 = Netalyzr.this.new UDPTestArgs(1, 5, var2);
                        var4 = Netalyzr.this.serverName;
                        var27 = Netalyzr.this.getUDPData(var4, 53, var3);

                        try {
                           var5 = new DNSMessage(var27);
                           Netalyzr.this.debug("Reply is");
                           var5.print();
                           if (var5.rcode == 0) {
                              Netalyzr.this.debug("Got a proper reply");
                              this.dnsDirectRecursiveOnly = "False";
                           } else {
                              Netalyzr.this.debug("Error, got RCODE " + var5.rcode);
                              this.dnsDirectRecursiveOnly = "True:" + var5.rcode;
                              this.dnsProxy = true;
                           }
                        } catch (DNSMessage.DNSError var20) {
                           Netalyzr.this.debug("DNS error");
                           this.dnsDirectRecursiveOnly = "True:-1";
                        }
                     } catch (Exception var25) {
                        Netalyzr.this.debug("Failure to parse status line " + var15);
                     }

                     if (!var32 || !var31) {
                        this.dnsChanges = this.dnsChanges + "\ndnsMangled=True";
                        Netalyzr.this.debug("Mangled DNS, so fetching server directly");
                        Netalyzr.this.debug("Rather than relying on parsing the CNAME");
                        DNSMessage var33 = Netalyzr.this.checkDNSFetch(var4, "server.mangled." + Netalyzr.this.custDnsName, 1, true, 0);
                        Netalyzr.this.debug("Got server string");
                        if (var33 != null) {
                           var33.print();
                        }

                        if (var33 != null && var33.answer.length >= 1 && var33.answer[0].rtype == 1 && !((DNSMessage.DNSRdataIP)var33.answer[0].rdata).rdata.getHostAddress().equals(Netalyzr.this.globalClientAddr)) {
                           Netalyzr.this.debug("Unexpected server value, expected " + Netalyzr.this.globalClientAddr + " got " + ((DNSMessage.DNSRdataIP)var33.answer[0].rdata).rdata.getHostAddress());
                           this.dnsChanges = this.dnsChanges + "\ndnsChangedIP=" + ((DNSMessage.DNSRdataIP)var33.answer[0].rdata).rdata.getHostAddress() + "\n";
                           this.dnsProxy = true;
                        }

                        this.dnsChanges = this.dnsChanges + "\n";
                     }
                  }
               }

               Netalyzr.this.debug("Now checking for a bogus (non-DNS) packet on port 53");
               int var29 = Netalyzr.this.checkUDP(var4, 53, Netalyzr.this.new UDPTestArgs(1, 5));
               if (var29 == 4) {
                  Netalyzr.this.debug("Bogus ping test passed, no DNS filtering detected");
                  return var29;
               } else {
                  Netalyzr.this.debug("Bogus ping packet not received at client");
                  Netalyzr.this.debug("now checking again with a real DNS packet");

                  try {
                     var26 = new DNSMessage("entropy.rawtest3." + Netalyzr.this.custDnsName, 1);
                  } catch (DNSMessage.DNSError var19) {
                     Netalyzr.this.debug("Caught DNS exception " + var19);
                  }

                  var26.rd = true;
                  var2 = var26.pack();
                  var3 = Netalyzr.this.new UDPTestArgs(1, 5, var2);
                  var29 = Netalyzr.this.checkUDP(var4, 53, var3);
                  if (var29 == 4) {
                     Netalyzr.this.debug("Sending legitimate DNS packet succeeded.");
                     this.dnsProxy = true;
                     return var29;
                  } else if (var1) {
                     Netalyzr.this.debug("Previous test worked even if this one didn't");
                     return 4;
                  } else {
                     return var29;
                  }
               }
            }
         }

         String getPostResults() {
            return this.dnsProxy ? "\ndnsProxyDetected=true\ndnsLargePackets=" + this.largeDNS + "\n" + this.dnsChanges + "\ndnsMediumPackets=" + this.mediumDNS + "\ndnsSmallPackets=" + this.smallDNS + "\ndnsDirectText=" + this.dnsDirectText + "\ndnsDirectIcsi=" + this.dnsDirectIcsi + "\ndnsDirectIcsi2=" + this.dnsDirectIcsi2 + "\ndnsDirectTruncation=" + this.dnsDirectTruncation + "\ndnsDirectIpv6=" + this.dnsDirectIpv6 + "\ndnsDirectNxdomain=" + this.dnsDirectNxdomain + "\ndnsDirectRecursiveOnly=" + this.dnsDirectRecursiveOnly + "\n" : "dnsLargePackets=" + this.largeDNS + "\ndnsMediumPackets=" + this.mediumDNS + "\ndnsDirectRecursiveOnly=" + this.dnsDirectRecursiveOnly + "\ndnsDirectText=" + this.dnsDirectText + "\ndnsDirectIcsi=" + this.dnsDirectIcsi + "\ndnsDirectIcsi2=" + this.dnsDirectIcsi2 + "\ndnsDirectIpv6=" + this.dnsDirectIpv6 + "\ndnsDirectNxdomain=" + this.dnsDirectNxdomain + "\ndnsDirectTruncation=" + this.dnsDirectTruncation + "\ndnsSmallPackets=" + this.smallDNS + "\n" + this.dnsChanges;
         }
      });
      this.tests.add(new Netalyzr.Test("checkRawDNSTCP") {
         boolean dnsProxy;
         String dnsChanges = "";
         String dnsTCPStatus = "none";

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 30000L;
         }

         int runImpl() throws IOException {
            Netalyzr.this.debug("Checking raw access to TCP DNS by querying for entropy");

            DNSMessage var1;
            DNSMessage var2;
            DNSMessage var3;
            try {
               var1 = new DNSMessage("entropy.rawtest.tcp." + Netalyzr.this.custDnsName, 1, 1);
               var1.rd = true;
               var3 = new DNSMessage("server.rawtest.tcp." + Netalyzr.this.custDnsName, 1, 1);
               var3.rd = true;
               var2 = Netalyzr.this.checkDNSFetchTCP(Netalyzr.this.serverName, var1);
            } catch (DNSMessage.DNSError var11) {
               Netalyzr.this.debug("Caught exception " + var11);
               return 0;
            }

            Netalyzr.this.debug("DNS reply " + var2);
            var2.print();
            if (var2 != null) {
               String var4 = "";

               for(int var5 = 0; var5 < var2.answer.length; ++var5) {
                  Netalyzr.this.debug("Reply " + var5 + " is " + var2.answer[0]);
                  Netalyzr.this.debug("type " + var2.answer[0].rtype);
               }

               this.dnsTCPStatus = "corrupted";
               if (var2.answer[0].rtype == 5) {
                  Netalyzr.this.debug("First answer is the right format");
                  var4 = ((DNSMessage.DNSRdataReference)var2.answer[0].rdata).rdata;
                  this.dnsTCPStatus = "reply";
               }

               Netalyzr.this.debug("Status info is " + var4);
               String[] var13 = var4.split("status");
               boolean var6 = false;
               boolean var7 = false;
               if (var13.length >= 2) {
                  String var8 = var13[1].split("done")[0];

                  try {
                     String var9 = var8.split("ad=")[1].split("-end")[0].replace('-', '.');
                     Netalyzr.this.debug("Address from DNS is " + var9);
                     if (!Netalyzr.this.globalClientAddr.equals("0.0.0.0") && !var9.equals(Netalyzr.this.globalClientAddr)) {
                        Netalyzr.this.debug("The DNS request came to our server from " + var9 + ", but we expected it to come from " + Netalyzr.this.globalClientAddr);
                     } else {
                        Netalyzr.this.debug("Address matches OK");
                        var6 = true;
                     }

                     String var10 = var8.split("id=")[1].split("-end")[0];
                     Netalyzr.this.debug("ID from DNS is " + var10);
                     if (Integer.parseInt(var10) == var1.id) {
                        Netalyzr.this.debug("ID matches OK");
                        var7 = true;
                     } else {
                        Netalyzr.this.debug("This is not the expected ID.");
                        this.dnsChanges = this.dnsChanges + "\ndnsTCPChangedID=" + var10;
                     }
                  } catch (Exception var12) {
                     Netalyzr.this.debug("Failure to parse status line " + var8);
                  }

                  if (!var7 || !var6) {
                     this.dnsTCPStatus = "corrupted";
                     this.dnsChanges = this.dnsChanges + "\ndnsTCPMangled=True";
                     Netalyzr.this.debug("Mangled DNS, so fetching server directly rather than relying on parsing the CNAME");
                     var3 = Netalyzr.this.checkDNSFetchTCP(Netalyzr.this.serverName, var3);
                     Netalyzr.this.debug("Got server string");
                     if (var3 != null) {
                        var3.print();
                     }

                     if (var3 != null && var3.answer.length >= 1 && var3.answer[0].rtype == 1) {
                        if (!((DNSMessage.DNSRdataIP)var3.answer[0].rdata).rdata.getHostAddress().equals(Netalyzr.this.globalClientAddr)) {
                           this.dnsChanges = this.dnsChanges + "\ndnsTCPChangedIP=" + ((DNSMessage.DNSRdataIP)var3.answer[0].rdata).rdata.getHostAddress() + "\n";
                           Netalyzr.this.debug("Changed IP, got" + ((DNSMessage.DNSRdataIP)var3.answer[0].rdata).rdata.getHostAddress());
                        } else {
                           Netalyzr.this.debug("IP not changed");
                        }
                     }

                     this.dnsChanges = this.dnsChanges + "\n";
                  }
               }
            }

            return 4;
         }

         String getPostResults() {
            return "\n" + this.dnsChanges + "\ndnsRawTCPStatus=" + this.dnsTCPStatus + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSResolvers") {
         ResolverData[] resolverInfo;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 2000L;
         }

         int runImpl() {
            Netalyzr.this.debug("Attempting to get DNS resolver addresses");

            try {
               Class var1 = Class.forName("sun.net.dns.ResolverConfiguration");
               Netalyzr.this.debug("Got " + var1);
               Method var2 = var1.getMethod("open", (Class[])null);
               Netalyzr.this.debug("Open method " + var2);
               Method var3 = var1.getMethod("nameservers", (Class[])null);
               Netalyzr.this.debug("Nameservers method " + var3);
               List var4 = (List)var3.invoke(var2.invoke((Object)null, (Object[])null), (Object[])null);
               Netalyzr.this.debug("Servers are " + var4);
               Iterator var5 = var4.iterator();
               int var6 = 0;

               for(this.resolverInfo = new ResolverData[var4.size()]; var5.hasNext(); ++var6) {
                  this.resolverInfo[var6] = new ResolverData((String)var5.next(), "Resolver" + (var6 + 1));
               }

               for(var6 = 0; var6 < this.resolverInfo.length; ++var6) {
                  this.resolverInfo[var6].collectData();
               }

               boolean var7 = false;

               for(var6 = 0; var6 < this.resolverInfo.length; ++var6) {
                  if (this.resolverInfo[var6].live) {
                     var7 = true;
                     break;
                  }
               }

               return !var7 ? 0 : 4;
            } catch (Exception var8) {
               Netalyzr.this.debug("Got Exception " + var8);
               return 0;
            }
         }

         String getPostResults() {
            String var1 = "\nresolverCount=" + this.resolverInfo.length;

            for(int var2 = 0; var2 < this.resolverInfo.length; ++var2) {
               var1 = var1 + this.resolverInfo[var2].getPostResults();
            }

            return var1;
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSRoots") {
         RootData[] rootInfo;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 100L;
         }

         int runImpl() {
            Netalyzr.this.debug("Attempting to identify DNS root servers using CHAOS queries");
            String[] var1 = new String[]{"198.41.0.4", "192.228.79.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"};
            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               this.ignoreResult = true;
               return 0;
            } else {
               class RootData {
                  String name = "";
                  String ip = "";
                  String hostname = "";
                  String facebook = "";
                  String nxdomain = "";
                  boolean live = false;
                  DNSMessage ds;
                  DNSMessage dnskey;
                  DNSMessage nxrecord;

                  void run(String var1, String var2) {
                     this.name = var1;
                     this.ip = var2;
                     Netalyzr.this.debug("Probing root authority " + this.name + " at IP address " + this.ip);
                     DNSMessage var3 = Netalyzr.this.checkDNSFetch(this.ip, "hostname.bind", 16, 3, true, 0);
                     if (var3 != null) {
                        this.live = true;
                     }

                     if (var3 != null && var3.answer.length > 0) {
                        this.hostname = ((DNSMessage.DNSRdataTXT)var3.answer[0].rdata).txt[0];
                        Netalyzr.this.debug("hostname.bind: " + this.hostname);
                     }

                     Netalyzr.this.debug("Querying root for DS (Domain Signature) for .com");
                     this.ds = Netalyzr.this.checkDNSFetch(this.ip, "com", 43, 1, false, 1024, true);
                     Netalyzr.this.debug("Got result for DS to root");
                     Netalyzr.this.debug("Querying root for DNSKEY");
                     this.dnskey = Netalyzr.this.checkDNSFetch(this.ip, "", 48, 1, false, 1024, true);
                     Netalyzr.this.debug("Got DNSKEY result");
                     Netalyzr.this.debug("Querying root for a guarenteed NXDOMAIN");
                     Netalyzr.this.debug("To get NSEC records");
                     this.nxrecord = Netalyzr.this.checkDNSFetch(this.ip, "oanetuhaonetuha.apenutahoeut", 1, 1, false, 1024, true);
                     Netalyzr.this.debug("Got NXRECORD result");
                     int var4;
                     if (this.nxrecord != null) {
                        for(var4 = 0; var4 < this.nxrecord.authority.length; ++var4) {
                           Netalyzr.this.debug("Authority record: " + this.nxrecord.authority[var4].repr());
                        }
                     }

                     var3 = Netalyzr.this.checkDNSFetch(this.ip, "www.facebook.com", 1, 1, true, 0);
                     if (var3 != null) {
                        this.live = true;
                     }

                     Netalyzr.this.debug("Returned value is " + var3);
                     if (var3 != null && var3.answer.length > 0) {
                        for(var4 = 0; var4 < var3.answer.length; ++var4) {
                           if (var3.answer[var4].rtype == 1) {
                              this.facebook = this.facebook + ((DNSMessage.DNSRdataIP)var3.answer[var4].rdata).rdata.getHostAddress();
                           }

                           if (var4 < var3.answer.length - 1) {
                              this.facebook = this.facebook + ",";
                           }
                        }
                     }

                     var3 = Netalyzr.this.checkDNSFetch(this.ip, "www.aoentauhoneth" + Netalyzr.this.rng.nextInt() + "aoeauoet" + Netalyzr.this.rng.nextInt() + "aoeu.com", 1, 1, true, 0);
                     if (var3 != null) {
                        this.live = true;
                     }

                     Netalyzr.this.debug("Returned value is " + var3);
                     if (var3 != null && var3.answer.length > 0) {
                        for(var4 = 0; var4 < var3.answer.length; ++var4) {
                           if (var3.answer[var4].rtype == 1) {
                              this.nxdomain = this.nxdomain + ((DNSMessage.DNSRdataIP)var3.answer[var4].rdata).rdata.getHostAddress();
                           }

                           if (var4 < var3.answer.length - 1) {
                              this.nxdomain = this.nxdomain + ",";
                           }
                        }
                     }

                  }

                  String getPostResults() {
                     if (this.name == null) {
                        return "";
                     } else {
                        String var1 = "\ndnsRoot" + this.name;
                        if (!this.live) {
                           return var1 + "Live=False";
                        } else {
                           try {
                              String var2 = "";

                              for(int var3 = 0; var3 < this.nxrecord.authority.length; ++var3) {
                                 var2 = var2 + this.nxrecord.authority[var3].repr();
                                 if (var3 < this.nxrecord.authority.length - 1) {
                                    var2 = var2 + "..#..";
                                 }
                              }

                              var2 = var2 + "..?.." + this.nxrecord.question[0].qname;
                              String var8 = "";

                              for(int var4 = 0; var4 < this.ds.answer.length; ++var4) {
                                 var8 = var8 + this.ds.answer[var4].repr();
                                 if (var4 < this.ds.answer.length - 1) {
                                    var8 = var8 + "..#..";
                                 }
                              }

                              String var9 = "";

                              for(int var5 = 0; var5 < this.dnskey.answer.length; ++var5) {
                                 var9 = var9 + this.dnskey.answer[var5].repr();
                                 if (var5 < this.dnskey.answer.length - 1) {
                                    var9 = var9 + "..#..";
                                 }
                              }

                              return var1 + "Live=True" + var1 + "NSEC=" + Netalyzr.this.safeUrlEncode(var2, "UTF-8") + var1 + "DS=" + Netalyzr.this.safeUrlEncode(var8, "UTF-8") + var1 + "DNSKEY=" + Netalyzr.this.safeUrlEncode(var9, "UTF-8") + var1 + "IP=" + this.ip + var1 + "Hostname=" + Netalyzr.this.safeUrlEncode(this.hostname, "UTF-8") + var1 + "Nxdomain=" + this.nxdomain + var1 + "Facebook=" + this.facebook;
                           } catch (UnsupportedEncodingException var6) {
                              Netalyzr.this.debug("Got unsupported IO Exception");
                              return "";
                           } catch (Exception var7) {
                              Netalyzr.this.debug("Caught exception in rendering");
                              Netalyzr.this.debugStackTrace(var7);
                              return "";
                           }
                        }
                     }
                  }
               }

               this.rootInfo = new RootData[var1.length];

               for(int var2 = 0; var2 < var1.length; ++var2) {
                  this.rootInfo[var2] = new RootData();
                  this.rootInfo[var2].run("" + (char)(65 + var2), var1[var2]);
               }

               return 4;
            }
         }

         String getPostResults() {
            String var1 = "";
            if (this.ignoreResult) {
               return "";
            } else {
               for(int var2 = 0; var2 < this.rootInfo.length; ++var2) {
                  if (this.rootInfo[var2] != null) {
                     var1 = var1 + "\n" + this.rootInfo[var2].getPostResults() + "\n";
                  }
               }

               return var1;
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSNAT") {
         ArrayList candidateNats = new ArrayList();

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 2000L;
            this.ignoreResult = true;
         }

         int runImpl() throws IOException {
            if (Netalyzr.this.foundNatAddrs.size() == 0 && !Netalyzr.this.isNatted()) {
               this.ignoreResult = true;
               Netalyzr.this.debug("Probably not NATted, ignoring");
               return 0;
            } else {
               int var3;
               if (Netalyzr.this.foundNatAddrs.size() == 0) {
                  Netalyzr.this.debug("Global/local address discrepancy suggests NAT, but UPnP did not find it. Guessing.");
                  String[] var1 = Netalyzr.this.localClientAddr.split("\\.");
                  String var2 = var1[0] + "." + var1[1] + "." + var1[2];
                  this.candidateNats.add(new null.NatDevice(var2 + ".1"));
                  this.candidateNats.add(new null.NatDevice(var2 + ".254"));
               } else {
                  Netalyzr.this.debug("Using UPnP-determined address(es)");

                  for(var3 = 0; var3 < Netalyzr.this.foundNatAddrs.size(); ++var3) {
                     this.candidateNats.add(new null.NatDevice((String)Netalyzr.this.foundNatAddrs.get(var3)));
                  }
               }

               for(var3 = 0; var3 < this.candidateNats.size(); ++var3) {
                  this.probeNat((null.NatDevice)this.candidateNats.get(var3), var3);
               }

               return 4;
            }
         }

         void probeNat(null.NatDevice var1, int var2) throws IOException {
            class ResolverData {
               boolean live = false;
               String resolver = "";
               String fromIP = "";
               String resultsName = "";
               String dnsText = "False";
               String dnsTextMedium = "False";
               String dnsTextLarge = "False";
               String dnsTextLargeEDNS = "False";
               String dnsIcsi = "False";
               String dnsIpv6 = "False";
               String dnsEdns = "False";
               String dnsDNSSECValidation = "False";
               String nxdomain = "";
               String facebook = "";
               String rootFacebook = "";
               String dnsVersion = "";
               String dnsHostname = "";
               String dnsAuthors = "";
               String dnsCopyright = "";
               String uncachedLatency = "";
               String cachedLatency = "";
               DNSMessage com_ds;
               DNSMessage root_dnskey;
               DNSMessage root_nxdomain;
               DNSMessage com_nxdomain;
               DNSMessage com_rrsig;

               ResolverData(String var2, String var3) {
                  this.resolver = var2;
                  this.resultsName = var3;
               }

               ResolverData collectData() {
                  Netalyzr.this.debug("Collecting data on resolver " + this.resolver);
                  DNSMessage var1 = Netalyzr.this.checkDNSFetch(this.resolver, "server." + Netalyzr.this.custDnsName, 1, 1, true, 0);
                  if (var1 != null && var1.answer.length > 0) {
                     this.live = true;
                     this.fromIP = ((DNSMessage.DNSRdataIP)var1.answer[0].rdata).rdata.getHostAddress();
                     Netalyzr.this.debug("Resolver is live, request came from IP" + this.fromIP);
                     Netalyzr.this.debug("Obtaining resolver properties");
                     var1 = Netalyzr.this.checkDNSFetch(this.resolver, "version.bind", 16, 3, true, 0);
                     if (var1 != null && var1.answer.length > 0) {
                        this.dnsVersion = ((DNSMessage.DNSRdataTXT)var1.answer[0].rdata).txt[0];
                        Netalyzr.this.debug("version.bind: " + this.dnsVersion);
                     }

                     var1 = Netalyzr.this.checkDNSFetch(this.resolver, "copyright.bind", 16, 3, true, 0);
                     if (var1 != null && var1.answer.length > 0) {
                        this.dnsCopyright = ((DNSMessage.DNSRdataTXT)var1.answer[0].rdata).txt[0];
                        Netalyzr.this.debug("copyright.bind: " + this.dnsCopyright);
                     }

                     var1 = Netalyzr.this.checkDNSFetch(this.resolver, "hostname.bind", 16, 3, true, 0);
                     if (var1 != null && var1.answer.length > 0) {
                        this.dnsHostname = ((DNSMessage.DNSRdataTXT)var1.answer[0].rdata).txt[0];
                        Netalyzr.this.debug("hostname.bind: " + this.dnsHostname);
                     }

                     var1 = Netalyzr.this.checkDNSFetch(this.resolver, "authors.bind", 16, 3, true, 0);
                     int var2;
                     String[] var3;
                     int var4;
                     if (var1 != null && var1.answer.length > 0) {
                        try {
                           for(var2 = 0; var2 < var1.answer.length; ++var2) {
                              var3 = ((DNSMessage.DNSRdataTXT)var1.answer[var2].rdata).txt;

                              for(var4 = 0; var4 < var3.length; ++var4) {
                                 this.dnsAuthors = this.dnsAuthors + var3[var4];
                                 if (var4 != var3.length - 1 || var2 != var1.answer.length - 1) {
                                    this.dnsAuthors = this.dnsAuthors + ", ";
                                 }
                              }
                           }
                        } catch (Exception var11) {
                           Netalyzr.this.debug("Caught exception " + var11);
                        }

                        Netalyzr.this.debug("authors.bind: " + this.dnsAuthors);
                     }

                     Netalyzr.this.debug("Checking performance of resolver");
                     Netalyzr.this.debug("By querying for the same name twice");

                     for(var2 = 0; var2 < 10; ++var2) {
                        long var12 = (new Date()).getTime();
                        String var5 = "www." + Netalyzr.this.rng.nextInt() + "." + Netalyzr.this.rng.nextInt() + "." + Netalyzr.this.custDnsName;
                        Netalyzr.this.checkDNSFetch(this.resolver, var5, 1, 1, true, 0);
                        long var6 = (new Date()).getTime() - var12;
                        this.uncachedLatency = this.uncachedLatency + var6 + ",";
                        var12 = (new Date()).getTime();
                        Netalyzr.this.checkDNSFetch(this.resolver, var5, 1, 1, true, 0);
                        var6 = (new Date()).getTime() - var12;
                        this.cachedLatency = this.cachedLatency + var6 + ",";
                     }

                     this.uncachedLatency = this.uncachedLatency.substring(0, this.uncachedLatency.length() - 1);
                     this.cachedLatency = this.cachedLatency.substring(0, this.cachedLatency.length() - 1);
                     Netalyzr.this.debug("Checking for NXDOMAIN wildcarding");

                     try {
                        var1 = Netalyzr.this.checkDNSFetch(this.resolver, "www.aoentauhoneth" + Netalyzr.this.rng.nextInt() + "aoeauoet" + Netalyzr.this.rng.nextInt() + "aoeu.com", 1, 1, true, 0);
                        Netalyzr.this.debug("Returned value is " + var1);
                        if (var1 != null && var1.answer.length > 0) {
                           for(var2 = 0; var2 < var1.answer.length; ++var2) {
                              this.nxdomain = this.nxdomain + ((DNSMessage.DNSRdataIP)var1.answer[var2].rdata).rdata.getHostAddress();
                              if (var2 < var1.answer.length - 1) {
                                 this.nxdomain = this.nxdomain + ",";
                              }
                           }
                        }
                     } catch (Exception var10) {
                        Netalyzr.this.debug("Got exception " + var10);
                     }

                     String[] var14;
                     try {
                        Netalyzr.this.debug("First looking up Facebook");
                        Netalyzr.this.debug("This has a short TTL");
                        var1 = Netalyzr.this.checkDNSFetch(this.resolver, "www.facebook.com", 1, 1, true, 0);
                        Netalyzr.this.debug("Returned value is " + var1);
                        if (var1 != null && var1.answer.length > 0) {
                           for(var2 = 0; var2 < var1.answer.length; ++var2) {
                              if (var1.answer[var2].rtype == 1) {
                                 this.facebook = this.facebook + ((DNSMessage.DNSRdataIP)var1.answer[var2].rdata).rdata.getHostAddress();
                              }

                              if (var2 < var1.answer.length - 1) {
                                 this.facebook = this.facebook + ",";
                              }
                           }
                        }

                        var14 = new String[]{"aaa", "aab", "aac", "aad", "aae", "aaf", "aag", "aah", "aai", "aaj"};

                        for(int var13 = 0; var13 < var14.length; ++var13) {
                           Netalyzr.this.debug("Looking up www.facebook.com." + var14[var13]);
                           var1 = Netalyzr.this.checkDNSFetch(this.resolver, "www.facebook.com." + var14[var13], 1, 1, true, 0);
                           Netalyzr.this.debug("Returned value is " + var1);
                           if (var1 != null && var1.answer.length > 0) {
                              for(var4 = 0; var4 < var1.answer.length; ++var4) {
                                 if (var1.answer[var4].rtype == 1) {
                                    this.rootFacebook = this.rootFacebook + ((DNSMessage.DNSRdataIP)var1.answer[var4].rdata).rdata.getHostAddress();
                                    this.rootFacebook = this.rootFacebook + ",";
                                 }
                              }
                           }
                        }

                        if (!this.rootFacebook.equals("") && this.rootFacebook.charAt(this.rootFacebook.length() - 1) == ',') {
                           this.rootFacebook = this.rootFacebook.substring(0, this.rootFacebook.length() - 1);
                        }
                     } catch (Exception var9) {
                        Netalyzr.this.debug("Got exception " + var9);
                     }

                     Netalyzr.this.debug("Checking for DNSSEC validation via www.dnssec-failed.org");
                     var1 = Netalyzr.this.checkDNSFetch(this.resolver, "www.dnssec-failed.org", 1, 1, true, 0);
                     if (var1 != null && var1.answer.length > 0) {
                        Netalyzr.this.debug("A valid answer was returned, no DNSSEC validation");
                     } else {
                        this.dnsDNSSECValidation = "True";
                        Netalyzr.this.debug("DNSSEC presumably validated as returned value was " + var1);
                     }

                     Netalyzr.this.debug("Checking for DNSSEC records for DS for com");
                     this.com_ds = Netalyzr.this.checkDNSFetch(this.resolver, "com", 43, 1, true, 1024, true);
                     Netalyzr.this.debug("Checking for DNSSEC records for DNSKEY for .");
                     this.root_dnskey = Netalyzr.this.checkDNSFetch(this.resolver, "", 48, 1, true, 1024, true);
                     Netalyzr.this.debug("Checking for DNSSEC records for NXDOMAIN for .");
                     this.root_nxdomain = Netalyzr.this.checkDNSFetch(this.resolver, "aoentauhoentuhaneuht.aoentahonetuh", 1, 1, true, 1024, true);
                     Netalyzr.this.debug("Checking for DNSSEC records for NXDOMAIN for com");
                     this.com_nxdomain = Netalyzr.this.checkDNSFetch(this.resolver, "www.aoentaoeuhoneth" + Netalyzr.this.rng.nextInt() + "aoeauoet" + Netalyzr.this.rng.nextInt() + "aoeu.com", 1, 1, true, 1024, true);
                     Netalyzr.this.debug("Checking for RRSIG fetch");
                     Netalyzr.this.debug("With no EDNS");
                     this.com_rrsig = Netalyzr.this.checkDNSFetch(this.resolver, "com", 46, 1, true, 0);
                     Netalyzr.this.debug("Checking if TXT records are received OK");
                     var14 = new String[]{"this is a test", "of two TXT records"};
                     this.dnsText = Netalyzr.this.checkDNSFetch(this.resolver, "txt.resolver1." + this.resultsName + "." + Netalyzr.this.custDnsName, 16, true, (String[])var14) ? "True" : "False";
                     Netalyzr.this.debug("Checking if ICSI records are received OK");
                     this.dnsIcsi = Netalyzr.this.checkDNSFetch(this.resolver, "txt.resolver2." + this.resultsName + "." + Netalyzr.this.custDnsName, 1169, true, (String[])var14) ? "True" : "False";
                     var3 = new String[]{"This TXT record should be ignored"};
                     Netalyzr.this.debug("Checking for a medium sized record");
                     this.dnsTextMedium = Netalyzr.this.checkDNSFetch(this.resolver, "txtpadding_1300.resolverb2." + this.resultsName + "." + Netalyzr.this.custDnsName, 16, true, (String[])var3) ? "True" : "False";
                     Netalyzr.this.debug("Checking for a large sized record");
                     this.dnsTextLarge = Netalyzr.this.checkDNSFetch(this.resolver, "txtpadding_3300.resolverb1." + this.resultsName + "." + Netalyzr.this.custDnsName, 16, true, (String[])var3) ? "True" : "False";
                     Netalyzr.this.debug("Checking for a large sized record with EDNS0");
                     this.dnsTextLargeEDNS = Netalyzr.this.checkDNSFetch(this.resolver, "txtpadding_3300.resolverb1." + this.resultsName + "." + Netalyzr.this.custDnsName, 16, true, (String[])var3, 4000) ? "True" : "False";
                     Netalyzr.this.debug("Checking if IPv6 records are received OK");

                     try {
                        this.dnsIpv6 = Netalyzr.this.checkDNSFetch(this.resolver, "ipv6-node.resolver3." + this.resultsName + "." + Netalyzr.this.custDnsName, 28, true, (InetAddress)((Inet6Address)InetAddress.getByName(Netalyzr.this.ipv6Server))) ? "True" : "False";
                     } catch (UnknownHostException var8) {
                        Netalyzr.this.debug("Got unknown host exception " + var8);
                     }

                     Netalyzr.this.debug("Checking if the resolver can handle an EDNS query");
                     this.dnsEdns = Netalyzr.this.checkDNSFetch(this.resolver, "www.resolver4." + this.resultsName + "." + Netalyzr.this.custDnsName, 1, true, (InetAddress)Netalyzr.this.trueIP, 4000) ? "True" : "False";
                     return this;
                  } else {
                     Netalyzr.this.debug("Resolver is not live");
                     return this;
                  }
               }

               String getPostResults() {
                  String var1 = "\ndns" + this.resultsName;
                  String var2 = "";
                  if (!this.live) {
                     var2 = var1 + "Live=False" + var1 + "IP=" + this.resolver;
                     return var2;
                  } else {
                     try {
                        String var3 = "";

                        for(int var4 = 0; var4 < this.com_ds.answer.length; ++var4) {
                           var3 = var3 + this.com_ds.answer[var4].repr();
                           if (var4 < this.com_ds.answer.length - 1) {
                              var3 = var3 + "..#..";
                           }
                        }

                        String var11 = "";

                        for(int var5 = 0; var5 < this.root_dnskey.answer.length; ++var5) {
                           var11 = var11 + this.root_dnskey.answer[var5].repr();
                           if (var5 < this.root_dnskey.answer.length - 1) {
                              var11 = var11 + "..#..";
                           }
                        }

                        String var12 = "";

                        for(int var6 = 0; var6 < this.root_nxdomain.authority.length; ++var6) {
                           var12 = var12 + this.root_nxdomain.authority[var6].repr();
                           if (var6 < this.root_nxdomain.authority.length - 1) {
                              var12 = var12 + "..#..";
                           }
                        }

                        var12 = var12 + "..?.." + this.root_nxdomain.question[0].qname;
                        String var13 = "";

                        for(int var7 = 0; var7 < this.com_nxdomain.authority.length; ++var7) {
                           var13 = var13 + this.com_nxdomain.authority[var7].repr();
                           if (var7 < this.com_nxdomain.authority.length - 1) {
                              var13 = var13 + "..#..";
                           }
                        }

                        var13 = var13 + "..?.." + this.com_nxdomain.question[0].qname;
                        String var14 = "";

                        for(int var8 = 0; var8 < this.com_rrsig.answer.length; ++var8) {
                           var14 = var14 + this.com_rrsig.answer[var8].repr();
                           if (var8 < this.com_rrsig.answer.length - 1) {
                              var14 = var14 + "..#..";
                           }
                        }

                        var2 = var1 + "Live=True" + var1 + "FromIP=" + this.fromIP + var1 + "UncachedLatency=" + this.uncachedLatency + var1 + "CachedLatency=" + this.cachedLatency + var1 + "IP=" + this.resolver + var1 + "Text=" + this.dnsText + var1 + "TextMedium=" + this.dnsTextMedium + var1 + "TextLarge=" + this.dnsTextLarge + var1 + "TextLargeEDNS=" + this.dnsTextLargeEDNS + var1 + "Icsi=" + this.dnsIcsi + var1 + "Ipv6=" + this.dnsIpv6 + var1 + "Edns=" + this.dnsEdns + var1 + "DNSSECValidation=" + this.dnsDNSSECValidation + var1 + "Hostname=" + Netalyzr.this.safeUrlEncode(this.dnsHostname, "UTF-8") + var1 + "Version=" + Netalyzr.this.safeUrlEncode(this.dnsVersion, "UTF-8") + var1 + "Copyright=" + Netalyzr.this.safeUrlEncode(this.dnsCopyright, "UTF-8") + var1 + "Authors=" + Netalyzr.this.safeUrlEncode(this.dnsAuthors, "UTF-8") + var1 + "Nxdomain=" + this.nxdomain + var1 + "Facebook=" + this.facebook + var1 + "RootFacebook=" + this.rootFacebook + var1 + "ComDS=" + Netalyzr.this.safeUrlEncode(var3, "UTF-8") + var1 + "ComRRSIG=" + Netalyzr.this.safeUrlEncode(var14, "UTF-8") + var1 + "RootDNSKEY=" + Netalyzr.this.safeUrlEncode(var11, "UTF-8") + var1 + "RootNXDOMAIN=" + Netalyzr.this.safeUrlEncode(var12, "UTF-8") + var1 + "ComNXDOMAIN=" + Netalyzr.this.safeUrlEncode(var13, "UTF-8") + "\n";
                     } catch (UnsupportedEncodingException var9) {
                        Netalyzr.this.debug("Caught encoding exception " + var9);
                     } catch (Exception var10) {
                        Netalyzr.this.debug("Caught other exception " + var10);
                     }

                     return var2;
                  }
               }
            }

            var1.resData = new ResolverData(var1.addr, "Nat" + var2);
            var1.resData.collectData();
            if (!var1.resData.live) {
               Netalyzr.this.debug("No live NAT found at " + var1.addr + " via DNS");
            } else {
               var1.isDnsProxy = true;
               this.ignoreResult = false;
               Netalyzr.this.debug("Checking for 2wire behavior");
               if (Netalyzr.this.checkDNSFetch(var1.addr, "gateway.2wire.net", 1, true, (InetAddress)InetAddress.getByName(var1.addr))) {
                  Netalyzr.this.debug("Gateway " + var1.addr + " is 2wire device");
                  DNSMessage var3 = Netalyzr.this.checkDNSFetch(var1.addr, "netalyzr.gateway.2wire.net", 1, true, 0);
                  if (var3 != null) {
                     Netalyzr.this.debug("Got response data");
                     Netalyzr.this.debug("RCODE is " + var3.rcode);
                     var1.twoWireRCode = var3.rcode;
                  }
               }

            }
         }

         String getPostResults() {
            StringBuffer var1 = new StringBuffer();

            for(int var2 = 0; var2 < this.candidateNats.size(); ++var2) {
               null.NatDevice var3 = (null.NatDevice)this.candidateNats.get(var2);
               String var4 = Integer.toString(var2);
               var1.append("\ndnsNat" + var4 + "Addr=" + var3.addr);
               var1.append("\ndnsNat" + var4 + "IsDnsProxy=" + var3.isDnsProxy);
               if (var3.isDnsProxy) {
                  var1.append("\ndnsNat" + var4 + "TwoWireRCode=" + var3.twoWireRCode);
                  var1.append(var3.resData.getPostResults());
               }
            }

            return var1.toString();
         }

         class NatDevice {
            String addr;
            ResolverData resData;
            boolean isDnsProxy = false;
            int twoWireRCode = -1;

            NatDevice(String var2) {
               this.addr = var2;
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSIntegrity") {
         public static final int TEST_ERROR_ADDR_MISMATCH = 64;
         String resolvedAddr;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() throws IOException {
            try {
               InetAddress var1 = InetAddress.getByName("www." + Netalyzr.this.custDnsName);
               this.resolvedAddr = var1.getHostAddress();
               Netalyzr.this.debug("Custom server IP is " + this.resolvedAddr + ", should be " + Netalyzr.this.custDnsAddr);
               if (!this.resolvedAddr.equals(Netalyzr.this.custDnsAddr)) {
                  InetAddress.getByName("mitm." + Netalyzr.this.custDnsName);
                  return 66;
               } else {
                  return 4;
               }
            } catch (UnknownHostException var2) {
               return 10;
            }
         }

         String getPostResults() {
            return "\nresAddr=" + this.resolvedAddr + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSServer") {
         String localResolver;
         String resolverList;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 4000L;
         }

         int runImpl() throws IOException {
            Netalyzr.this.debug("First doing a lookup which we can correlate later");
            Netalyzr.this.isTrueName("server.id." + Netalyzr.this.agentID.replace('-', '.') + ".done." + Netalyzr.this.custDnsName);
            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               this.ignoreResult = true;
               return 0;
            } else {
               try {
                  Netalyzr.this.debug("Trying to get address server.server" + Netalyzr.this.custDnsName);
                  InetAddress var1 = InetAddress.getByName("server.server" + Netalyzr.this.custDnsName);
                  this.localResolver = var1.getHostAddress();
                  Netalyzr.this.debug("Successfully got address: " + this.localResolver);
                  this.resolverList = this.localResolver;
                  Netalyzr.this.addrLookups.add(this.localResolver);
               } catch (UnknownHostException var4) {
                  return 10;
               }

               Netalyzr.this.debug("Trying to get a local resolver list");

               for(int var5 = 0; var5 < 5; ++var5) {
                  try {
                     InetAddress var2 = InetAddress.getByName("server.server" + var5 + Netalyzr.this.custDnsName);
                     this.resolverList = this.resolverList + "," + var2.getHostAddress();
                  } catch (UnknownHostException var3) {
                  }
               }

               return 4;
            }
         }

         String getPostResults() {
            String var1 = "\nlocalRes=" + this.localResolver + "\n";
            var1 = var1 + "localResList=" + this.resolverList + "\n";
            return var1;
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSRand") {
         public static final int TEST_ERROR_NONRAND = 64;
         int NUM_CONNS;
         public static final int REPORT_CONNS = 10;
         int[] ports;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.NUM_CONNS = 12;
            this.ports = new int[this.NUM_CONNS];
            this.timeout = 30000L;
         }

         int getPort(int var1) {
            try {
               String var2 = "port." + var1 + "." + Netalyzr.this.custDnsName;
               Netalyzr.this.debug("Resolving " + var2);
               InetAddress var3 = InetAddress.getByName(var2);
               String var4 = var3.getHostAddress();
               String[] var5 = var4.split("\\.");
               int var6 = Netalyzr.this.parseInt(var5[2]) * 256 + Netalyzr.this.parseInt(var5[3]);
               Netalyzr.this.debug("Port is " + var6);
               return var6;
            } catch (UnknownHostException var7) {
               return 0;
            }
         }

         int unsignedRandomCheck() {
            for(int var1 = 0; var1 < 12; ++var1) {
               Netalyzr.this.isTrueName("dns-rand-set." + var1 + ".random" + Netalyzr.this.custDnsName);
            }

            return Netalyzr.this.isTrueName("dns-rand-check.random" + Netalyzr.this.custDnsName) ? 4 : 66;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoRestrictedLookup) {
               this.ignoreResult = true;
               return 0;
            } else if (!Netalyzr.this.canDoUnrestrictedLookup) {
               return this.unsignedRandomCheck();
            } else {
               int var1 = 0;
               int var2 = 0;
               boolean var3 = false;

               int var4;
               for(var4 = 0; var4 < this.NUM_CONNS; ++var4) {
                  this.ports[var4] = this.getPort(var4);
               }

               for(var4 = 1; var4 < this.NUM_CONNS; ++var4) {
                  if (this.ports[var4] == 0) {
                     ++var1;
                  } else if (this.ports[var4] == this.ports[var4 - 1]) {
                     ++var1;
                  } else if (this.ports[var4] == this.ports[var4 - 1] + var2) {
                     ++var1;
                  }

                  var2 = this.ports[var4] - this.ports[var4 - 1];
               }

               if (var1 > 6) {
                  return 66;
               } else {
                  return 4;
               }
            }
         }

         String getPostResults() {
            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               return "";
            } else {
               String var1 = "\nDNSPorts=";
               int var2 = 10;
               if (var2 > this.NUM_CONNS) {
                  var2 = this.NUM_CONNS;
               }

               for(int var3 = 0; var3 < var2; ++var3) {
                  var1 = var1 + this.ports[var3];
                  if (var3 < var2 - 1) {
                     var1 = var1 + ",";
                  }
               }

               return var1 + "\n";
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkDNSWildcard") {
         public static final int TEST_ERROR_NX_WILDCARDED = 64;
         String cmoSubstitution;
         String orgSubstitution;
         String notWWWSubstitution;
         String nxdomainICIRSubstitution;
         String servfailSubstitution;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.cmoSubstitution = "";
            this.orgSubstitution = "";
            this.notWWWSubstitution = "";
            this.nxdomainICIRSubstitution = "";
            this.servfailSubstitution = "";
            this.timeout = 5000L;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoUnrestrictedLookup) {
               this.ignoreResult = true;
               return 0;
            } else {
               try {
                  String var1 = "www.aoeutnh" + Netalyzr.this.rng.nextInt() + "aoeuaoe" + Netalyzr.this.rng.nextInt() + "aoe.com";
                  Netalyzr.this.debug("Checking for NX Wildcarding");
                  Netalyzr.this.debug("Looking up " + var1);
                  InetAddress var2 = InetAddress.getByName(var1);
                  Netalyzr.this.dnsNxAddr = var2.getHostAddress();
                  Netalyzr.this.addrLookups.add(Netalyzr.this.dnsNxAddr);
                  Netalyzr.this.debug("Exploring detected NXDOMAIN wildcarding in more detail");
                  String var3 = var1;

                  try {
                     var1 = "www.yahoo.cmo";
                     Netalyzr.this.debug("Looking up " + var1);
                     var2 = InetAddress.getByName(var1);
                     this.cmoSubstitution = var2.getHostAddress();
                     Netalyzr.this.debug("This host returns www.yahoo.cmo as " + this.cmoSubstitution);
                  } catch (UnknownHostException var14) {
                     Netalyzr.this.debug("Domain properly reported as an error");
                  }

                  try {
                     var1 = "www.aoeutnh" + Netalyzr.this.rng.nextInt() + "aoeuaoe" + Netalyzr.this.rng.nextInt() + "aoea.org";
                     Netalyzr.this.debug("Looking up " + var1);
                     var2 = InetAddress.getByName(var1);
                     this.orgSubstitution = var2.getHostAddress();
                     Netalyzr.this.debug("This host returns " + var1 + " as " + this.orgSubstitution);
                  } catch (UnknownHostException var13) {
                     Netalyzr.this.debug("Domain properly reported as an error");
                  }

                  try {
                     var1 = "fubar.eaoeutnh" + Netalyzr.this.rng.nextInt() + "aoeuaoe" + Netalyzr.this.rng.nextInt() + "aoea.com";
                     Netalyzr.this.debug("Looking up " + var1);
                     var2 = InetAddress.getByName(var1);
                     this.notWWWSubstitution = var2.getHostAddress();
                     Netalyzr.this.debug("This host returns " + var1 + " as " + this.notWWWSubstitution);
                  } catch (UnknownHostException var12) {
                     Netalyzr.this.debug("Domain properly reported as an error");
                  }

                  try {
                     var1 = "nxdomain.eoeo.aoeu." + Netalyzr.this.rng.nextInt() + "aoeuaoe." + Netalyzr.this.netalyzrDomain;
                     Netalyzr.this.debug("Looking up " + var1);
                     var2 = InetAddress.getByName(var1);
                     this.nxdomainICIRSubstitution = var2.getHostAddress();
                     Netalyzr.this.debug("This host returns " + var1 + " as " + this.nxdomainICIRSubstitution);
                  } catch (UnknownHostException var11) {
                     Netalyzr.this.debug("Domain properly reported as an error");
                  }

                  try {
                     var1 = "servfail.aoentuhaoenth." + Netalyzr.this.rng.nextInt() + "aoeueaaoe." + Netalyzr.this.netalyzrDomain;
                     Netalyzr.this.debug("Looking up " + var1);
                     var2 = InetAddress.getByName(var1);
                     this.servfailSubstitution = var2.getHostAddress();
                     Netalyzr.this.debug("This host returns server failure as " + this.cmoSubstitution);
                  } catch (UnknownHostException var10) {
                     Netalyzr.this.debug("Domain properly reported as an error");
                  }

                  try {
                     this.idleMsg = Netalyzr.this.getLocalString("checkDNSWildcardTypos");
                     Netalyzr.this.shell.enableRedraw();
                     String var4 = "GET / HTTP/1.1\r\nHost: " + var3 + "\r\nUser-Agent: " + Netalyzr.this.userAgent + "\r\nAccept: " + Netalyzr.this.accept + "\r\nAccept-Language: " + Netalyzr.this.acceptLanguage + "\r\nAccept-Encoding: \r\nAccept-Charset: " + Netalyzr.this.acceptCharset + "\r\nConnection: close\r\n\r\n";
                     Netalyzr.HttpResponse var5 = Netalyzr.this.new HttpResponse();
                     Netalyzr.this.debug("Fetching http://" + var3 + " ...");
                     int var6 = Netalyzr.this.checkRawHTTP((String)Netalyzr.this.dnsNxAddr, 80, var4, var5);
                     byte[] var7 = var5.getRawContent();
                     int var8 = var7 != null ? var7.length : 0;
                     if (var6 == 4) {
                        Netalyzr.this.debug("Fetch succeeded: " + var8 + " bytes retrieved.");
                     } else if (var6 == 66) {
                        Netalyzr.this.debug("Fetch failed with HTTP format violation: " + var8 + " bytes retrieved.");
                     } else {
                        Netalyzr.this.debug("Fetch failed with unknown error: " + var8 + " bytes retrieved.");
                     }

                     if (var7 != null) {
                        Netalyzr.this.doHTTPPost("http://" + Netalyzr.this.getHTTPServerName() + "/upload/id=" + Netalyzr.this.agentID + "/key=nxpage", new String(var7));
                        Netalyzr.this.debug("Successfully posted NXDOMAIN content");
                     }
                  } catch (Exception var9) {
                     Netalyzr.this.debug("Failed to fetch URL: exception " + var9);
                  }

                  Netalyzr.this.debug("Returning 66");
                  return 66;
               } catch (UnknownHostException var15) {
                  Netalyzr.this.debug("No NXDOMAIN wildcarding detected.");
                  return 4;
               }
            }
         }

         String getPostResults() {
            String var1 = "";
            if (Netalyzr.this.dnsNxAddr.length() > 0) {
               var1 = var1 + "\nnxAddr=" + Netalyzr.this.dnsNxAddr;
            }

            if (this.cmoSubstitution.length() > 0) {
               var1 = var1 + "\ncmoAddr=" + this.cmoSubstitution;
            }

            if (this.orgSubstitution.length() > 0) {
               var1 = var1 + "\norgAddr=" + this.orgSubstitution;
            }

            if (this.notWWWSubstitution.length() > 0) {
               var1 = var1 + "\nnotWWWAddr=" + this.notWWWSubstitution;
            }

            if (this.servfailSubstitution.length() > 0) {
               var1 = var1 + "\nservfailAddr=" + this.servfailSubstitution;
            }

            if (this.nxdomainICIRSubstitution.length() > 0) {
               var1 = var1 + "\nnxdomainICIRAddr=" + this.nxdomainICIRSubstitution;
            }

            return var1 + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkMTUV6") {
         int sendMTU;
         int recvMTU;
         String pathMTUProblem;
         String bottleneckIP;
         String v6SendFragments;
         String v6ReceiveFragments;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.pathMTUProblem = "false";
            this.bottleneckIP = "";
            this.v6SendFragments = "";
            this.v6ReceiveFragments = "";
         }

         int runImpl() throws IOException {
            int var1 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("FRAGMENT_ECHO_PORT_V6"));
            int var2 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_BUFFER_PORT"));
            String var3 = "ipv6-node." + Netalyzr.this.custDnsName;
            if (Netalyzr.this.canDoRawUDP && Netalyzr.this.canDoV6) {
               this.sendMTU = -1;
               this.pathMTUProblem = "False";

               String var6;
               for(var6 = "000.000 1 0 "; var6.length() < 2000; var6 = var6 + ".") {
               }

               this.v6SendFragments = "False";
               Netalyzr.this.debug("Testing the ability to send a large UDP packet (2000 bytes) over IPv6");
               Netalyzr.UDPTestArgs var5 = Netalyzr.this.new UDPTestArgs(1, 10, var6.getBytes());
               Netalyzr.this.checkUDP(var3, var2, var5);
               if (Netalyzr.this.checkUDP(var3, var2, var5) == 4) {
                  Netalyzr.this.debug("Can send UDP fragments successfully");
                  this.v6SendFragments = "True";
               } else {
                  Netalyzr.this.debug("Can't send UDP fragments");
                  this.pathMTUProblem = "True";
               }

               var6 = "000.000 2 2000 .";
               this.v6ReceiveFragments = "False";
               Netalyzr.this.debug("Testing the ability to receive a large UDP packet (2000 bytes) over IPv6");
               var5 = Netalyzr.this.new UDPTestArgs(1, 10, var6.getBytes());
               if (Netalyzr.this.checkUDP(var3, var2, var5) == 4) {
                  Netalyzr.this.debug("Can receive UDP fragments successfully");
                  this.v6ReceiveFragments = "True";
               } else {
                  Netalyzr.this.debug("Can't receive UDP fragments");
                  this.pathMTUProblem = "True";
               }

               String var7 = "fragment ";

               for(int var8 = 0; var8 < 200; ++var8) {
                  var7 = var7 + "1234567890";
               }

               Netalyzr.this.debug("Attempting to send a packet with");
               Netalyzr.this.debug("fragmentation of " + var7.length() + " bytes");
               Netalyzr.UDPTestArgs var4 = Netalyzr.this.new UDPTestArgs(1, 10, var7.getBytes());
               byte[] var12 = Netalyzr.this.getUDPData(var3, var1, var4);
               if (var12 != null) {
                  Netalyzr.this.debug("Got a reply back, so working");
                  this.sendMTU = Netalyzr.this.parseInt(new String(var12));
                  Netalyzr.this.debug("Send packet MTU is " + this.sendMTU);
               } else {
                  Netalyzr.this.debug("No reply back");
               }

               Netalyzr.this.v6SendMTU = this.sendMTU;
               Netalyzr.this.debug("Now looking for the receive MTU. Trying 1500 first");
               var7 = "mtu 1500 64";
               Netalyzr.this.debug("MSG: " + var7);
               var4 = Netalyzr.this.new UDPTestArgs(1, 10, var7.getBytes());
               var12 = Netalyzr.this.getUDPData(var3, var1, var4);
               if (var12 == null) {
                  Netalyzr.this.debug("No data received, so a potential path MTU problem");
                  this.pathMTUProblem = "True";
               } else {
                  if (!(new String(var12)).startsWith("bad")) {
                     Netalyzr.this.debug("Path MTU is >= 1500B");
                     this.recvMTU = 1500;
                     return 4;
                  }

                  Netalyzr.this.debug("Response is " + new String(var12));
                  Netalyzr.this.debug("Path MTU is <1500B");
                  this.bottleneckIP = (new String(var12)).split(" ")[2];
               }

               Netalyzr.this.debug("Beginning binary search to find the path MTU");
               int var9 = 0;
               int var10 = 1500;

               for(int var11 = (var10 - var9) / 2 + var9; var9 < var10 - 1; var11 = (var10 - var9) / 2 + var9) {
                  Netalyzr.this.debug("Works: " + var9);
                  Netalyzr.this.debug("Fails: " + var10);
                  Netalyzr.this.debug("At:    " + var11);
                  var7 = "mtu " + var11 + " 64";
                  Netalyzr.this.debug("Message: " + var7);
                  var4 = Netalyzr.this.new UDPTestArgs(1, 5, var7.getBytes());
                  var12 = Netalyzr.this.getUDPData(var3, var1, var4);
                  if (var12 == null) {
                     var10 = var11;
                     Netalyzr.this.debug("Silent failure");
                  } else if ((new String(var12)).startsWith("bad")) {
                     var10 = var11;
                     Netalyzr.this.debug("Responsive failure");
                     Netalyzr.this.debug("Response is " + new String(var12));
                     this.bottleneckIP = (new String(var12)).split(" ")[2];
                  } else {
                     Netalyzr.this.debug("Success");
                     var9 = var11;
                  }
               }

               this.recvMTU = var9;
               Netalyzr.this.debug("Final MTU is " + this.recvMTU);
               return 4;
            } else {
               this.ignoreResult = true;
               return 1;
            }
         }

         String getPostResults() {
            return "\nsendPathMTUV6=" + this.sendMTU + "\nrecvPathMTUV6=" + this.recvMTU + "\npathMTUProblemV6=" + this.pathMTUProblem + "\nbottleneckIPV6=" + this.bottleneckIP + "\nv6SendFragments=" + this.v6SendFragments + "\nv6ReceiveFragments=" + this.v6ReceiveFragments + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkTraceroute") {
         String path;
         int hopcount;
         int badhop;
         String timepath;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.badhop = 0;
            this.hopcount = 0;
            this.path = "";
            this.timepath = "";
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoRawUDP) {
               this.ignoreResult = true;
               return 1;
            } else {
               int var1 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("FRAGMENT_ECHO_PORT"));
               String var2 = Netalyzr.this.serverName;
               this.path = "";
               String var3 = "";

               for(this.hopcount = 1; this.hopcount < 64 && !var3.startsWith(Netalyzr.this.localClientAddr); ++this.hopcount) {
                  if (this.hopcount > 2) {
                     this.path = this.path + ",";
                  }

                  this.path = this.path + var3;
                  var3 = Netalyzr.this.getTraceroute(this.hopcount, 128, var1, var2);
                  if (var3.indexOf("/") > 0) {
                     Netalyzr.this.addrLookups.add(var3.split("/")[0]);
                  }
               }

               --this.hopcount;
               Netalyzr.this.debug("Traceroute complete.  Hopcount: " + this.hopcount);
               Netalyzr.this.debug("Now attempting to find bad-point for 1500B MTU");
               var3 = "*";

               for(this.badhop = this.hopcount; this.badhop > 0 && var3.equals("*"); --this.badhop) {
                  var3 = Netalyzr.this.getTraceroute(this.badhop, 1500, var1, var2);
               }

               ++this.badhop;
               Netalyzr.this.debug("Last hop which gets 1500B is " + this.badhop);
               return 4;
            }
         }

         String getPostResults() {
            return "\ntraceroutePath=" + this.path + "\ntracerouteHopcount=" + this.hopcount + "\ntraceroute1500BHop=" + this.badhop + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkTracerouteV6") {
         String path;
         int hopcount;
         int badhop;
         String timepath;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.badhop = 0;
            this.hopcount = 0;
            this.path = "";
            this.timepath = "";
         }

         int runImpl() throws IOException {
            if (Netalyzr.this.canDoRawUDP && Netalyzr.this.canDoV6) {
               this.path = "";
               String var1 = "";
               int var2 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("FRAGMENT_ECHO_PORT_V6"));
               String var3 = "ipv6-node." + Netalyzr.this.custDnsName;

               for(this.hopcount = 1; this.hopcount < 64 && !var1.startsWith(Netalyzr.this.localClientAddr); ++this.hopcount) {
                  if (this.hopcount > 2) {
                     this.path = this.path + ",";
                  }

                  this.path = this.path + var1;
                  var1 = Netalyzr.this.getTraceroute(this.hopcount, 128, var2, var3);
                  if (var1.indexOf("/") > 0) {
                     Netalyzr.this.addrLookups.add(var1.split("/")[0]);
                  }
               }

               --this.hopcount;
               Netalyzr.this.debug("Traceroute complete.  Hopcount: " + this.hopcount);
               Netalyzr.this.debug("Now attempting to find bad-point for 1500B MTU");
               var1 = "*";

               for(this.badhop = this.hopcount; this.badhop > 0 && var1.equals("*"); --this.badhop) {
                  var1 = Netalyzr.this.getTraceroute(this.badhop, 1500, var2, var3);
               }

               ++this.badhop;
               Netalyzr.this.debug("Last hop which gets 1500B is " + this.badhop);
               return 4;
            } else {
               this.ignoreResult = true;
               return 1;
            }
         }

         String getPostResults() {
            return "\ntracerouteV6Path=" + this.path + "\ntracerouteV6Hopcount=" + this.hopcount + "\ntracerouteV61500BHop=" + this.badhop + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkTracerouteV4") {
         String path;
         int hopcount;
         int badhop;
         String timepath;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.badhop = 0;
            this.hopcount = 0;
            this.path = "";
            this.timepath = "";
         }

         int runImpl() throws IOException {
            if (Netalyzr.this.canDoRawUDP && Netalyzr.this.canDoV6) {
               int var1 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("FRAGMENT_ECHO_PORT"));
               String var2 = "ipv4-node." + Netalyzr.this.custDnsName;
               this.path = "";
               String var3 = "";

               for(this.hopcount = 1; this.hopcount < 64 && !var3.startsWith(Netalyzr.this.localClientAddr); ++this.hopcount) {
                  if (this.hopcount > 2) {
                     this.path = this.path + ",";
                  }

                  this.path = this.path + var3;
                  var3 = Netalyzr.this.getTraceroute(this.hopcount, 128, var1, var2);
                  if (var3.indexOf("/") > 0) {
                     Netalyzr.this.addrLookups.add(var3.split("/")[0]);
                  }
               }

               --this.hopcount;
               Netalyzr.this.debug("Traceroute complete.  Hopcount: " + this.hopcount);
               Netalyzr.this.debug("Now attempting to find bad-point for 1500B MTU");
               var3 = "*";

               for(this.badhop = this.hopcount; this.badhop > 0 && var3.equals("*"); --this.badhop) {
                  var3 = Netalyzr.this.getTraceroute(this.badhop, 1500, var1, var2);
               }

               ++this.badhop;
               Netalyzr.this.debug("Last hop which gets 1500B is " + this.badhop);
               return 4;
            } else {
               this.ignoreResult = true;
               return 1;
            }
         }

         String getPostResults() {
            return "\ntracerouteV4Path=" + this.path + "\ntracerouteV4Hopcount=" + this.hopcount + "\ntracerouteV41500BHop=" + this.badhop + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("checkICMP6") {
         int sendMTUAfter;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() throws IOException {
            int var1 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("FRAGMENT_ECHO_PORT_V6"));
            int var2 = Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_BUFFER_PORT"));
            String var3 = "ipv6-node." + Netalyzr.this.custDnsName;
            if (Netalyzr.this.canDoRawUDP && Netalyzr.this.canDoV6 && Netalyzr.this.v6SendMTU != -1) {
               this.sendMTUAfter = -1;
               String var6 = "toobig ";

               for(int var7 = 0; var7 < 136; ++var7) {
                  var6 = var6 + "1234567890";
               }

               DatagramSocket var17 = new DatagramSocket();
               InetAddress var8 = InetAddress.getByName(var3);
               var17.setSoTimeout(500);
               DatagramPacket var9 = new DatagramPacket(var6.getBytes(), var6.getBytes().length, var8, var1);
               Netalyzr.this.debug("Attempting to send messages to cause the ICMP too big");

               for(int var10 = 0; var10 < 10; ++var10) {
                  Netalyzr.this.debug("Sending a too-big triggering packet");

                  try {
                     var17.send(var9);
                     byte[] var11 = new byte[1024];
                     DatagramPacket var12 = new DatagramPacket(var11, 1024);
                     var17.receive(var12);
                     Netalyzr.this.debug("Got a reply of " + var12.getLength() + " bytes");
                     byte[] var13 = new byte[var12.getLength()];

                     for(int var14 = 0; var14 < var12.getLength(); ++var14) {
                        var13[var14] = var11[var14];
                     }

                     Netalyzr.this.debug("Returned message is " + new String(var13));
                     this.sendMTUAfter = Netalyzr.this.parseInt(new String(var13));
                     return 4;
                  } catch (SocketTimeoutException var15) {
                     Netalyzr.this.debug("No reply: got timeout");
                  } catch (Exception var16) {
                     Netalyzr.this.debug("Caught exception " + var16);
                  }
               }

               return 4;
            } else {
               this.ignoreResult = true;
               return 1;
            }
         }

         String getPostResults() {
            return "\nsendPathMTUV6AfterTooBig=" + this.sendMTUAfter + "\n";
         }
      });
      this.tests.add(new Netalyzr.Test("uploadRemainingNames") {
         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 10L;
         }

         int runImpl() throws IOException {
            Netalyzr.this.debug("Doing a first run of requestLookups()");
            Netalyzr.this.debug("So that the server can cache results");
            Netalyzr.this.requestLookups();
            return 4;
         }
      });
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpNtp", 123));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpNetBiosNs", 137));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpNetBiosDgm", 138));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpIkeKex", 500));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpOpenVpn", 1194));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpSlammer", 1434));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpL2tp", 1701));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpIpsecNat", 4500));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpRtp", 5004));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpRtcp", 5005));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpSip", 5060));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpVoip1", 7078));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpVoip2", 7082));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpSctp", 9899));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpSteam1", 27005));
      this.tests.add(new Netalyzr.UdpConnTest("checkReachUdpSteam2", 27015));
      this.tests.add(new Netalyzr.TcpConnTest("checkFTP", "ftpData", 21));
      this.tests.add(new Netalyzr.TcpConnTest("checkSSH", "sshData", 22));
      this.tests.add(new Netalyzr.TcpConnTest("checkSMTP", "smtpData", 25));
      this.tests.add(new Netalyzr.TcpConnTest("checkPOP", "popData", 110));
      this.tests.add(new Netalyzr.TcpConnTest("checkRPC", "rpcData", 135));
      this.tests.add(new Netalyzr.TcpConnTest("checkNetBIOS", "netbiosData", 139));
      this.tests.add(new Netalyzr.TcpConnTest("checkIMAP", "imapData", 143));
      this.tests.add(new Netalyzr.TcpConnTest("checkSNMP", "snmpData", 161));
      this.tests.add(new Netalyzr.TcpConnTest("checkHTTPS", "httpsData", 443));
      this.tests.add(new Netalyzr.TcpConnTest("checkSMB", "smbData", 445));
      this.tests.add(new Netalyzr.TcpConnTest("checkSecureSMTP", "secureSMTPData", 465));
      this.tests.add(new Netalyzr.TcpConnTest("checkSecureIMAP", "secureImapData", 585));
      this.tests.add(new Netalyzr.TcpConnTest("checkAuthSMTP", "authSMTPData", 587));
      this.tests.add(new Netalyzr.TcpConnTest("checkIMAPSSL", "imapSSLData", 993));
      this.tests.add(new Netalyzr.TcpConnTest("checkPOPSSL", "popSSLData", 995));
      this.tests.add(new Netalyzr.TcpConnTest("checkOpenVPNTCP", "openVPNTCPData", 1194));
      this.tests.add(new Netalyzr.TcpConnTest("checkPPTPControl", "pptpControlData", 1723));
      this.tests.add(new Netalyzr.TcpConnTest("checkSIP", "sipData", 5060));
      this.tests.add(new Netalyzr.TcpConnTest("checkBitTorrent", "bitTorrentData", 6881));
      this.tests.add(new Netalyzr.TcpConnTest("checkTOR", "torData", 9001));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkFTP", "ftpData", 21));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkSSH", "sshData", 22));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkSMTP", "smtpData", 25));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkPOP", "popData", 110));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkRPC", "rpcData", 135));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkNetBIOS", "netbiosData", 139));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkIMAP", "imapData", 143));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkSNMP", "snmpData", 161));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkHTTPS", "httpsData", 443));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkSMB", "smbData", 445));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkSecureSMTP", "secureSMTPData", 465));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkSecureIMAP", "secureImapData", 585));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkAuthSMTP", "authSMTPData", 587));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkIMAPSSL", "imapSSLData", 993));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkPOPSSL", "popSSLData", 995));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkOpenVPNTCP", "openVPNTCPData", 1194));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkPPTPControl", "pptpControlData", 1723));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkSIP", "sipData", 5060));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkBitTorrent", "bitTorrentData", 6881));
      this.tests.add(new Netalyzr.IPv6TcpConnTest("checkTOR", "torData", 9001));
      this.tests.add(new Netalyzr.Test("checkTCPLatency") {
         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         }

         int runImpl() throws IOException {
            int var1 = Netalyzr.this.tcpSetupCount + Netalyzr.this.tcpFirstSetupCount;
            Netalyzr.this.debug("Obtained " + var1 + " latency datapoints.");
            return var1 == 0 ? 2 : 4;
         }

         String getPostResults() {
            if (Netalyzr.this.tcpSetupCount == 0 && Netalyzr.this.tcpFirstSetupCount == 0) {
               return "";
            } else {
               String var1 = "\ntcpSetupLatency=";

               int var2;
               for(var2 = 0; var2 < Netalyzr.this.tcpSetupCount; ++var2) {
                  var1 = var1 + Netalyzr.this.tcpSetupLatency[var2];
                  if (var2 < Netalyzr.this.tcpSetupCount - 1) {
                     var1 = var1 + ",";
                  }
               }

               var1 = var1 + "\ntcpFirstSetupLatency=";

               for(var2 = 0; var2 < Netalyzr.this.tcpFirstSetupCount; ++var2) {
                  var1 = var1 + Netalyzr.this.tcpFirstSetupLatency[var2];
                  if (var2 < Netalyzr.this.tcpFirstSetupCount - 1) {
                     var1 = var1 + ",";
                  }
               }

               if (Netalyzr.this.tcpSetups.length() > 0) {
                  var1 = var1 + "\nallTCPConnections=" + Netalyzr.this.tcpSetups.substring(0, Netalyzr.this.tcpSetups.length() - 1);
               }

               if (Netalyzr.this.httpTimings.length() > 0) {
                  var1 = var1 + "\nallHTTPConnections=" + Netalyzr.this.httpTimings.substring(0, Netalyzr.this.httpTimings.length() - 1);
               }

               return var1 + "\n";
            }
         }
      });
      this.tests.add(new Netalyzr.Test("checkPing") {
         private Netalyzr.NetProbeStats stats;

         void init() {
            this.idleMsg = Netalyzr.this.getLocalString(this.testName);
            this.timeout = 30000L;
         }

         int runImpl() throws IOException {
            if (!Netalyzr.this.canDoRawUDP) {
               return 1;
            } else {
               Netalyzr.this.startedPingTest = true;
               this.stats = Netalyzr.this.new NetProbeStats(Netalyzr.this.serverName, Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_BUFFER_PORT")), 50, 200);
               this.stats.run();
               if (this.stats.status != 4) {
                  this.ignoreResult = true;
               }

               return this.stats.status;
            }
         }

         String getPostResults() {
            return this.stats != null && this.stats.status == 4 ? "quietRTT=" + this.stats.avgRTT + "\nquietSendCount=" + this.stats.sendCount + "\nquietRecvCount=" + this.stats.recvCount + "\nquietServerRecvCount=" + this.stats.serverRecvCount + "\nquietReorder=" + this.stats.reorderCount + "\nquietDup=" + this.stats.dupCount + "\n" : "";
         }
      });
      this.tests.add(new Netalyzr.BandwidthTest("checkUplink", true));
      this.tests.add(new Netalyzr.BandwidthTest("checkDownlink", false));
   }

   void initTests() {
      for(int var1 = 0; var1 < this.tests.size(); ++var1) {
         Netalyzr.Test var2 = (Netalyzr.Test)this.tests.get(var1);
         var2.init();
         if (var2.idleMsg == "") {
            this.debug("Never set idle message for test " + var2.testName);
         }
      }

   }

   boolean runTests() {
      for(this.currentTest = 0; this.currentTest < this.tests.size(); ++this.currentTest) {
         Netalyzr.Test var1 = (Netalyzr.Test)this.tests.get(this.currentTest);
         this.shell.enableRedraw();
         this.shell.updateDisplay();
         if (!this.isLatestVersion) {
            return false;
         }

         this.debug("");
         this.debug("Running test " + this.currentTest + ": " + var1.testName);
         this.debug("----------------------------");
         if (var1.isReady()) {
            int var2 = 50;
            ThreadGroup var3 = new ThreadGroup("test-" + this.currentTest);
            Thread var4 = new Thread(var3, var1);
            long var5 = (new Date()).getTime();
            var4.start();

            while(var4.isAlive()) {
               try {
                  Thread.sleep((long)var2);
                  var2 = Math.min(500, var2 + 25);
               } catch (InterruptedException var8) {
               }

               this.shell.updateDisplay();
               if ((new Date()).getTime() - var5 > var1.timeout) {
                  this.debug("Test running overlong, skipping/backgrounding");
                  var1.setTimeoutFlag();
                  break;
               }
            }
         } else {
            this.debug("Test did not initialize properly.");
         }
      }

      this.shell.enableRedraw();
      this.shell.updateDisplay();
      return true;
   }

   void reportResults() {
      this.idleMsg = this.getLocalString("gatherResults");
      this.shell.enableRedraw();
      this.debug("\nGathering test results");
      this.debug("----------------------");
      StringBuffer var1 = new StringBuffer("http://" + this.getHTTPServerName() + "/log/id=" + this.agentID + "/checkVer=" + this.shell.getBuildNumber());
      StringBuffer var2 = new StringBuffer();

      try {
         var2.append("userAgent=" + this.safeUrlEncode(this.userAgent, "US-ASCII") + "\n");
         var2.append("osName=" + this.safeUrlEncode(System.getProperty("os.name"), "US-ASCII") + "\n");
      } catch (Exception var10) {
         this.debug("Got exception " + var10);
      }

      int var3;
      for(var3 = 0; var3 < expectedParameters.length; ++var3) {
         var2.append("\nAppletParameter" + expectedParameters[var3] + "=" + this.shell.getParameter(expectedParameters[var3]) + "\n");
      }

      this.debug("Adding " + this.tests.size() + " regular test results");

      for(var3 = 0; var3 < this.tests.size(); ++var3) {
         this.addTestOutput((Netalyzr.Test)this.tests.get(var3), var1, var2);
      }

      if (this.skippedTests.size() > 0) {
         this.debug("Adding " + this.skippedTests.size() + " tests skipped due to test mode '" + this.mode.getName() + "':");

         for(var3 = 0; var3 < this.skippedTests.size(); ++var3) {
            Netalyzr.Test var4 = (Netalyzr.Test)this.skippedTests.get(var3);
            this.debug("- " + var4.testName);
            this.addTestOutput(var4, var1, var2);
         }
      }

      var2.append("\nclientTime=" + (new Date()).getTime() + "\n\n");
      this.debug("\nTest results");
      this.debug("------------");
      String var12 = var2.toString();
      var12 = this.sortLines(var12) + "\n";
      var12 = var12 + "\n";
      this.debug(var12);
      this.debug("\nReporting to server");
      this.debug("-------------------");
      this.idleMsg = this.getLocalString("postingResults");
      this.shell.enableRedraw();
      boolean var11 = false;

      for(int var5 = 0; !var11 && var5 < 4; ++var5) {
         var11 = this.doHTTPPost(var1.toString(), var12 + "resultUploadRetries=" + var5 + "\n");
         if (!var11) {
            this.debug("Upload failed, retrying");
            this.idleMsg = this.getLocalString("retryingResults");
            this.shell.enableRedraw();

            try {
               Thread.sleep(30000L);
            } catch (Exception var9) {
            }
         }
      }

      this.debug("\nUploading UPnP information");
      this.debug("--------------------------");
      this.uploadUpnpInfo();
      this.debug("\nRequesting remaining DNS lookups");
      this.debug("--------------------------------");
      this.requestLookups();
      this.idleMsg = this.getLocalString("uploadingTrans");
      this.shell.enableRedraw();
      this.debug("\nUploading transcript");
      this.debug("--------------------");
      this.doHTTPPost("http://" + this.getHTTPServerName() + "/debug/id=" + this.agentID, this.debugOutput.toString());
      this.idleMsg = this.getLocalString("calculatingFinal");
      this.shell.enableRedraw();
      this.debug("\nSaving session state");
      this.debug("--------------------");

      try {
         HttpURLConnection var13 = (HttpURLConnection)(new URL("http://" + this.getHTTPServerName() + "/save/id=" + this.agentID)).openConnection();
         this.debug("Session saving request complete, result code " + var13.getResponseCode());
      } catch (MalformedURLException var7) {
      } catch (IOException var8) {
      }

      String var14 = "http://" + this.getHTTPServerName() + "/summary/id=" + this.agentID;
      this.debug("DONE -- results at " + var14);
      this.debug("Redirecting to " + this.mode.getResultsURL());
      this.shell.complete(this.mode.getResultsURL());
      this.shell.enableRedraw();
   }

   void uploadUpnpInfo() {
      Iterator var1 = this.upnpIGDs.entrySet().iterator();

      while(var1.hasNext()) {
         Entry var2 = (Entry)var1.next();
         UpnpIGD var3 = (UpnpIGD)var2.getValue();
         if (var3.descr != null) {
            if (this.doHTTPPost("http://" + this.getHTTPServerName() + "/upload/id=" + this.agentID + "/key=upnp_" + var3.id + "_details", var3.descr.produceZip(), "application/zip")) {
               this.debug("Successfully posted UPnP content for device " + var3.addr);
            } else {
               this.debug("Could not post UPnP content for device " + var3.addr);
            }
         }
      }

   }

   void requestLookups() {
      this.idleMsg = this.getLocalString("requestingLookups");
      this.shell.enableRedraw();
      int var1 = this.addrLookups.size() + this.nameLookups.size();
      if (var1 == 0) {
         this.debug("No names to lookup");
      } else {
         this.debug("Requesting lookup of " + var1 + " client-side names.");
         StringBuffer var2 = new StringBuffer("http://" + this.getHTTPServerName() + "/lookups/id=" + this.agentID);
         int var3;
         if (this.addrLookups.size() > 0) {
            var2.append("/byAddr=");

            for(var3 = 0; var3 < this.addrLookups.size(); ++var3) {
               var2.append((String)this.addrLookups.get(var3));
               if (var3 < this.addrLookups.size() - 1) {
                  var2.append(",");
               }
            }
         }

         if (this.nameLookups.size() > 0) {
            var2.append("/byName=");

            for(var3 = 0; var3 < this.nameLookups.size(); ++var3) {
               var2.append((String)this.nameLookups.get(var3));
               if (var3 < this.nameLookups.size() - 1) {
                  var2.append(",");
               }
            }
         }

         try {
            this.debug("Requested URL " + var2.toString());
            HttpURLConnection var6 = (HttpURLConnection)(new URL(var2.toString())).openConnection();
            this.debug("DNS lookup request complete, result code " + var6.getResponseCode());
            this.addrLookups = new ArrayList();
            this.nameLookups = new ArrayList();
         } catch (MalformedURLException var4) {
         } catch (IOException var5) {
         }

      }
   }

   Netalyzr getNetalyzr() {
      return this;
   }

   void addTestOutput(Netalyzr.Test var1, StringBuffer var2, StringBuffer var3) {
      int var4 = var1.getTestResultCode();
      if (!var1.ignoreResult) {
         this.idleMsg = this.getLocalString("gatherResultsFor", new Object[]{var1.testName});
         this.shell.enableRedraw();
         var3.append(var1.getTestResultString());
         var3.append("\nTime" + var1.testName + "=" + var1.getDuration() + "\n");
         var3.append("\nignoredTest" + var1.testName + "=False\n");
         if (var4 != 0 && var4 != 50) {
            var3.append("\n" + var1.getPostResults() + "\n");
         }
      } else {
         var3.append("\nignoredTest" + var1.testName + "=True\n");
      }

   }

   public String padString(String var1, int var2) {
      if (var1.length() >= var2) {
         return var1;
      } else {
         boolean var3 = true;

         String var4;
         for(var4 = var1; var4.length() < var2; var3 = !var3) {
            if (var3) {
               var4 = var4 + " ";
            } else {
               var4 = " " + var4;
            }
         }

         return var4;
      }
   }

   public String utcTime() {
      TimeZone var1 = TimeZone.getDefault();
      SimpleDateFormat var2 = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
      Date var3 = new Date((new Date()).getTime() - (long)var1.getRawOffset());
      if (var1.inDaylightTime(var3)) {
         Date var4 = new Date(var3.getTime() - (long)var1.getDSTSavings());
         if (var1.inDaylightTime(var4)) {
            var3 = var4;
         }
      }

      return var2.format(var3) + " UTC";
   }

   public String getLocalString(String var1) {
      if (this.l10nMsgs == null) {
         return "";
      } else {
         try {
            return this.l10nMsgs.getString(var1);
         } catch (MissingResourceException var3) {
            this.debug("l10n failure, tag '" + var1 + "': " + var3.getMessage());
            return "";
         }
      }
   }

   public String getLocalString(String var1, Object[] var2) {
      if (this.l10nMsgs == null) {
         return "";
      } else {
         try {
            return MessageFormat.format(this.l10nMsgs.getString(var1), var2);
         } catch (MissingResourceException var4) {
            this.debug("*** localization failure, text tag '" + var1 + "': " + var4.getMessage());
            return "";
         }
      }
   }

   String getHTTPServerName() {
      return this.serverPort != 80 ? this.serverName + ":" + this.serverPort : this.serverName;
   }

   boolean isTrueName(String var1) {
      this.debug("Fetching name " + var1);

      try {
         InetAddress var2 = InetAddress.getByName(var1);
         this.debug("A is " + var2);
         return var2.getHostAddress().equals(this.trueIP.getHostAddress());
      } catch (Exception var3) {
         return false;
      }
   }

   String sortLines(String var1) {
      var1 = var1.replaceAll("\n+", "\n");
      String[] var2 = var1.split("\n");
      Arrays.sort(var2);
      StringBuffer var3 = new StringBuffer();

      for(int var4 = 0; var4 < var2.length; ++var4) {
         var3.append(var2[var4] + "\n");
      }

      return var3.toString();
   }

   int parseInt(String var1) {
      if (var1 == null) {
         if (this.printParseIntCount < 20) {
            this.debug("Reporting null as integer -1");
         }

         if (this.printParseIntCount == 20) {
            this.debug("Supressing error");
         }

         ++this.printParseIntCount;
         return -1;
      } else {
         try {
            return Integer.parseInt(var1);
         } catch (NumberFormatException var3) {
            if (this.printParseIntCount < 20) {
               this.debug("Reporting \"" + var1 + "\" as integer -1");
            }

            if (this.printParseIntCount == 20) {
               this.debug("Supressing error");
            }

            ++this.printParseIntCount;
            return -1;
         }
      }
   }

   boolean isNatted() {
      this.debug("Checking if a NAT probing test might work");
      if (!this.canDoRawUDP) {
         this.debug("No UDP, not able to probe via DNS or UDP multicast");
         return false;
      } else {
         this.debug("Global/local client addrs: " + this.globalClientAddr + "/" + this.localClientAddr);
         if (this.globalClientAddr.equals("0.0.0.0")) {
            this.debug("Unable to get global address, so not executing");
            return false;
         } else if (this.localClientAddr.equals("0.0.0.0")) {
            this.debug("Unable to get local address, so not executing");
            return false;
         } else if (this.globalClientAddr.equals(this.localClientAddr)) {
            this.debug("No address-level NAT detected, test not run");
            return false;
         } else {
            this.debug("NAT is likely and probable");
            return true;
         }
      }
   }

   String safeUrlEncode(String var1, String var2) throws UnsupportedEncodingException {
      return var1 == null ? "" : URLEncoder.encode(var1, var2);
   }

   void debug(String var1) {
      long var2 = (new Date()).getTime();
      long var4 = var2 - this.debugStartTime;
      String var6 = tsFormatter.format((double)((float)var4) / 1000.0D);
      String var7 = Thread.currentThread().getThreadGroup().getName();
      if (!var7.startsWith("test-")) {
         var7 = "main";
      }

      while(var7.length() < 7) {
         var7 = " " + var7;
      }

      String var8 = "";
      String[] var9 = var1.split("\n");

      for(int var10 = 0; var10 < var9.length; ++var10) {
         var8 = var8 + var6 + " " + var7 + "| " + var9[var10];
         if (var10 < var9.length - 1) {
            var8 = var8 + "\n";
         }
      }

      var1 = var8;
      synchronized(this.debugOutput) {
         if (this.debugStdout) {
            System.out.println(var1);
            System.out.flush();
         }

         this.debugOutput.append(var1 + "\n");
      }
   }

   void debugStackTrace(Throwable var1) {
      StringWriter var2 = new StringWriter();
      var1.printStackTrace(new PrintWriter(var2));
      this.debug(var2.toString());
   }

   int checkUDP(String var1, int var2, Netalyzr.UDPTestArgs var3) throws IOException {
      this.debug("Sending UDP request to " + var1 + " on port " + var2);

      try {
         if (var2 >= 0 && var2 <= 65535) {
            DatagramSocket var4 = new DatagramSocket();
            InetAddress var5 = InetAddress.getByName(var1);
            var4.setSoTimeout(var3.timeoutMilliSecs);
            var4.connect(var5, var2);
            DatagramPacket var6;
            if (var3.payload == null) {
               var6 = new DatagramPacket(this.agentID.getBytes(), this.agentID.length(), var5, var2);
            } else {
               var6 = new DatagramPacket(var3.payload, var3.payload.length, var5, var2);
            }

            int var7 = 0;

            while(var7 < var3.numSend) {
               var3.sendPacketTS = (new Date()).getTime();
               var4.send(var6);
               this.debug("UDP socket at " + var4.getLocalAddress().getHostAddress() + ":" + var4.getLocalPort());

               try {
                  DatagramPacket var8 = new DatagramPacket(new byte[8096], 8096);
                  var4.receive(var8);
                  var3.recvPacketTS = (new Date()).getTime();
                  this.debug("Got datagram of " + var8.getLength() + " bytes.");
                  var3.addResult(var4.getLocalAddress().getHostAddress(), var4.getLocalPort(), var8.getLength());
                  var4.close();
                  return 4;
               } catch (SocketTimeoutException var9) {
                  this.debug("No data received.");
                  ++var7;
               }
            }

            var4.close();
            return 18;
         } else {
            return 34;
         }
      } catch (SocketException var10) {
         this.debug("Got exception " + var10 + " on UDP test");
         return 2;
      } catch (UnknownHostException var11) {
         this.debug("Got exception " + var11 + " on UDP test");
         return 10;
      }
   }

   byte[] getTCPData(String var1, int var2, byte[] var3, int var4) throws IOException {
      Socket var5 = new Socket();
      InetSocketAddress var6 = new InetSocketAddress(var1, var2);
      long var7 = (new Date()).getTime();
      var5.setSoTimeout(5000);
      var5.connect(var6, 5000);
      var7 = (new Date()).getTime() - var7;
      this.debug("connected to '" + var6 + "' in " + var7 + " ms");
      this.tcpSetups = this.tcpSetups + var1 + ":" + var2 + "|" + var7 + ",";
      this.debug("Query to server is " + var3.length + " bytes");
      var5.getOutputStream().write(var3);
      this.debug("Sent request");
      byte[] var9 = new byte[var4];
      InputStream var10 = var5.getInputStream();
      int var11 = 0;

      while(var11 < var4) {
         boolean var12 = false;
         this.debug("Read starting");

         int var15;
         try {
            var15 = var10.read(var9, var11, var4 - var11);
            var11 += var15;
         } catch (SocketTimeoutException var14) {
            this.debug("Caught timeout exception");
            break;
         }

         if (var15 < 0) {
            break;
         }
      }

      var5.close();
      this.debug("Final count is " + var11);
      byte[] var16 = new byte[var11];

      for(int var13 = 0; var13 < var11; ++var13) {
         var16[var13] = var9[var13];
      }

      return var16;
   }

   byte[] getUDPData(String var1, int var2, Netalyzr.UDPTestArgs var3, int var4) throws IOException {
      try {
         if (var2 >= 0 && var2 <= 65535) {
            DatagramSocket var5 = new DatagramSocket();
            InetAddress var6 = InetAddress.getByName(var1);
            var5.setSoTimeout(var3.timeoutMilliSecs);
            var5.connect(var6, var2);
            DatagramPacket var7;
            if (var3.payload == null) {
               var7 = new DatagramPacket(this.agentID.getBytes(), this.agentID.length(), var6, var2);
            } else {
               var7 = new DatagramPacket(var3.payload, var3.payload.length, var6, var2);
            }

            int var8 = 0;

            while(var8 < var3.numSend) {
               var3.sendPacketTS = (new Date()).getTime();
               var5.send(var7);
               this.debug("UDP socket at " + var5.getLocalAddress().getHostAddress() + ":" + var5.getLocalPort());

               try {
                  byte[] var9 = new byte[var4];
                  DatagramPacket var10 = new DatagramPacket(var9, var4);
                  var5.receive(var10);
                  var3.recvPacketTS = (new Date()).getTime();
                  this.debug("Got datagram of " + var10.getLength() + " bytes.");
                  var3.addResult(var5.getLocalAddress().getHostAddress(), var5.getLocalPort(), var10.getLength());
                  var5.close();
                  byte[] var11 = new byte[var10.getLength()];

                  for(int var12 = 0; var12 < var10.getLength(); ++var12) {
                     var11[var12] = var9[var12];
                  }

                  return var11;
               } catch (SocketTimeoutException var13) {
                  this.debug("No data received.");
                  ++var8;
               }
            }

            var5.close();
            return null;
         } else {
            return null;
         }
      } catch (SocketException var14) {
         this.debug("Got exception " + var14 + " on UDP test");
         return null;
      } catch (UnknownHostException var15) {
         this.debug("Got exception " + var15 + " on UDP test");
         return null;
      }
   }

   byte[] getUDPData(String var1, int var2, Netalyzr.UDPTestArgs var3) throws IOException {
      return this.getUDPData(var1, var2, var3, 1024);
   }

   public String getHttpData(String var1) {
      URL var2;
      try {
         var2 = new URL(var1);
      } catch (MalformedURLException var4) {
         this.debug("HTTP GET failed, malformed URL");
         return null;
      }

      String var3 = "GET " + var2.getFile() + " HTTP/1.1\r\nHost: " + var2.getHost() + "\r\nUser-Agent: " + this.userAgent + "\r\nAccept: " + this.accept + "\r\nAccept-Language: " + this.acceptLanguage + "\r\nAccept-Encoding: " + this.acceptEncoding + "\r\nAccept-Charset: " + this.acceptCharset + "\r\nConnection: close\r\n\r\n";
      return this.getHttpResponse(var2, var3);
   }

   public String postHttpData(String var1, String var2) {
      URL var3;
      try {
         var3 = new URL(var1);
      } catch (MalformedURLException var5) {
         this.debug("HTTP POST failed, malformed URL");
         return null;
      }

      return this.getHttpResponse(var3, var2);
   }

   private String getHttpResponse(URL var1, String var2) {
      int var3 = var1.getPort();
      if (var3 < 0) {
         var3 = 80;
      }

      String var4;
      try {
         var4 = InetAddress.getByName(var1.getHost()).getHostAddress();
      } catch (UnknownHostException var10) {
         this.debug("HTTP fetch failed, host not found");
         return null;
      }

      Netalyzr.HttpResponse var5 = new Netalyzr.HttpResponse();

      try {
         int var6 = this.checkRawHTTP(var4, var3, var2, var5);
         byte[] var7 = var5.getRawContent();
         int var8 = var7 != null ? var7.length : 0;
         if (var6 == 4) {
            this.debug("Raw HTTP fetch succeeded: " + var8 + " bytes retrieved.");
            return new String(var7);
         } else if (var6 == 66) {
            this.debug("Raw HTTP fetch failed, HTTP format violation: " + var8 + " bytes retrieved.");
            return null;
         } else {
            this.debug("Raw HTTP fetch failed with unknown error: " + var8 + " bytes retrieved.");
            return null;
         }
      } catch (IOException var9) {
         this.debug("Raw HTTP fetch caused IOException: " + var9);
         return null;
      }
   }

   int checkTCP(String var1, int var2, Netalyzr.TCPTestArgs var3) {
      return this.checkTCP(var1, var2, var3, true);
   }

   int checkTCP(String var1, int var2, Netalyzr.TCPTestArgs var3, boolean var4) {
      try {
         return this.checkTCP(InetAddress.getByName(var1), var2, var3, var4);
      } catch (UnknownHostException var6) {
         this.debug("connecting to " + var1 + ":" + var2 + ": unknown host");
         return 10;
      }
   }

   int checkTCP(InetAddress var1, int var2, Netalyzr.TCPTestArgs var3, boolean var4) {
      if (var2 < 0) {
         return 34;
      } else {
         if (var3 == null) {
            var3 = new Netalyzr.TCPTestArgs();
         }

         try {
            InetSocketAddress var5 = new InetSocketAddress(var1, var2);
            Socket var6 = new Socket();
            long var7 = (new Date()).getTime();
            var6.connect(var5, var3.timeoutMilliSecs);
            var7 = (new Date()).getTime() - var7;
            this.debug("Connected to " + var1 + ":" + var2 + " in " + var7 + " ms");
            this.tcpSetups = this.tcpSetups + var1 + ":" + var2 + "|" + var7 + ",";
            if (var4) {
               if (!this.contactedTcpPorts.contains(new Integer(var2))) {
                  if (this.tcpFirstSetupCount < this.maxTcpSetupCount) {
                     this.tcpFirstSetupLatency[this.tcpFirstSetupCount] = var7;
                     ++this.tcpFirstSetupCount;
                  }
               } else if (this.tcpSetupCount < this.maxTcpSetupCount) {
                  this.tcpSetupLatency[this.tcpSetupCount] = var7;
                  ++this.tcpSetupCount;
               }
            }

            this.contactedTcpPorts.add(new Integer(var2));
            var3.localAddr = var6.getLocalAddress().getHostAddress();
            var3.localPort = var6.getLocalPort();
            var3.remoteAddr = var6.getInetAddress().getHostAddress();
            if (var3.todoData > 0) {
               this.debug("reading " + var3.todoData + " bytes from socket...");
               byte[] var9 = new byte[var3.todoData];
               var6.setSoTimeout(5000);
               InputStream var10 = var6.getInputStream();
               StringBuffer var11 = new StringBuffer();

               while(var11.length() < var3.todoData + 200) {
                  int var12;
                  try {
                     var12 = var10.read(var9, 0, var3.todoData);
                  } catch (SocketTimeoutException var14) {
                     break;
                  }

                  if (var12 < 0) {
                     break;
                  }

                  var11.append(new String(var9, 0, var12));
               }

               var3.recvData = var11.toString();
               if (var3.expectedData != null) {
                  boolean var17 = var3.recvData.startsWith(var3.expectedData);
                  this.debug("TCP test to " + var1 + ":" + var2 + ": expected='" + var3.expectedData.trim() + "', have '" + var3.recvData.trim() + "', match: " + var17);
                  if (!var17) {
                     var6.close();
                     return 66;
                  }
               }
            }

            var6.close();
            return 4;
         } catch (UnknownHostException var15) {
            this.debug("connecting to " + var1 + ":" + var2 + ": unknown host");
            return 10;
         } catch (IOException var16) {
            this.debug("connecting to " + var1 + ":" + var2 + ": unavailable");
            return 18;
         }
      }
   }

   int checkRawHTTP(String var1, int var2, String var3, Netalyzr.HttpResponse var4) throws IOException {
      if (var2 < 0) {
         return 34;
      } else {
         InetSocketAddress var5 = new InetSocketAddress(var1, var2);
         return this.checkRawHTTP(var5, var3, var4);
      }
   }

   int checkRawHTTP(InetAddress var1, int var2, String var3, Netalyzr.HttpResponse var4) throws IOException {
      if (var2 < 0) {
         return 34;
      } else {
         InetSocketAddress var5 = new InetSocketAddress(var1, var2);
         return this.checkRawHTTP(var5, var3, var4);
      }
   }

   int checkRawHTTP(InetSocketAddress var1, String var2, Netalyzr.HttpResponse var3) throws IOException {
      return this.checkRawHTTP(var1, var2, var3, 10000);
   }

   int checkRawHTTP(InetSocketAddress var1, String var2, Netalyzr.HttpResponse var3, int var4) throws IOException {
      Socket var5 = new Socket();
      long var6 = (new Date()).getTime();
      var5.connect(var1, var4);
      long var8 = (new Date()).getTime() - var6;
      this.debug("connected to '" + var1 + "' in " + var8 + " ms");
      this.tcpSetups = this.tcpSetups + var1 + "|" + var8 + ",";
      var5.getOutputStream().write(var2.getBytes());
      var6 = (new Date()).getTime();
      byte[] var10 = new byte[4096];
      InputStream var11 = var5.getInputStream();
      ByteArrayOutputStream var12 = new ByteArrayOutputStream();
      StringBuffer var13 = new StringBuffer();
      boolean var14 = false;
      int var15 = 0;
      int var16 = -1;
      boolean var17 = false;

      int var29;
      do {
         var29 = var11.read(var10);
         if (var29 < 0) {
            break;
         }

         var13.append(new String(var10, 0, var29));
         var12.write(var10, 0, var29);
         var15 += var29;
      } while((var16 = var13.indexOf("\r\n\r\n")) <= 0);

      var6 = (new Date()).getTime() - var6;
      this.debug("read response headers in " + var6 + " ms");
      this.httpTimings = this.httpTimings + var1 + "|" + var8 + "|" + var6 + ",";
      if (var3 != null) {
         byte[] var18 = var12.toByteArray();
         var3.setRawContent(var18);
      }

      if (var16 < 0) {
         this.debug("Result invalid, end of headers not found.");
         this.debug("Going to assume bad server which uses just \\n instead of \\r\\n");
         int var30 = var13.indexOf("\n\n");
         var17 = true;
         if (var30 < 0) {
            this.debug("Still no header");
            return 66;
         }

         var16 = var30;
      }

      String var31 = var13.substring(0, var16);
      String[] var19;
      if (var17) {
         var19 = var31.split("\n");
      } else {
         var19 = var31.split("\r\n");
      }

      if (var19.length < 2) {
         this.debug("Result invalid: header is " + var31);
         return 66;
      } else if (!var19[0].startsWith("HTTP/1.0 ") && !var19[0].startsWith("HTTP/1.1 ")) {
         this.debug("Result invalid: first line is " + var19[0]);
         return 66;
      } else {
         String[] var20 = var19[0].split(" ");
         if (var20.length < 3) {
            this.debug("Result invalid, not HTTP response: " + var19[0]);
            return 66;
         } else if (var3 == null) {
            return 4;
         } else {
            var3.setResponseCode(this.parseInt(var20[1]));
            if (var3.getResponseCode() < 0) {
               this.debug("Could not extract status code: " + var19[0]);
               return 66;
            } else {
               String var21 = "HTTP headers received: ";

               int var22;
               for(var22 = 1; var22 < var19.length; ++var22) {
                  String[] var23 = var19[var22].split(": ");
                  if (var23.length == 2) {
                     var3.addHeader(var23[0], var23[1]);
                     var21 = var21 + var23[0] + " ";
                  }
               }

               this.debug(var21);
               var22 = var3.getContentLength();
               if (var22 <= 0 && var19.length == 1) {
                  this.debug("No content length reported and no connection closed and no headers");
                  this.debug("So just going to treat it like connection: close");
                  this.debug("Here's the content so far:" + var13);
               } else if (var22 <= 0 && (var3.getHeader("connection") == null || !var3.getHeader("connection").toLowerCase().equals("close"))) {
                  this.debug("No content length reported, and no connection close; done.");
                  this.debug("Here's the content so far:" + var13);
                  this.debug("Going to treat like connection: close");
               }

               this.debug("Content length is: " + var22);
               if (var22 == 0) {
                  this.debug("No data received, so just return");
                  return 4;
               } else {
                  this.debug("Now getting the payload itself");
                  if (var17) {
                     this.debug("Bad separator, so decrement eoh by 2 to accomodate");
                     this.debug("smaller eoh length in payload grabbing");
                     var16 -= 2;
                  }

                  try {
                     byte[] var24;
                     byte[] var32;
                     if (var22 > 0) {
                        while(true) {
                           if (var12.size() >= var22 + var16 + 4) {
                              var32 = var12.toByteArray();
                              var24 = new byte[var22];
                              this.debug("Got all content");
                              var3.setRawContent(var32);

                              try {
                                 System.arraycopy(var32, var16 + 4, var24, 0, var22);
                                 var3.setEntity(var24);
                              } catch (IndexOutOfBoundsException var27) {
                                 this.debug("Index out of bound exception " + var27.getMessage());
                              }
                              break;
                           }

                           var29 = var11.read(var10);
                           if (var29 < 0) {
                              break;
                           }

                           var12.write(var10, 0, var29);
                        }
                     } else {
                        this.debug("No content length, so just reading till the end");

                        while(true) {
                           var29 = var11.read(var10);
                           if (var29 < 0) {
                              var32 = var12.toByteArray();
                              this.debug("Got all content");
                              var3.setRawContent(var32);
                              var22 = var32.length - (var16 + 4);
                              var3.setContentLength(var22);
                              this.debug("Content length should be " + var22);
                              var24 = new byte[var22];

                              try {
                                 System.arraycopy(var32, var16 + 4, var24, 0, var22);
                                 var3.setEntity(var24);
                              } catch (IndexOutOfBoundsException var26) {
                                 this.debug("Index out of bound exception " + var26.getMessage());
                              }
                              break;
                           }

                           var12.write(var10, 0, var29);
                        }
                     }
                  } catch (SocketTimeoutException var28) {
                     this.debug("Unable to get content, caught timeout exception");
                     this.debugStackTrace(var28);
                  }

                  return 4;
               }
            }
         }
      }
   }

   boolean doHTTPPost(String var1, String var2) {
      try {
         this.debug("HTTP POST of " + var2.length() + " bytes to " + var1 + " ...");
         HttpURLConnection var3 = (HttpURLConnection)(new URL(var1)).openConnection();
         var3.setDoOutput(true);
         var3.setRequestProperty("Content-Type", "text/plain");
         OutputStreamWriter var4 = new OutputStreamWriter(var3.getOutputStream());
         var4.write(var2);
         var4.flush();
         int var5 = var3.getResponseCode();
         var4.close();
         this.debug("POST complete, return code " + var5);
         return var5 == 200;
      } catch (IOException var6) {
         this.debug("Got IO exception " + var6 + " during HTTP POST");
         return false;
      }
   }

   boolean doHTTPPost(String var1, byte[] var2, String var3) {
      try {
         this.debug("HTTP POST of " + var2.length + " bytes to " + var1 + " ...");
         HttpURLConnection var4 = (HttpURLConnection)(new URL(var1)).openConnection();
         var4.setDoOutput(true);
         var4.setRequestProperty("Content-Type", var3);
         OutputStream var5 = var4.getOutputStream();
         var5.write(var2);
         var5.flush();
         int var6 = var4.getResponseCode();
         var5.close();
         this.debug("POST complete, return code " + var6);
         return var6 == 200;
      } catch (IOException var7) {
         this.debug("Got IO exception " + var7 + " during HTTP POST");
         return false;
      }
   }

   DNSMessage checkDNSFetch(String var1, String var2, int var3, boolean var4, int var5) {
      return this.checkDNSFetch(var1, var2, var3, 1, var4, var5);
   }

   DNSMessage checkDNSFetch(String var1, String var2, int var3, int var4, boolean var5, int var6) {
      return this.checkDNSFetch(var1, var2, var3, var4, var5, var6, false);
   }

   DNSMessage checkDNSFetch(String var1, String var2, int var3, int var4, boolean var5, int var6, boolean var7) {
      this.debug("Performing DNS fetch check of query " + var2);
      this.debug("To server " + var1);
      this.debug("With EDNS0 MTU of " + var6 + " and want_dnssec of " + var7);

      try {
         DNSMessage var8;
         if (var6 != 0) {
            var8 = new DNSMessage(var2, var3, var4, var6, var7);
         } else {
            var8 = new DNSMessage(var2, var3, var4);
         }

         var8.rd = var5;
         this.debug("Query to server is " + var8.pack().length + " bytes");
         this.debug("Testing query as DNS to make sure it parses");
         DNSMessage var9 = new DNSMessage(var8.pack());
         var9.print();
         byte[] var10 = this.getUDPData(var1, 53, new Netalyzr.UDPTestArgs(1, 5, var8.pack()), 4096);
         if (var10 != null) {
            DNSMessage var11 = new DNSMessage(var10);
            if (var11.tc) {
               this.debug("Got truncation in the reply");
               return this.checkDNSFetchTCP(var1, var2, var3, var4, var5, var6);
            }

            var11.print_short();
            return var11;
         }
      } catch (DNSMessage.DNSError var12) {
         this.debug("Error in DNS, caught: " + var12);
      } catch (IOException var13) {
         this.debug("Error in querying, caught: " + var13);
      }

      return null;
   }

   DNSMessage checkDNSFetchTCP(String var1, String var2, int var3, int var4, boolean var5, int var6) {
      return this.checkDNSFetchTCP(var1, var2, var3, var4, var5, var6, false);
   }

   DNSMessage checkDNSFetchTCP(String var1, String var2, int var3, int var4, boolean var5, int var6, boolean var7) {
      this.debug("Performing DNS fetch check of query " + var2 + ", EDNS0 MTU: " + var6);

      try {
         DNSMessage var8;
         if (var6 != 0) {
            var8 = new DNSMessage(var2, var3, var4, var6, var7);
         } else {
            var8 = new DNSMessage(var2, var3, var4);
         }

         var8.rd = var5;
         return this.checkDNSFetchTCP(var1, var8);
      } catch (DNSMessage.DNSError var10) {
         this.debug("Error in DNS, caught: " + var10);
         return null;
      }
   }

   DNSMessage checkDNSFetchTCP(String var1, DNSMessage var2) {
      this.debug("DNSFetch to server " + var1 + " via TCP");

      try {
         this.debug("Creating TCP framing for message");
         byte[] var3 = var2.pack();
         ByteBuffer var4 = ByteBuffer.allocate(var3.length + 2);
         var4.putShort((short)var3.length);
         var4.put(var3);
         Socket var5 = new Socket();
         InetSocketAddress var6 = new InetSocketAddress(var1, 53);
         long var7 = (new Date()).getTime();
         var5.setSoTimeout(5000);
         var5.connect(var6, 5000);
         var7 = (new Date()).getTime() - var7;
         this.debug("connected to '" + var6 + "' in " + var7 + " ms");
         this.tcpSetups = this.tcpSetups + var6 + "|" + var7 + ",";
         var5.getOutputStream().write(var4.array());
         this.debug("Sent request");
         byte[] var9 = new byte[1];
         InputStream var10 = var5.getInputStream();
         boolean var11 = false;
         boolean var12 = false;
         this.debug("Reading first byte of length field");
         var10.read(var9);
         var4 = ByteBuffer.allocate(2);
         var4.put(var9[0]);
         this.debug("Reading second byte of length field");
         var10.read(var9);
         var4.put(var9[0]);
         short var13 = var4.getShort(0);
         this.debug("Message length is " + var13);
         var9 = new byte[var13];
         int var19 = 0;

         while(var19 < var13) {
            var12 = false;
            this.debug("Read starting");

            int var20;
            try {
               var20 = var10.read(var9, var19, var13 - var19);
               var19 += var20;
            } catch (SocketTimeoutException var16) {
               this.debug("Caught timeout exception");
               break;
            }

            if (var20 < 0) {
               break;
            }
         }

         var5.close();
         this.debug("Final count is " + var19);
         byte[] var14 = new byte[var19];

         for(int var15 = 0; var15 < var19; ++var15) {
            var14[var15] = var9[var15];
         }

         if (var14 != null && var19 > 0) {
            DNSMessage var21 = new DNSMessage(var14);
            return var21;
         }
      } catch (DNSMessage.DNSError var17) {
         this.debug("Error in DNS, caught: " + var17);
      } catch (IOException var18) {
         this.debug("Error in querying, caught: " + var18);
      }

      return null;
   }

   boolean checkDNSFetch(String var1, String var2, int var3, boolean var4, String[] var5) {
      return this.checkDNSFetch(var1, var2, var3, var4, (String[])var5, 0);
   }

   boolean checkDNSFetch(String var1, String var2, int var3, boolean var4, String[] var5, int var6) {
      DNSMessage var7 = this.checkDNSFetch(var1, var2, var3, var4, var6);
      if (var7 != null) {
         try {
            if (var7.answer.length == 1) {
               String[] var8 = ((DNSMessage.DNSRdataTXT)var7.answer[0].rdata).txt;
               int var9;
               if (var8.length == var5.length) {
                  for(var9 = 0; var9 < var5.length; ++var9) {
                     if (!var8[var9].equals(var5[var9])) {
                        this.debug("Text mismatch");
                        return false;
                     }
                  }

                  this.debug("Text match");
                  return true;
               }

               if (var8.length > var5.length) {
                  for(var9 = 0; var9 < var5.length; ++var9) {
                     if (!var8[var9].equals(var5[var9])) {
                        this.debug("Text mismatch");
                        return false;
                     }
                  }

                  this.debug("Text prefix match");
                  return true;
               }
            }

            this.debug("Mismatched reply");
            return false;
         } catch (Exception var10) {
            this.debug("Got Error " + var10);
            this.debug("So no match");
            return false;
         }
      } else {
         this.debug("No reply");
         return false;
      }
   }

   boolean checkDNSFetch(String var1, String var2, int var3, boolean var4, InetAddress var5) {
      return this.checkDNSFetch(var1, var2, var3, var4, (InetAddress)var5, 0);
   }

   boolean checkDNSFetch(String var1, String var2, int var3, boolean var4, InetAddress var5, int var6) {
      DNSMessage var7 = this.checkDNSFetch(var1, var2, var3, var4, var6);
      this.debug("checking for match with IP " + var5);
      if (var7 != null) {
         try {
            if (var7.answer.length == 1) {
               InetAddress var8 = ((DNSMessage.DNSRdataIP)var7.answer[0].rdata).rdata;
               this.debug("Reply is " + var8);
               if (var8.equals(var5)) {
                  this.debug("IP match");
                  return true;
               }
            }

            this.debug("Mismatched reply");
            return false;
         } catch (Exception var9) {
            this.debug("Got Error " + var9);
            this.debug("So no match");
            return false;
         }
      } else {
         this.debug("No reply");
         return false;
      }
   }

   String getTraceroute(int var1, int var2, int var3, String var4) {
      String var5 = "mtu " + var2 + " 0" + var1;
      this.debug("Checking traceroute for TTL " + var1);
      Netalyzr.UDPTestArgs var6 = new Netalyzr.UDPTestArgs(1, 4, var5.getBytes());

      byte[] var7;
      try {
         var7 = this.getUDPData(var4, var3, var6);
      } catch (IOException var10) {
         this.debug("Traceroute caught exception " + var10);
         return "*";
      }

      try {
         if (var7 == null) {
            this.debug("No data received");
            return "*";
         }

         if ((new String(var7)).startsWith("ttl")) {
            String var8 = new String(var7);
            this.debug("Response is " + var8);
            this.debug("IP is: " + var8.split(" ")[2]);
            this.debug("Timestamp is: " + var8.split(" ")[3]);
            return var8.split(" ")[2] + "/" + var8.split(" ")[3];
         }

         if ((new String(var7)).startsWith("good")) {
            this.debug("Packet received to client");
            return this.localClientAddr;
         }

         if ((new String(var7)).startsWith("bad")) {
            this.debug("ICMP too big received");
            return "X";
         }
      } catch (IndexOutOfBoundsException var9) {
      }

      this.debug("Unknown response received: " + new String(var7));
      return "?";
   }

   private class UDPTestArgs {
      public int timeoutMilliSecs;
      public int numSend;
      public int numRecv;
      public int[] recvLen;
      public String[] localAddrs;
      public int[] localPorts;
      public byte[] payload;
      public long sendPacketTS;
      public long recvPacketTS;

      UDPTestArgs() {
         this.timeoutMilliSecs = 1500;
         this.numSend = 10;
         this.numRecv = 0;
         this.recvLen = new int[this.numSend];
         this.localAddrs = new String[this.numSend];
         this.localPorts = new int[this.numSend];
         this.payload = null;
      }

      UDPTestArgs(int var2, int var3) {
         this.timeoutMilliSecs = var2 * 1000;
         this.numSend = var3;
         this.numRecv = 0;
         this.recvLen = new int[var3];
         this.localAddrs = new String[var3];
         this.localPorts = new int[var3];
         this.payload = null;
      }

      UDPTestArgs(int var2, int var3, byte[] var4) {
         this.timeoutMilliSecs = var2 * 1000;
         this.numSend = var3;
         this.payload = var4;
         this.numRecv = 0;
         this.recvLen = new int[var3];
         this.localAddrs = new String[var3];
         this.localPorts = new int[var3];
      }

      void debugStatus() {
         Netalyzr.this.debug("UDP arguments");
         Netalyzr.this.debug("numSend: " + this.numSend);
         Netalyzr.this.debug("numRecv: " + this.numRecv);
         Netalyzr.this.debug("payload: " + new String(this.payload));
      }

      public void addResult(String var1, int var2, int var3) {
         if (this.numRecv < this.numSend) {
            this.localAddrs[this.numRecv] = var1;
            this.localPorts[this.numRecv] = var2;
            this.recvLen[this.numRecv] = var3;
            ++this.numRecv;
         }
      }
   }

   private class UdpConnTest extends Netalyzr.ConnTest {
      UdpConnTest(String var2, int var3) {
         super(var2, (String)null, var3, "UDP");
         this.timeout = 2000L;
      }

      int runImpl() throws IOException {
         if (!Netalyzr.this.canDoRawUDP) {
            this.ignoreResult = true;
            return 0;
         } else {
            return Netalyzr.this.checkUDP(Netalyzr.this.serverName, this.port, Netalyzr.this.new UDPTestArgs(1, 5));
         }
      }

      String getPostResults() {
         return "\nconnTest" + this.protoName + "Port" + this.port + "=" + this.testResult + "\n";
      }
   }

   private class IPv6TcpConnTest extends Netalyzr.TcpConnTest {
      IPv6TcpConnTest(String var2, String var3, int var4) {
         super(var2, var3, var4);
         this.protoName = "IPv6TCP";
         this.idleMsg = Netalyzr.this.getLocalString(var2) + " " + Netalyzr.this.getLocalString("reachabilityV6Suffix");
         this.testName = var2 + "IPv6";
         this.postName = var3 + "IPv6";
      }

      int runImpl() throws IOException {
         if (!Netalyzr.this.canDoV6) {
            Netalyzr.this.debug("IPv6 not available, skipping test.");
            return 0;
         } else {
            String var1 = Netalyzr.this.globalClientAddr;
            if (var1.equals("0.0.0.0")) {
               Netalyzr.this.debug("No global client address: will use null string");
               var1 = "";
            }

            Netalyzr.TCPTestArgs var2 = Netalyzr.this.new TCPTestArgs(120);
            int var3 = Netalyzr.this.checkTCP(Netalyzr.this.v6server, this.port, var2, false);
            if (var3 == 66 && var2.recvData != null) {
               this.recvData = Netalyzr.this.safeUrlEncode(var2.recvData, "UTF-8");
            }

            return var3;
         }
      }

      String getPostResults() {
         return Netalyzr.this.canDoV6 ? super.getPostResults() : "";
      }
   }

   private class TCPTestArgs {
      public int timeoutMilliSecs;
      public int todoData;
      public String expectedData;
      public String recvData;
      public String localAddr;
      public int localPort;
      public String remoteAddr;
      public boolean do_not_time;

      TCPTestArgs() {
         this.timeoutMilliSecs = 12000;
         this.todoData = 0;
         this.expectedData = this.recvData = null;
      }

      TCPTestArgs(int var2) {
         this.timeoutMilliSecs = 12000;
         this.todoData = var2;
         this.expectedData = this.recvData = null;
      }

      TCPTestArgs(int var2, String var3) {
         this.timeoutMilliSecs = var2 * 1000;
         this.expectedData = var3;
         this.todoData = 0;
         if (this.expectedData != null) {
            this.todoData = this.expectedData.length();
         }

      }
   }

   private class TcpConnTest extends Netalyzr.ConnTest {
      TcpConnTest(String var2, String var3, int var4) {
         super(var2, var3, var4, "TCP");
         this.timeout = 1000L;
      }

      int runImpl() throws IOException {
         String var1 = Netalyzr.this.serverName;
         String var2 = Netalyzr.this.globalClientAddr;
         if (var2.equals("0.0.0.0")) {
            Netalyzr.this.debug("No global client address: will use null string");
            var2 = "";
         }

         Netalyzr.TCPTestArgs var3 = Netalyzr.this.new TCPTestArgs(12, var2);
         int var4 = Netalyzr.this.checkTCP(var1, this.port, var3);
         if (var4 == 66 && var3.recvData != null) {
            this.recvData = Netalyzr.this.safeUrlEncode(var3.recvData, "UTF-8");
         }

         return var4;
      }

      String getPostResults() {
         String var1 = "\nconnTest" + this.protoName + "Port" + this.port + "=" + this.testResult + "\n";
         if (this.recvData != null) {
            var1 = var1 + "\nconnTest" + this.protoName + "Port" + this.port + "data=" + this.recvData + "\n" + this.postName + "=" + this.recvData + "\n";
         }

         return var1;
      }
   }

   private class ConnTest extends Netalyzr.Test {
      String recvData;
      String postName;
      int port;
      String protoName;

      ConnTest(String var2, String var3, int var4, String var5) {
         super(var2);
         this.idleMsg = Netalyzr.this.getLocalString(var2);
         this.testName = var2;
         this.postName = var3;
         this.port = var4;
         this.protoName = var5;
      }
   }

   private class BandwidthTest extends Netalyzr.Test {
      private Netalyzr.NetProbeStats stats;
      boolean overload = false;
      boolean uplink;

      BandwidthTest(String var2, boolean var3) {
         super(var2);
         this.uplink = var3;
      }

      void init() {
         this.idleMsg = Netalyzr.this.getLocalString(this.testName);
         this.timeout = 30000L;
      }

      int runImpl() throws IOException {
         short var1 = 0;
         short var2 = 0;
         if (this.overload) {
            return 4;
         } else if (!Netalyzr.this.canDoRawUDP) {
            this.ignoreResult = true;
            return 1;
         } else {
            if (this.uplink) {
               this.getUpnpStats("stats-pre-tx");
               var1 = 1024;
            } else {
               this.getUpnpStats("stats-pre-rx");
               var2 = 1024;
            }

            Netalyzr.this.debug("Conducting measurement...");
            this.stats = Netalyzr.this.new NetProbeStats(Netalyzr.this.serverName, Netalyzr.this.parseInt(Netalyzr.this.shell.getParameter("UDP_BUFFER_PORT")), 0, 10, var1, var2);
            this.stats.run();
            Netalyzr.this.debug("");
            if (this.uplink) {
               this.getUpnpStats("stats-post-tx");
            } else {
               this.getUpnpStats("stats-post-rx");
            }

            if (this.stats.status != 4) {
               this.ignoreResult = true;
            }

            return this.stats.status;
         }
      }

      void getUpnpStats(String var1) {
         if (Netalyzr.this.upnpIGDs.size() != 0) {
            Netalyzr.this.debug("Beginning UPnP calls for packet/byte counters...");
            Iterator var2 = Netalyzr.this.upnpIGDs.entrySet().iterator();

            while(var2.hasNext()) {
               Entry var3 = (Entry)var2.next();
               UpnpIGD var4 = (UpnpIGD)var3.getValue();
               if (var4.descr != null) {
                  var4.descr.call(var1, "*", "WANCommonInterfaceConfig", "GetTotalBytesSent");
                  var4.descr.call(var1, "*", "WANCommonInterfaceConfig", "GetTotalPacketsSent");
                  var4.descr.call(var1, "*", "WANCommonInterfaceConfig", "GetTotalBytesReceived");
                  var4.descr.call(var1, "*", "WANCommonInterfaceConfig", "GetTotalPacketsReceived");
               }
            }

            Netalyzr.this.debug("");
         }
      }

      String getPostResults() {
         if (this.ignoreResult) {
            return "";
         } else if (this.overload) {
            return "\nbufferOverload=True\n";
         } else if (this.stats.status != 4) {
            return "";
         } else {
            return this.uplink ? "\nsendSustainedRTT=" + this.stats.sustainedRTT + "\nsendSustainedPPS=" + this.stats.sustainedPPS + "\nsendPacketSize=" + this.stats.sendPacketSize + "\nsendPacketsSent=" + this.stats.sendCount + "\nsendPacketsRecv=" + this.stats.recvCount + "\nsendServerPacketsRecv=" + this.stats.serverRecvCount + "\nsendReorder=" + this.stats.reorderCount + "\nsendDup=" + this.stats.dupCount + "\n" : "\nrecvSustainedRTT=" + this.stats.sustainedRTT + "\nrecvSustainedPPS=" + this.stats.sustainedPPS + "\nrecvPacketSize=" + this.stats.recvPacketSize + "\nrecvPacketsSent=" + this.stats.sendCount + "\nrecvPacketsRecv=" + this.stats.recvCount + "\nrecvServerPacketsRecv=" + this.stats.serverRecvCount + "\nrecvReorder=" + this.stats.reorderCount + "\nrecvDup=" + this.stats.dupCount + "\n";
         }
      }
   }

   public class ModeSkippedTest extends Netalyzr.Test {
      ModeSkippedTest(String var2) {
         super(var2);
      }
   }

   public class Test implements Runnable {
      public long timeout = 20000L;
      public long duration = 0L;
      public static final int TEST_NOT_EXECUTED = 0;
      public static final int TEST_PROHIBITED = 1;
      public static final int TEST_ERROR = 2;
      public static final int TEST_SUCCESS = 4;
      public static final int TEST_COMPLEX = 6;
      public static final int TEST_ERROR_UNKNOWN_HOST = 8;
      public static final int TEST_ERROR_UNAVAIL = 16;
      public static final int TEST_ERROR_IO = 32;
      public static final int TEST_ERROR_IO_WRONGDATA = 64;
      public static final int TEST_ERROR_NOT_COMPLETED = 48;
      public static final int TEST_ERROR_OTHER_EXCEPTION = 80;
      String idleMsg = "";
      int testResult;
      protected boolean initSuccess;
      public boolean ignoreResult;
      public boolean didTimeout;
      public String testName = "";

      Test(String var2) {
         this.testName = var2;
         this.testResult = 0;
         this.initSuccess = true;
         this.didTimeout = false;
      }

      public void run() {
         this.testResult = 0;
         this.duration = 0L;
         long var1 = (new Date()).getTime();
         Netalyzr.this.debug("Starting " + this.testName);
         if (this.initSuccess) {
            try {
               this.testResult = 50;
               this.testResult = this.runImpl();
            } catch (SecurityException var4) {
               Netalyzr.this.debug("Security restriction:");
               Netalyzr.this.debugStackTrace(var4);
               this.testResult = 1;
            } catch (IOException var5) {
               Netalyzr.this.debug("Test aborted due to IO exception:");
               Netalyzr.this.debugStackTrace(var5);
               this.testResult = 34;
            } catch (Exception var6) {
               Netalyzr.this.debug("Test aborted due to other exception:");
               Netalyzr.this.debugStackTrace(var6);
               this.testResult = 82;
            }
         }

         this.duration = (new Date()).getTime() - var1;
      }

      void init() {
      }

      boolean isReady() {
         return this.initSuccess;
      }

      int getTestResultCode() {
         return this.testResult;
      }

      String getTestResultString() {
         return "\n" + this.testName + "=" + this.testResult + "\n";
      }

      String getPostResults() {
         return "";
      }

      public void setTimeoutFlag() {
         this.didTimeout = true;
      }

      public long getDuration() {
         return this.duration;
      }

      int runImpl() throws IOException {
         return 0;
      }
   }

   public class NetProbeStats {
      public float avgRTT;
      public float sustainedPPS;
      public float sustainedRTT;
      public int sendPacketSize;
      public int recvPacketSize;
      public long sendCount;
      public long recvCount;
      public long serverRecvCount;
      public long reorderCount;
      private int reorderIndex;
      public long lossBurstCount;
      public long lossBurstLength;
      public long dupCount;
      private boolean[] dupData;
      private int dupRange;
      public int status;
      private String server;
      private InetAddress serverIP;
      private int port;
      private int sendRate;
      private int sendTime;
      private int sendSize;
      private int recvSize;
      private String sendSlug;
      private boolean isPing;
      private int maxSend;
      private boolean stopAtPing;

      public NetProbeStats(String var2, int var3, int var4, int var5) {
         this.isPing = true;
         this.server = var2;
         this.dupRange = 30000;
         this.dupData = new boolean[this.dupRange];
         this.dupCount = 0L;
         this.reorderCount = 0L;
         this.reorderIndex = -1;
         this.lossBurstCount = 0L;
         this.lossBurstLength = 0L;

         try {
            this.serverIP = InetAddress.getByName(this.server);
         } catch (UnknownHostException var7) {
            this.status = 2;
            Netalyzr.this.debug("Failed to initialize properly");
            return;
         }

         this.maxSend = var5;
         this.port = var3;
         this.sendRate = var4;
         this.sendTime = 0;
         this.sendSize = 0;
         this.recvSize = 0;
         this.sendSlug = "";
         this.serverRecvCount = 0L;

         for(int var6 = 0; var6 < this.sendSize; ++var6) {
            this.sendSlug = this.sendSlug + ".";
         }

         this.stopAtPing = false;
      }

      public NetProbeStats(String var2, int var3, int var4) {
         this.isPing = true;
         this.server = var2;
         this.stopAtPing = true;
         this.lossBurstCount = 0L;
         this.lossBurstLength = 0L;
         this.dupRange = 30000;
         this.dupData = new boolean[this.dupRange];
         this.dupCount = 0L;
         this.reorderCount = 0L;
         this.reorderIndex = -1;

         try {
            this.serverIP = InetAddress.getByName(this.server);
         } catch (UnknownHostException var6) {
            this.status = 2;
            Netalyzr.this.debug("Failed to initialize properly");
            return;
         }

         this.maxSend = 10000;
         this.port = var3;
         this.sendRate = var4;
         this.sendTime = 0;
         this.sendSize = 0;
         this.recvSize = 0;
         this.sendSlug = "";
         this.serverRecvCount = 0L;

         for(int var5 = 0; var5 < this.sendSize; ++var5) {
            this.sendSlug = this.sendSlug + ".";
         }

      }

      public NetProbeStats(String var2, int var3, int var4, int var5, int var6, int var7) {
         this.isPing = false;
         this.dupRange = 30000;
         this.dupData = new boolean[this.dupRange];
         this.dupCount = 0L;
         this.reorderCount = 0L;
         this.reorderIndex = -1;
         this.lossBurstCount = 0L;
         this.lossBurstLength = 0L;
         this.stopAtPing = false;
         this.serverRecvCount = 0L;
         this.server = var2;

         try {
            this.serverIP = InetAddress.getByName(this.server);
         } catch (UnknownHostException var9) {
            this.status = 2;
            Netalyzr.this.debug("Failed to initialize properly");
            return;
         }

         this.port = var3;
         this.sendRate = var4;
         this.sendTime = var5;
         this.sendSize = var6;
         this.recvSize = var7;
         this.sendSlug = "";

         for(int var8 = 0; var8 < this.sendSize; ++var8) {
            this.sendSlug = this.sendSlug + ".";
         }

      }

      public void run() {
         this.sendCount = 0L;
         this.recvCount = 0L;
         this.status = 2;
         long var1 = 0L;
         long var3 = 0L;
         long var5 = 0L;
         long var7 = (new Date()).getTime();
         long var9 = (new Date()).getTime();
         Netalyzr.this.debug("Start time is " + var7);
         Netalyzr.this.debug("Remote server is " + this.server);
         Netalyzr.this.debug("Remote port is " + this.port);
         byte[] var11 = new byte[2048];

         DatagramSocket var12;
         try {
            var12 = new DatagramSocket();
            var12.setSoTimeout(1);
         } catch (SocketException var27) {
            this.status = 2;
            Netalyzr.this.debug("Test aborted due to socket exception");
            return;
         }

         long var13 = 0L;
         this.recvPacketSize = 0;

         try {
            int var20;
            int var22;
            for(; this.stopAtPing && !Netalyzr.this.startedPingTest && this.sendCount < (long)this.maxSend || this.isPing && this.sendCount < (long)this.maxSend && !this.stopAtPing || !this.isPing && !this.stopAtPing && var9 - var7 < (long)(this.sendTime * 1000); var9 = (new Date()).getTime()) {
               var9 = (new Date()).getTime();
               if (this.sendRate == 0 || var9 - var13 > (long)this.sendRate) {
                  String var15 = var9 - var7 + " " + this.sendCount + " " + this.recvSize + " " + this.sendSlug;

                  try {
                     var12.send(new DatagramPacket(var15.getBytes(), var15.length(), this.serverIP, this.port));
                  } catch (IOException var28) {
                     if (this.isPing) {
                        Netalyzr.this.debug("Probing process caught IOException, just treating as a loss event.");
                     }
                  }

                  ++this.sendCount;
                  this.sendPacketSize = var15.length();
                  var13 = var9;
               }

               try {
                  DatagramPacket var30 = new DatagramPacket(var11, 2048);
                  var12.receive(var30);
                  var9 = (new Date()).getTime();
                  long var16 = var9 - var7;
                  String var18 = new String(var11);
                  String[] var19 = var18.split(" ");
                  var20 = Netalyzr.this.parseInt(var19[0]);
                  int var21 = Netalyzr.this.parseInt(var19[4]);
                  var22 = Netalyzr.this.parseInt(var19[2]);
                  if (var22 < this.reorderIndex) {
                     ++this.reorderCount;
                     Netalyzr.this.debug("Packet reordering observed");
                  }

                  this.reorderIndex = var22;
                  if (var22 < this.dupRange && this.dupData[var22]) {
                     Netalyzr.this.debug("Duplicate packet received");
                     ++this.dupCount;
                  }

                  if (var22 < this.dupRange) {
                     this.dupData[var22] = true;
                  }

                  if ((long)var21 > this.serverRecvCount) {
                     this.serverRecvCount = (long)var21;
                  }

                  if (var20 < 0) {
                     return;
                  }

                  var1 += var16 - (long)var20;
                  if (var30.getLength() != 0) {
                     this.recvPacketSize = var30.getLength();
                  }

                  if (var16 >= (long)(this.sendTime * 500)) {
                     ++var5;
                     var3 += var16 - (long)var20;
                  }

                  ++this.recvCount;
               } catch (SocketTimeoutException var26) {
               }
            }

            long var31 = (new Date()).getTime();
            Netalyzr.this.debug("All packets sent, waiting for the last responses");

            long var33;
            for(; !this.isPing && var9 - var7 < (long)(this.sendTime * 1500) || this.isPing && var31 > var9 - 3000L; var9 = (new Date()).getTime()) {
               try {
                  DatagramPacket var17 = new DatagramPacket(var11, 2048);
                  var12.receive(var17);
                  if (var17.getLength() != 0) {
                     this.recvPacketSize = var17.getLength();
                  }

                  var9 = (new Date()).getTime();
                  var33 = var9 - var7;
                  String var34 = new String(var11);
                  String[] var35 = var34.split(" ");
                  var22 = Netalyzr.this.parseInt(var35[0]);
                  int var23 = Netalyzr.this.parseInt(var35[4]);
                  int var24 = Netalyzr.this.parseInt(var35[2]);
                  if (var24 < this.reorderIndex) {
                     ++this.reorderCount;
                     Netalyzr.this.debug("Packet reordering observed");
                  }

                  this.reorderIndex = var24;
                  if (var24 < this.dupRange && this.dupData[var24]) {
                     Netalyzr.this.debug("Duplicate packet received");
                     ++this.dupCount;
                  }

                  if (var24 < this.dupRange) {
                     this.dupData[var24] = true;
                  }

                  if ((long)var23 > this.serverRecvCount) {
                     this.serverRecvCount = (long)var23;
                  }

                  if (var22 < 0) {
                     return;
                  }

                  var1 += var33 - (long)var22;
                  ++this.recvCount;
               } catch (SocketTimeoutException var25) {
               }
            }

            Netalyzr.this.debug("Now counting up bursts on loss");
            boolean var32 = false;
            var33 = 0L;
            var20 = 2;

            while(true) {
               if ((long)var20 >= this.sendCount || var20 >= this.dupRange) {
                  Netalyzr.this.debug("Probing done");
                  break;
               }

               if (this.dupData[var20]) {
                  var32 = false;
               } else if (!this.dupData[var20] && !this.dupData[var20 - 1] && !this.dupData[var20 - 2]) {
                  if (var32) {
                     ++var33;
                     if (var33 > this.lossBurstLength) {
                        this.lossBurstLength = var33;
                     }
                  } else {
                     var32 = true;
                     var33 = 3L;
                     ++this.lossBurstCount;
                     if (this.lossBurstLength < 3L) {
                        this.lossBurstLength = 3L;
                     }
                  }
               }

               ++var20;
            }
         } catch (IOException var29) {
            Netalyzr.this.debug("Probing process caught IOException!");
            this.status = 2;
            return;
         }

         this.avgRTT = (float)var1 / (float)this.recvCount;
         this.sustainedPPS = (float)var5 / (float)((double)this.sendTime * 0.5D);
         this.sustainedRTT = (float)var3 / (float)var5;
         Netalyzr.this.debug("Sent " + this.sendCount + " packets");
         Netalyzr.this.debug("Received " + this.recvCount + " packets");
         Netalyzr.this.debug("Average RTT " + this.avgRTT);
         Netalyzr.this.debug("Sustained RTT " + this.sustainedRTT);
         Netalyzr.this.debug("Server received " + this.serverRecvCount);
         Netalyzr.this.debug("Packets reordered " + this.reorderCount);
         Netalyzr.this.debug("Packets duplicated " + this.dupCount);
         Netalyzr.this.debug("Loss bursts observed " + this.lossBurstCount);
         if (!this.isPing) {
            Netalyzr.this.debug("Sustained PPS " + this.sustainedPPS);
            Netalyzr.this.debug("Send packet bandwidth " + (float)(this.sendPacketSize * 8) * this.sustainedPPS);
            Netalyzr.this.debug("Received packet bandwidth " + (float)(this.recvPacketSize * 8) * this.sustainedPPS);
         }

         Netalyzr.this.debug("Send packet size " + this.sendPacketSize);
         Netalyzr.this.debug("Received packet size " + this.recvPacketSize);
         this.status = 4;
      }
   }

   public class HttpResponse {
      private Hashtable headers = new Hashtable();
      private List headerList = new LinkedList();
      private int code = 0;
      private byte[] entity = null;
      private byte[] rawContent = null;
      private int setContentLengthValue = -1;

      HttpResponse() {
      }

      public void addHeader(String var1, String var2) {
         var1 = var1.replaceFirst("^\\s+", "").replaceFirst("\\s+$", "");
         var2 = var2.replaceFirst("^\\s+", "").replaceFirst("\\s+$", "");
         this.headers.put(var1.toLowerCase(), var2);
         this.headerList.add(var1);
      }

      public String getHeader(String var1) {
         return (String)this.headers.get(var1.toLowerCase());
      }

      public Map getHeaderFields() {
         return this.headers;
      }

      public List getHeaderList() {
         return this.headerList;
      }

      public int getContentLength() {
         int var1 = Netalyzr.this.parseInt(this.getHeader("content-length"));
         return var1 >= 0 ? var1 : this.setContentLengthValue;
      }

      public void setContentLength(int var1) {
         this.setContentLengthValue = var1;
      }

      public void setResponseCode(int var1) {
         this.code = var1;
      }

      public int getResponseCode() {
         return this.code;
      }

      public void setEntity(byte[] var1) {
         this.entity = var1;
      }

      public byte[] getEntity() {
         return this.entity;
      }

      public void setRawContent(byte[] var1) {
         this.rawContent = var1;
      }

      public byte[] getRawContent() {
         return this.rawContent;
      }
   }
}
