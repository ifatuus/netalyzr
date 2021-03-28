import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;

public class DNSMessage {
   public static Netalyzr netalyzrInstance;
   public static final int RCODE_OK = 0;
   public static final int RCODE_FMT = 1;
   public static final int RCODE_SERVFAIL = 2;
   public static final int RCODE_NXNAME = 3;
   public static final int RCODE_NOIMPLEMENT = 4;
   public static final int RCODE_REFUSE = 5;
   public static final int RTYPE_A = 1;
   public static final int RTYPE_NS = 2;
   public static final int RTYPE_CNAME = 5;
   public static final int RTYPE_SOA = 6;
   public static final int RTYPE_NULL = 10;
   public static final int RTYPE_PTR = 12;
   public static final int RTYPE_MX = 15;
   public static final int RTYPE_TXT = 16;
   public static final int RTYPE_OPT = 41;
   public static final int RTYPE_AAAA = 28;
   public static final int RTYPE_ANY = 255;
   public static final int RTYPE_ICSI = 169;
   public static final int RTYPE_ICSI2 = 1169;
   public static final int OPCODE_QUERY = 0;
   public static final int OPCODE_IQUERY = 1;
   public static final int OPCODE_STATUS = 2;
   public static final int CLASS_IN = 1;
   public static final int CLASS_CHAOS = 3;
   public static final int RTYPE_RRSIG = 46;
   public static final int RTYPE_DS = 43;
   public static final int RTYPE_DNSKEY = 48;
   public static final int RTYPE_NSEC = 47;
   public static final int RTYPE_NSEC3 = 50;
   int datagramSize;
   int id;
   boolean qr;
   byte opcode;
   boolean aa;
   boolean tc;
   boolean rd;
   boolean ra;
   byte z;
   byte rcode;
   DNSMessage.DNSQuestion[] question;
   DNSMessage.DNSAnswer[] answer;
   DNSMessage.DNSAnswer[] authority;
   DNSMessage.DNSAnswer[] additional;
   DNSMessage.EDNS_OPT opt;

   String rtypeName(int var1) {
      if (var1 == 1) {
         return "A";
      } else if (var1 == 2) {
         return "NS";
      } else if (var1 == 5) {
         return "CNAME";
      } else if (var1 == 6) {
         return "SOA";
      } else if (var1 == 10) {
         return "NULL";
      } else if (var1 == 12) {
         return "PTR";
      } else if (var1 == 15) {
         return "MX";
      } else if (var1 == 16) {
         return "TXT";
      } else if (var1 == 41) {
         return "OPT";
      } else if (var1 == 28) {
         return "AAAA";
      } else if (var1 == 255) {
         return "ANY";
      } else if (var1 == 169) {
         return "ICSI";
      } else if (var1 == 1169) {
         return "ICSI2";
      } else if (var1 == 46) {
         return "RRSIG";
      } else if (var1 == 43) {
         return "DS";
      } else if (var1 == 48) {
         return "DNSKEY";
      } else if (var1 == 47) {
         return "NSEC";
      } else {
         return var1 == 50 ? "NSEC3" : "TYPE" + var1;
      }
   }

   String className(int var1) {
      if (var1 == 1) {
         return "IN";
      } else {
         return var1 == 3 ? "CH" : "" + var1;
      }
   }

   void debug(String var1) {
      if (netalyzrInstance != null) {
         netalyzrInstance.debug("DNS: " + var1);
      }

   }

   DNSMessage.NamepackerData unpack(ByteBuffer var1, int var2, int var3) throws DNSMessage.DNSError {
      byte var4 = var1.get(var2);
      if (var4 == 0) {
         return new DNSMessage.NamepackerData("", 1);
      } else if (var3 > 100) {
         throw new DNSMessage.DNSError("Loop in compression pointer");
      } else {
         short var8 = var1.getShort(var2);
         if ((var8 & '쀀') == 49152) {
            return new DNSMessage.NamepackerData(this.unpack(var1, var8 & 16383, var3 + 1).data, 2);
         } else {
            var4 = var1.get(var2);
            byte[] var5 = new byte[var4];

            for(int var6 = 0; var6 < var4; ++var6) {
               var5[var6] = var1.get(var6 + var2 + 1);
            }

            String var9 = new String(var5);
            DNSMessage.NamepackerData var7 = this.unpack(var1, var2 + var4 + 1, var3);
            return var7.data.equals("") ? new DNSMessage.NamepackerData(var9, var4 + var7.length + 1) : new DNSMessage.NamepackerData(var9 + "." + var7.data, var4 + var7.length + 1);
         }
      }
   }

   public DNSMessage(String var1, int var2, int var3, int var4) throws DNSMessage.DNSError {
      this(var1, var2, var3);
      if (var4 != 0) {
         this.opt = new DNSMessage.EDNS_OPT(var4);
      }

   }

   public DNSMessage(String var1, int var2, int var3, int var4, boolean var5) throws DNSMessage.DNSError {
      this(var1, var2, var3);
      if (var4 != 0) {
         this.opt = new DNSMessage.EDNS_OPT(var4, var5);
      }

   }

   public DNSMessage(String var1, int var2) throws DNSMessage.DNSError {
      this(var1, var2, 1);
   }

   public DNSMessage(String var1, int var2, int var3) throws DNSMessage.DNSError {
      this.datagramSize = 0;
      this.opt = null;
      this.id = (new Random()).nextInt() & '\uffff';
      this.qr = false;
      this.opcode = 0;
      this.aa = false;
      this.tc = false;
      this.rd = false;
      this.ra = false;
      this.z = 0;
      this.rcode = 0;
      this.question = new DNSMessage.DNSQuestion[1];
      this.question[0] = new DNSMessage.DNSQuestion(var1, var2, var3);
      this.answer = new DNSMessage.DNSAnswer[0];
      this.authority = new DNSMessage.DNSAnswer[0];
      this.additional = new DNSMessage.DNSAnswer[0];
   }

   public byte[] pack() {
      ByteBuffer var1 = ByteBuffer.allocate(4096);
      var1.putShort(0, (short)this.id);
      short var2 = 0;
      if (this.qr) {
         var2 = (short)(var2 | 128);
      }

      var2 = (short)(var2 | this.opcode << 3);
      if (this.aa) {
         var2 = (short)(var2 | 4);
      }

      if (this.tc) {
         var2 = (short)(var2 | 2);
      }

      if (this.rd) {
         var2 = (short)(var2 | 1);
      }

      var1.put(2, (byte)var2);
      byte var3 = 0;
      var1.put(3, (byte)var3);
      var1.putShort(4, (short)1);
      var1.putShort(6, (short)0);
      var1.putShort(8, (short)0);
      if (this.opt == null) {
         var1.putShort(10, (short)0);
      } else {
         var1.putShort(10, (short)1);
      }

      this.question[0].pack(var1, 12);
      byte[] var4;
      if (this.opt != null) {
         this.opt.pack(var1, 12 + this.question[0].unpackLen);
         var4 = new byte[12 + this.question[0].unpackLen + this.opt.unpackLen];
      } else {
         var4 = new byte[12 + this.question[0].unpackLen];
      }

      for(int var5 = 0; var5 < var4.length; ++var5) {
         var4[var5] = var1.get(var5);
      }

      return var4;
   }

   public DNSMessage(byte[] var1) throws DNSMessage.DNSError {
      try {
         this.datagramSize = var1.length;
         this.opt = null;
         ByteBuffer var2 = ByteBuffer.wrap(var1);
         this.id = var2.getShort(0);
         if (this.id < 0) {
            this.id &= 65535;
         }

         short var12 = (short)var2.get(2);
         this.qr = (var12 & 128) != 0;
         this.opcode = (byte)((var12 & 120) >> 3);
         this.aa = (var12 & 4) != 0;
         this.tc = (var12 & 2) != 0;
         this.rd = (var12 & 1) != 0;
         short var13 = (short)var2.get(3);
         this.ra = (var13 & 128) != 0;
         this.rcode = (byte)(var13 & 15);
         this.z = (byte)((var13 & 112) >> 4);
         short var5 = var2.getShort(4);
         short var6 = var2.getShort(6);
         short var7 = var2.getShort(8);
         short var8 = var2.getShort(10);
         this.question = new DNSMessage.DNSQuestion[var5];
         this.answer = new DNSMessage.DNSAnswer[var6];
         this.authority = new DNSMessage.DNSAnswer[var7];
         this.additional = new DNSMessage.DNSAnswer[var8];
         int var9 = 12;

         int var10;
         for(var10 = 0; var10 < var5; ++var10) {
            this.question[var10] = new DNSMessage.DNSQuestion(var2, var9);
            var9 += this.question[var10].unpackLen;
         }

         for(var10 = 0; var10 < var6; ++var10) {
            this.answer[var10] = new DNSMessage.DNSAnswer(var2, var9);
            var9 += this.answer[var10].unpackLen;
         }

         for(var10 = 0; var10 < var7; ++var10) {
            this.authority[var10] = new DNSMessage.DNSAnswer(var2, var9);
            var9 += this.authority[var10].unpackLen;
         }

         for(var10 = 0; var10 < var8; ++var10) {
            this.additional[var10] = new DNSMessage.DNSAnswer(var2, var9);
            var9 += this.additional[var10].unpackLen;
         }

      } catch (Exception var11) {
         if (!this.tc) {
            this.debug("Caught exception " + var11.toString());
            StackTraceElement[] var3 = var11.getStackTrace();

            for(int var4 = 0; var4 < var3.length; ++var4) {
               this.debug("  " + var3[var4].toString());
            }

            throw new DNSMessage.DNSError("Problem during parsing, caught error " + var11);
         }
      }
   }

   void print() {
      this.debug("id: " + this.id + " qr: " + this.qr + " opcode: " + this.opcode);
      this.debug("aa: " + this.aa + " tc: " + this.tc + " rd: " + this.rd + " ra: " + this.ra);
      this.debug("rcode: " + this.rcode);
      this.debug("Questions:");

      int var1;
      for(var1 = 0; var1 < this.question.length; ++var1) {
         this.question[var1].print();
      }

      this.debug("Answers:");

      for(var1 = 0; var1 < this.answer.length; ++var1) {
         this.answer[var1].print();
      }

      this.debug("Authority:");

      for(var1 = 0; var1 < this.authority.length; ++var1) {
         this.authority[var1].print();
      }

      this.debug("Additional:");

      for(var1 = 0; var1 < this.additional.length; ++var1) {
         this.additional[var1].print();
      }

   }

   void print_short() {
      this.debug("id: " + this.id + " rcode : " + this.rcode);
      this.debug("Questions:");

      int var1;
      for(var1 = 0; var1 < this.question.length; ++var1) {
         this.question[var1].print();
      }

      this.debug("Answers:");

      for(var1 = 0; var1 < this.answer.length; ++var1) {
         this.answer[var1].print();
      }

      this.debug("Authority: " + this.authority.length);
      this.debug("Additional: " + this.additional.length);
   }

   public class DNSAnswer {
      public String rname;
      public int rtype;
      public int rclass = 1;
      public int unpackLen = 0;
      public long ttl;
      public int rdlen;
      DNSMessage.DNSRdata rdata;

      public DNSAnswer(String var2, int var3, int var4) {
         this.rname = var2;
         this.rtype = var3;
         this.ttl = (long)var4;
      }

      DNSAnswer(ByteBuffer var2, int var3) throws DNSMessage.DNSError {
         DNSMessage.NamepackerData var4 = DNSMessage.this.unpack(var2, var3, 0);
         this.rname = var4.data;
         this.rtype = var2.getShort(var3 + var4.length);
         if (this.rtype < 0) {
            this.rtype &= 65535;
         }

         this.rclass = var2.getShort(var3 + var4.length + 2);
         this.ttl = (long)var2.getInt(var3 + var4.length + 4);
         if (this.ttl < 0L) {
            this.ttl &= -1L;
         }

         this.rdlen = var2.getShort(var3 + var4.length + 8);
         if (this.rdlen < 0) {
            this.rdlen &= 65535;
         }

         this.unpackLen = var4.length + 10 + this.rdlen;
         if (this.rtype != 5 && this.rtype != 2 && this.rtype != 12) {
            if (this.rtype == 1) {
               this.rdata = DNSMessage.this.new DNSRdataIP(var2, var3 + var4.length + 10, 4);
            } else if (this.rtype == 28) {
               this.rdata = DNSMessage.this.new DNSRdataIP(var2, var3 + var4.length + 10, 16);
            } else if (this.rtype == 41) {
               this.rdata = DNSMessage.this.new DNSRdataOPT(var2, var3);
            } else if (this.rtype != 16 && this.rtype != 169 && this.rtype != 1169) {
               if (this.rtype == 6) {
                  this.rdata = DNSMessage.this.new DNSRdataSOA(var2, var3 + var4.length + 10, this.rdlen);
               } else if (this.rtype == 43) {
                  this.rdata = DNSMessage.this.new DNSRdataDS(var2, var3 + var4.length + 10, this.rdlen);
               } else if (this.rtype == 46) {
                  this.rdata = DNSMessage.this.new DNSRdataRRSIG(var2, var3 + var4.length + 10, this.rdlen);
               } else if (this.rtype == 48) {
                  this.rdata = DNSMessage.this.new DNSRdataDNSKEY(var2, var3 + var4.length + 10, this.rdlen);
               } else if (this.rtype == 47) {
                  this.rdata = DNSMessage.this.new DNSRdataNSEC(var2, var3 + var4.length + 10, this.rdlen);
               } else if (this.rtype == 50) {
                  this.rdata = DNSMessage.this.new DNSRdataNSEC3(var2, var3 + var4.length + 10, this.rdlen);
               } else {
                  this.rdata = DNSMessage.this.new DNSRdata();
               }
            } else {
               this.rdata = DNSMessage.this.new DNSRdataTXT(var2, var3 + var4.length + 10, this.rdlen);
            }
         } else {
            var4 = DNSMessage.this.unpack(var2, var3 + var4.length + 10, 0);
            this.rdata = DNSMessage.this.new DNSRdataReference(var4.data);
         }

      }

      void print() {
         DNSMessage.this.debug(this.rname + " RTYPE: " + DNSMessage.this.rtypeName(this.rtype) + " TTL: " + this.ttl);
         this.rdata.print();
      }

      String repr() {
         return this.rname + ".\t" + this.ttl + "\t" + DNSMessage.this.className(this.rclass) + "\t" + DNSMessage.this.rtypeName(this.rtype) + "\t" + this.rdata.repr();
      }
   }

   public class EDNS_OPT extends DNSMessage.DNSAnswer {
      boolean do_bit;

      public EDNS_OPT(int var2, boolean var3) {
         super(".", 41, 0);
         this.rclass = var2;
         this.do_bit = var3;
      }

      public EDNS_OPT(int var2) {
         super(".", 41, 0);
         this.rclass = var2;
         this.do_bit = false;
      }

      void pack(ByteBuffer var1, int var2) {
         var1.put(var2, (byte)0);
         byte var3 = 1;
         var1.putShort(var2 + var3, (short)this.rtype);
         var1.putShort(var2 + var3 + 2, (short)this.rclass);
         if (this.do_bit) {
            var1.putInt(var2 + var3 + 4, (int)this.ttl | '耀');
         } else {
            var1.putInt(var2 + var3 + 4, (int)this.ttl | '耀');
         }

         var1.putShort(var2 + var3 + 8, (short)0);
         this.unpackLen = var3 + 10;
      }
   }

   public class DNSRdataOPT extends DNSMessage.DNSRdata {
      int mtu;
      long ttl;

      public DNSRdataOPT(ByteBuffer var2, int var3) {
         super();
         this.mtu = var2.getShort(var3 + 3);
         if (this.mtu < 0) {
            this.mtu &= 65535;
         }

         DNSMessage.this.debug("OPT parsing incomplete");
      }

      void print() {
         DNSMessage.this.debug("EDNS MTU: " + this.mtu);
      }
   }

   public class DNSRdataIP extends DNSMessage.DNSRdata {
      public InetAddress rdata;

      public DNSRdataIP(ByteBuffer var2, int var3, int var4) throws DNSMessage.DNSError {
         super();
         byte[] var5 = new byte[var4];

         for(int var6 = 0; var6 < var4; ++var6) {
            var5[var6] = var2.get(var6 + var3);
         }

         try {
            this.rdata = InetAddress.getByAddress(var5);
         } catch (UnknownHostException var7) {
            throw DNSMessage.this.new DNSError("Problem in parsing address record");
         }
      }

      void print() {
         DNSMessage.this.debug("" + this.rdata.getHostAddress());
      }
   }

   public class DNSRdataTXT extends DNSMessage.DNSRdata {
      String[] txt;

      public DNSRdataTXT(ByteBuffer var2, int var3, int var4) throws DNSMessage.DNSError {
         super();
         int var5 = 1;
         int var7 = 0;

         for(this.txt = new String[0]; var7 < var4; ++var5) {
            int var9 = var2.get(var3 + var7);
            if (var9 < 0) {
               var9 &= 255;
            }

            byte[] var6 = new byte[var9];

            int var10;
            for(var10 = 0; var10 < var9; ++var10) {
               var6[var10] = var2.get(var3 + var7 + 1 + var10);
            }

            var7 += var9 + 1;
            String[] var8 = this.txt;
            this.txt = new String[var5];

            for(var10 = 0; var10 < var8.length; ++var10) {
               this.txt[var10] = var8[var10];
            }

            try {
               this.txt[var5 - 1] = new String(var6, "US-ASCII");
            } catch (UnsupportedEncodingException var11) {
               throw DNSMessage.this.new DNSError("Unsupported encoding: " + var11);
            }
         }

      }

      void print() {
         String var1 = "[";

         for(int var2 = 0; var2 < this.txt.length; ++var2) {
            var1 = var1 + "\"" + this.txt[var2] + "\"";
            if (var2 < this.txt.length - 1) {
               var1 = var1 + ", ";
            }
         }

         var1 = var1 + "]";
         DNSMessage.this.debug(var1);
      }
   }

   public class DNSRdataRRSIG extends DNSMessage.DNSRdata {
      int type;
      int algorithm;
      int labels;
      long orig_ttl;
      long expires;
      long inception;
      int tag;
      String name;
      byte[] signature;

      public DNSRdataRRSIG(ByteBuffer var2, int var3, int var4) throws DNSMessage.DNSError {
         super();
         this.type = var2.getShort(var3);
         if (this.type < 0) {
            this.type &= 65535;
         }

         this.algorithm = var2.get(var3 + 2);
         if (this.algorithm < 0) {
            this.algorithm &= 255;
         }

         this.labels = var2.get(var3 + 3);
         if (this.labels < 0) {
            this.labels &= 255;
         }

         this.orig_ttl = (long)var2.getInt(var3 + 4);
         if (this.orig_ttl < 0L) {
            this.orig_ttl &= -1L;
         }

         this.expires = (long)var2.getInt(var3 + 8);
         if (this.expires < 0L) {
            this.expires &= -1L;
         }

         this.inception = (long)var2.getInt(var3 + 12);
         if (this.inception < 0L) {
            this.inception &= -1L;
         }

         this.tag = var2.getShort(var3 + 16);
         if (this.tag < 0) {
            this.tag &= 65535;
         }

         DNSMessage.NamepackerData var5 = DNSMessage.this.unpack(var2, var3 + 18, 0);
         this.name = var5.data;
         this.signature = new byte[var4 - 18 - (this.name.length() + 1)];

         for(int var6 = 0; var6 < this.signature.length; ++var6) {
            this.signature[var6] = var2.get(var3 + 18 + this.name.length() + 1 + var6);
         }

      }

      String repr() {
         String var1 = "";
         var1 = DNSMessage.this.rtypeName(this.type) + " " + this.algorithm + " " + this.labels + " " + this.orig_ttl + " " + this.expires + " " + this.inception + " " + this.tag + " " + this.name + ". " + DatatypeConverter.printBase64Binary(this.signature);
         return var1;
      }

      void print() {
         String var1 = "RRSIG";
         DNSMessage.this.debug(var1 + " " + this.repr());
      }
   }

   public class DNSRdataNSEC3 extends DNSMessage.DNSRdata {
      String nextdomain;
      short algorithm;
      short flags;
      int iterations;
      byte[] salt;
      byte[] hash;
      byte[] bitmask;

      public DNSRdataNSEC3(ByteBuffer var2, int var3, int var4) throws DNSMessage.DNSError {
         super();
         this.algorithm = (short)var2.get(var3);
         if (this.algorithm < 0) {
            this.algorithm = (short)(this.algorithm & 255);
         }

         this.flags = (short)var2.get(var3 + 1);
         if (this.flags < 0) {
            this.flags = (short)(this.flags & 255);
         }

         this.iterations = var2.getShort(var3 + 2);
         if (this.iterations < 0) {
            this.iterations &= 65535;
         }

         int var5 = var2.get(var3 + 4);
         if (var5 < 0) {
            var5 &= 255;
         }

         int var6;
         if (var5 != 0) {
            this.salt = new byte[var5];

            for(var6 = 0; var6 < var5; ++var6) {
               this.salt[var6] = var2.get(var3 + 5 + var6);
            }
         }

         var6 = var2.get(var3 + 5 + var5);
         if (var6 < 0) {
            var6 &= 255;
         }

         this.hash = new byte[var6];

         int var7;
         for(var7 = 0; var7 < var6; ++var7) {
            this.hash[var7] = var2.get(var3 + 6 + var5 + var7);
         }

         this.bitmask = new byte[var4 - (6 + var5 + var6)];

         for(var7 = 0; var7 < this.bitmask.length; ++var7) {
            this.bitmask[var7] = var2.get(var3 + 6 + var5 + var6 + var7);
         }

      }

      String repr() {
         boolean var1 = false;
         int var2 = 0;
         String var3 = "";
         var3 = var3 + this.algorithm + " " + this.flags + " " + this.iterations + " ";
         if (this.salt == null) {
            var3 = var3 + "- ";
         } else {
            var3 = var3 + DatatypeConverter.printHexBinary(this.salt) + " ";
         }

         var3 = var3 + "NEED_TO_ENCODE_BASE32_OF_HASH ";

         while(!var1) {
            int var4 = this.bitmask[var2];
            if (var4 < 0) {
               var4 &= 255;
            }

            int var5 = this.bitmask[var2 + 1];
            if (var5 < 0) {
               var5 &= 255;
            }

            for(int var6 = 0; var6 < var5; ++var6) {
               byte var7 = this.bitmask[var2 + 2 + var6];

               for(int var8 = 0; var8 < 8; ++var8) {
                  byte var9 = (byte)(var7 & 1 << 7 - var8);
                  if (var9 != 0) {
                     var3 = var3 + DNSMessage.this.rtypeName(var4 * 256 + var6 * 8 + var8);
                     var3 = var3 + " ";
                  }
               }
            }

            var2 = var2 + 2 + var5;
            if (var2 >= this.bitmask.length) {
               var1 = true;
            }
         }

         return var3.trim();
      }

      void print() {
         String var1 = "NSEC3 " + this.repr();
         DNSMessage.this.debug(var1);
      }
   }

   public class DNSRdataNSEC extends DNSMessage.DNSRdata {
      String nextdomain;
      byte[] bitmask;

      public DNSRdataNSEC(ByteBuffer var2, int var3, int var4) throws DNSMessage.DNSError {
         super();
         DNSMessage.NamepackerData var5 = DNSMessage.this.unpack(var2, var3, 0);
         this.nextdomain = var5.data;
         this.bitmask = new byte[var4 - var5.length];

         for(int var6 = 0; var6 < this.bitmask.length; ++var6) {
            this.bitmask[var6] = var2.get(var3 + var5.length + var6);
         }

      }

      String repr() {
         boolean var1 = false;
         int var2 = 0;
         String var3 = "";
         var3 = var3 + this.nextdomain + ". ";

         while(!var1) {
            int var4 = this.bitmask[var2];
            if (var4 < 0) {
               var4 &= 255;
            }

            int var5 = this.bitmask[var2 + 1];
            if (var5 < 0) {
               var5 &= 255;
            }

            for(int var6 = 0; var6 < var5; ++var6) {
               byte var7 = this.bitmask[var2 + 2 + var6];

               for(int var8 = 0; var8 < 8; ++var8) {
                  byte var9 = (byte)(var7 & 1 << 7 - var8);
                  if (var9 != 0) {
                     var3 = var3 + DNSMessage.this.rtypeName(var4 * 256 + var6 * 8 + var8);
                     var3 = var3 + " ";
                  }
               }
            }

            var2 = var2 + 2 + var5;
            if (var2 >= this.bitmask.length) {
               var1 = true;
            }
         }

         return var3.trim();
      }

      void print() {
         String var1 = "NSEC " + this.repr();
         DNSMessage.this.debug(var1);
      }
   }

   public class DNSRdataDNSKEY extends DNSMessage.DNSRdata {
      int flags;
      short protocol;
      short algorithm;
      byte[] key;

      public DNSRdataDNSKEY(ByteBuffer var2, int var3, int var4) throws DNSMessage.DNSError {
         super();
         this.flags = var2.getShort(var3);
         if (this.flags < 0) {
            this.flags &= 65535;
         }

         this.protocol = (short)var2.get(var3 + 2);
         this.algorithm = (short)var2.get(var3 + 3);
         if (this.algorithm < 0) {
            this.algorithm = (short)(this.algorithm & 255);
         }

         if (this.protocol < 0) {
            this.protocol = (short)(this.protocol & 255);
         }

         this.key = new byte[var4 - 4];

         for(int var5 = 0; var5 < this.key.length; ++var5) {
            this.key[var5] = var2.get(var3 + 4 + var5);
         }

      }

      String repr() {
         String var1 = "";
         var1 = var1 + this.flags + " " + this.protocol + " " + this.algorithm + " " + DatatypeConverter.printBase64Binary(this.key);
         return var1;
      }

      void print() {
         String var1 = "DNSKEY " + this.repr();
         DNSMessage.this.debug(var1);
      }
   }

   public class DNSRdataDS extends DNSMessage.DNSRdata {
      int key_tag;
      short algorithm;
      short digest_type;
      byte[] digest;

      public DNSRdataDS(ByteBuffer var2, int var3, int var4) throws DNSMessage.DNSError {
         super();
         this.key_tag = var2.getShort(var3);
         if (this.key_tag < 0) {
            this.key_tag &= 65535;
         }

         this.algorithm = (short)var2.get(var3 + 2);
         this.digest_type = (short)var2.get(var3 + 3);
         if (this.algorithm < 0) {
            this.algorithm = (short)(this.algorithm & 255);
         }

         if (this.digest_type < 0) {
            this.digest_type = (short)(this.digest_type & 255);
         }

         this.digest = new byte[var4 - 4];

         for(int var5 = 0; var5 < this.digest.length; ++var5) {
            this.digest[var5] = var2.get(var3 + 4 + var5);
         }

      }

      String repr() {
         String var1 = "";
         var1 = var1 + this.key_tag + " " + this.algorithm + " " + DatatypeConverter.printHexBinary(this.digest);
         return var1;
      }

      void print() {
         String var1 = "DS " + this.repr();
         DNSMessage.this.debug(var1);
      }
   }

   public class DNSRdataReference extends DNSMessage.DNSRdata {
      public String rdata;

      public DNSRdataReference(String var2) {
         super();
         this.rdata = var2;
      }

      void print() {
         DNSMessage.this.debug(this.rdata);
      }
   }

   public class DNSRdataSOA extends DNSMessage.DNSRdata {
      String mname;
      String rname;
      long serial;
      long refresh;
      long retry;
      long expire;

      public DNSRdataSOA(ByteBuffer var2, int var3, int var4) throws DNSMessage.DNSError {
         super();
         DNSMessage.NamepackerData var5 = DNSMessage.this.unpack(var2, var3, 0);
         this.mname = var5.data;
         DNSMessage.NamepackerData var6 = DNSMessage.this.unpack(var2, var3 + var5.length, 0);
         this.rname = var6.data;
         this.serial = (long)var2.getInt(var3 + var5.length + var6.length);
         if (this.serial < 0L) {
            this.serial &= -1L;
         }

         this.refresh = (long)var2.getInt(var3 + var5.length + var6.length + 4);
         if (this.refresh < 0L) {
            this.refresh &= -1L;
         }

         this.retry = (long)var2.getInt(var3 + var5.length + var6.length + 8);
         if (this.retry < 0L) {
            this.retry &= -1L;
         }

         this.expire = (long)var2.getInt(var3 + var5.length + var6.length + 12);
         if (this.expire < 0L) {
            this.expire &= -1L;
         }

      }

      String repr() {
         return this.mname + ". " + this.rname + ". " + this.serial + " " + this.refresh + " " + this.retry + " " + this.expire;
      }
   }

   public class DNSRdata {
      void print() {
         DNSMessage.this.debug("RDATA Unknown");
      }

      void pack(ByteBuffer var1, int var2) throws DNSMessage.DNSError {
         throw DNSMessage.this.new DNSError("Problem in parsing A record");
      }

      String repr() {
         return "No Representation";
      }
   }

   public class DNSQuestion {
      public String qname;
      public int qtype;
      public int qclass;
      public int unpackLen;

      public DNSQuestion(String var2, int var3) throws DNSMessage.DNSError {
         this(var2, var3, 1);
      }

      public DNSQuestion(String var2, int var3, int var4) throws DNSMessage.DNSError {
         this.qclass = 1;
         this.unpackLen = 0;
         this.qname = var2;
         this.qtype = var3;
         this.qclass = var4;
         if (this.qclass != 1 && this.qclass != 3) {
            throw DNSMessage.this.new DNSError("Unknown query class " + this.qclass);
         }
      }

      DNSQuestion(ByteBuffer var2, int var3) throws DNSMessage.DNSError {
         this.qclass = 1;
         this.unpackLen = 0;
         DNSMessage.NamepackerData var4 = DNSMessage.this.unpack(var2, var3, 0);
         this.qname = var4.data;
         this.unpackLen = var4.length + 4;
         this.qtype = var2.getShort(var3 + var4.length);
         this.qclass = var2.getShort(var3 + var4.length + 2);
      }

      void pack(ByteBuffer var1, int var2) {
         String[] var3 = this.qname.split("\\.");
         int var4 = 0;
         if (this.qname == "") {
            DNSMessage.this.debug("Empty name, so just a 0");
         } else {
            for(int var5 = 0; var5 < var3.length; ++var5) {
               var1.put(var2 + var4, (byte)var3[var5].length());
               byte[] var6 = new byte[0];

               try {
                  var6 = var3[var5].getBytes("US-ASCII");
               } catch (UnsupportedEncodingException var8) {
               }

               for(int var7 = 0; var7 < var6.length; ++var7) {
                  var1.put(var2 + var4 + var7 + 1, var6[var7]);
               }

               var4 += 1 + var3[var5].length();
            }
         }

         var1.put(var2 + var4, (byte)0);
         ++var4;
         var1.putShort(var2 + var4, (short)this.qtype);
         var1.putShort(var2 + var4 + 2, (short)this.qclass);
         this.unpackLen = var4 + 4;
      }

      void print() {
         DNSMessage.this.debug(this.qname + " QTYPE: " + this.qtype + " QCLASS: " + this.qclass);
      }
   }

   class NamepackerData {
      public String data;
      public int length;

      public NamepackerData(String var2, int var3) {
         this.data = var2;
         this.length = var3;
      }
   }

   public class DNSError extends Exception {
      public String msg;
      public static final long serialVersionUID = 2623513L;

      public DNSError(String var2) {
         this.msg = var2;
         DNSMessage.this.debug("ERROR: " + this.msg);
      }
   }
}
