import java.applet.Applet;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.net.URL;
import java.util.Date;

public class NetalyzrApplet extends Applet implements NetalyzrShell, Runnable, MouseListener {
   Netalyzr neta;
   boolean doRedraw = false;
   boolean testsComplete = false;
   String summaryURL;
   Color redColor = new Color(160, 16, 16);
   volatile Thread backgroundThread;
   static final long serialVersionUID = 1L;

   public void init() {
      this.neta = new Netalyzr(this);
      this.neta.init();
   }

   public void start() {
      this.setBackground(Color.white);
      this.getGraphics().clearRect(0, 0, this.getWidth(), this.getHeight());
      this.neta.start();
      if (this.backgroundThread == null) {
         this.backgroundThread = new Thread(this);
         this.backgroundThread.start();
      }

   }

   public void run() {
      while(true) {
         try {
            Thread.sleep(500L);
            this.repaint();
            if (!this.neta.isLatestVersion) {
               return;
            }
         } catch (Exception var2) {
            this.neta.debugStackTrace(var2);
         }
      }
   }

   public void stop() {
      this.backgroundThread = null;
      this.neta.stop();
   }

   public void showSummary() {
      try {
         if (this.neta.mode instanceof NetalyzrEmbeddedMode) {
            this.getAppletContext().showDocument(new URL(this.summaryURL), "_blank");
         } else {
            this.getAppletContext().showDocument(new URL(this.summaryURL), "_self");
         }
      } catch (Exception var2) {
         this.neta.debug("Got exception " + var2 + " when switching to results.");
      }

   }

   public void mouseClicked(MouseEvent var1) {
      this.showSummary();
   }

   public void mousePressed(MouseEvent var1) {
   }

   public void mouseReleased(MouseEvent var1) {
   }

   public void mouseEntered(MouseEvent var1) {
      this.getAppletContext().showStatus(this.summaryURL);
      this.setCursor(Cursor.getPredefinedCursor(12));
   }

   public void mouseExited(MouseEvent var1) {
      this.getAppletContext().showStatus("");
      this.setCursor(Cursor.getPredefinedCursor(0));
   }

   public String getBackendHost() {
      return this.getDocumentBase().getHost();
   }

   public int getBackendPort() {
      return this.getDocumentBase().getPort();
   }

   public URL getResource(String var1) {
      return this.getClass().getResource(var1);
   }

   public int getBuildNumber() {
      return 57861;
   }

   public void enableRedraw() {
      this.doRedraw = true;
   }

   public void updateDisplay() {
      this.update(this.getGraphics());
   }

   public void complete(String var1) {
      this.summaryURL = var1;
      this.testsComplete = true;
      this.showSummary();
      if (this.neta.mode instanceof NetalyzrEmbeddedMode) {
         this.addMouseListener(this);
      }

   }

   public void update(Graphics var1) {
      if (this.neta.isLatestVersion && this.neta.initSucceeded) {
         if (this.doRedraw) {
            this.paint(var1);
         }

         long var2 = (new Date()).getTime() / 1000L;
         var1.setColor(this.testsComplete ? Color.white : Color.lightGray);
         var1.fillRect(this.getWidth() / 2 - 6, 30, 4, 4);
         var1.fillRect(this.getWidth() / 2 + 0, 30, 4, 4);
         var1.fillRect(this.getWidth() / 2 + 6, 30, 4, 4);
         if (!this.testsComplete) {
            var1.setColor(Color.gray);
            if (var2 % 4L == 0L) {
               var1.fillRect(this.getWidth() / 2 - 6, 30, 4, 4);
            } else if (var2 % 4L != 1L && var2 % 4L != 3L) {
               var1.fillRect(this.getWidth() / 2 + 6, 30, 4, 4);
            } else {
               var1.fillRect(this.getWidth() / 2, 30, 4, 4);
            }
         }

      } else {
         if (this.doRedraw) {
            this.paint(var1);
         }

      }
   }

   public void paintMessage(Graphics var1, String[] var2) {
      byte var3 = 20;
      FontMetrics var4 = var1.getFontMetrics();
      var1.clearRect(0, 0, this.getWidth(), this.getHeight());

      for(int var5 = 0; var5 < var2.length; ++var5) {
         int var6 = var4.stringWidth(var2[var5]);
         var1.drawString(var2[var5], (this.getWidth() - var6) / 2, var3 + var5 * (var4.getHeight() + 4));
      }

   }

   public void paint(Graphics var1) {
      Graphics2D var2 = (Graphics2D)var1;
      var2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
      var2.setColor(Color.black);
      String[] var12;
      if (!this.neta.initSucceeded) {
         var12 = new String[]{this.neta.getLocalString("noInit"), "*** " + this.neta.initFailureMsg + " ***", this.neta.getLocalString("seeFAQ")};
         this.paintMessage(var2, var12);
      } else if (!this.neta.isLatestVersion) {
         var12 = new String[]{this.neta.getLocalString("cachedApplet"), this.neta.getLocalString("clearCache")};
         this.paintMessage(var2, var12);
      } else {
         FontMetrics var3 = var2.getFontMetrics();
         byte var4 = 20;
         byte var5 = 80;
         int var6 = this.getWidth() - 2 * var5;
         int var7 = var6 / this.neta.getNumTests();
         int var8 = var4 + 20;
         var2.clearRect(0, 0, this.getWidth(), var8 - 2);
         var2.clearRect(0, var8 + 2, this.getWidth(), this.getHeight());
         String var10 = this.testsComplete ? "." : "...";
         String var9;
         if (this.neta.getCurTestIdx() < this.neta.getNumTests()) {
            Netalyzr.Test var11 = this.neta.getTest(this.neta.getCurTestIdx());
            var9 = var11.idleMsg + var10;
         } else {
            var9 = this.neta.idleMsg + var10;
         }

         int var13 = var3.stringWidth(var9);
         var2.drawString(var9, (this.getWidth() - var13) / 2, var4);
         if (this.neta.getCurTestIdx() < this.neta.getNumTests()) {
            var9 = this.neta.getLocalString("patience");
            var13 = var3.stringWidth(var9);
            var2.drawString(var9, (this.getWidth() - var13) / 2, var8 + 20);
            if (!(this.neta.mode instanceof NetalyzrEmbeddedMode)) {
               var2.setColor(this.redColor);
            }

            var2.drawLine(var5, var8, var5 + this.neta.getCurTestIdx() * var7, var8);
            var2.drawLine(var5, var8 - 1, var5, var8 + 1);
            var2.setColor(Color.lightGray);
            var2.drawLine(var5 + this.neta.getCurTestIdx() * var7, var8, var5 + var6, var8);
            var2.drawLine(var5 + var6, var8 - 1, var5 + var6, var8 + 1);
            var2.setColor(Color.black);
         } else {
            if (!(this.neta.mode instanceof NetalyzrEmbeddedMode)) {
               var2.setColor(this.redColor);
            }

            var2.drawLine(var5, var8, var5 + var6, var8);
            if (!(this.neta.mode instanceof NetalyzrEmbeddedMode)) {
               var2.setColor(Color.black);
            }

            var2.drawLine(var5, var8 - 1, var5, var8 + 1);
            var2.drawLine(var5 + var6, var8 - 1, var5 + var6, var8 + 1);
         }

         this.doRedraw = false;
      }
   }
}
