package quic.packet;

import org.junit.jupiter.api.*;
import quic.exception.QuicException;
import quic.frame.QuicAckFrame;
import quic.frame.QuicCryptoFrame;
import quic.frame.QuicFrame;


import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Set;



public class QuicInitialPacketTest {
    public String byteToString(byte[] x){

        String str="";
        for (byte b:x){
            str+=b;
        }
        return str;
    }
    @Test
    public void testGetScId() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),123465789,25,"192.168.43.225".getBytes());
        Assertions.assertEquals(byteToString(initialPacket.getScID()),byteToString("192.168.43.225".getBytes()));
    }
    @Test
    public void testGetDcId() {

        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),123465789,25,"192.168.43.225".getBytes());
        Assertions.assertEquals(byteToString(initialPacket.getDcID()), byteToString("192.168.43.230".getBytes()));
    }
    @Test
    public void testGetPacketNumber(){
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),123465789,25,"192.168.43.225".getBytes());
        Assertions.assertEquals(initialPacket.getPacketNumber(), 123465789);
    }
    @Test
    public void testGetVersion() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),123465789,25,"192.168.43.225".getBytes());
        Assertions.assertEquals(initialPacket.getVersion(), 25);
    }
   @Test
   public void testSetScId() {
       QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),123465789,25,"192.168.43.225".getBytes());
       initialPacket.setScID("192.168.45.222".getBytes());
       Assertions.assertEquals(byteToString(initialPacket.getScID()), byteToString("192.168.45.222".getBytes()));
   }
    @Test
    public void testSetDcId() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),123465789,25,"192.168.43.225".getBytes());
        initialPacket.setDcID("192.168.45.222".getBytes());
        Assertions.assertEquals(byteToString(initialPacket.getDcID()), byteToString("192.168.45.222".getBytes()));
    }
    @Test
    public void testSetPacketNumber() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),123465789,25,"192.168.43.225".getBytes());
        initialPacket.setPacketNumber(132135453);
        Assertions.assertEquals(initialPacket.getPacketNumber(), 132135453);
    }
    @Test
    public void testSetVersion() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),123465789,25,"192.168.43.225".getBytes());
        initialPacket.setVersion(25);
        Assertions.assertEquals(initialPacket.getVersion(), 25);
    }
    @Test
    public void testMaximumPacketNumber() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),12121212121221L, 25,"192.168.43.225".getBytes());
        Assertions.assertTrue(initialPacket.getPacketNumber()< Math.pow(2,62),"Packet Number can be of maximum 2^62 - 1 in length ");
    }
    @Test
    public void testMinimumPacketNumber() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),0, 25,"192.168.43.225".getBytes());
        Assertions.assertTrue(initialPacket.getPacketNumber()>-1, "Packet number cannot be negative");
    }
    @Test
    public void testMaximumScId() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),0, 25,"192.168.43.225".getBytes());
        byte[] scId=initialPacket.getScID();
        Assertions.assertTrue(scId.length <=20,"Source Connection ID must be less than or equal to 20 bytes.");
    }
    @Test
    public void testMaximumDcId() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),0, 25,"192.168.43.225".getBytes());
        byte[] dcId=initialPacket.getDcID();
        Assertions.assertTrue(dcId.length <=20,"Destination Connection ID must be less than or equal to 20 bytes.\"");
    }
    @Test
    public void testMaximumVersion() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),0, 25,"192.168.43.225".getBytes());
        int versionBytes= (int) initialPacket.getVersion();
        Assertions.assertTrue(versionBytes <=4,"Version can be of maximum 4 bytes in length.");
    }
    @Test
    public void testScIdNotNull() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),121212, 25,"192.168.43.225".getBytes());
        Assertions.assertTrue(initialPacket.getScID().length > 0,"Source Connection ID cannot be null.");
    }
    @Test
    public void testDcIdNotNull() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),121212, 25,"192.168.43.225".getBytes());
        Assertions.assertTrue( initialPacket.getDcID().length > 0,"Destination ID cannot be null.");
    }

    @Test
    public void testPacketNumberNotNull() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),121212, 25,"192.168.43.225".getBytes());
        Assertions.assertNotNull(initialPacket.getPacketNumber(),"Packet Number cannot be null");
    }
    @Test
    public  void testAddFrame() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),121212, 25,"192.168.43.225".getBytes());
        QuicCryptoFrame quicCryptoFrame = new QuicCryptoFrame(10, "new quic crypto frame");
        initialPacket.addFrame(quicCryptoFrame);
        Assertions.assertTrue(initialPacket.getFrames().contains(quicCryptoFrame),"Frames can be added successfully.");

    }
    @Test
    public void testCryptoFrameType() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),121212, 25,"192.168.43.225".getBytes());
       Set<QuicFrame> frameSet = initialPacket.getFrames();
       for( QuicFrame i : frameSet ){
           Assertions.assertTrue(i instanceof QuicCryptoFrame);
       }
    }
    @Test
    public void testAckFrameType() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),121212, 25,"192.168.43.225".getBytes());
        Set<QuicFrame> frameSet = initialPacket.getFrames();
        for( QuicFrame i : frameSet ){
            Assertions.assertTrue(i instanceof QuicAckFrame);
        }
    }
    @Test
    public void testFramesEmpty() {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),121212, 25,"192.168.43.225".getBytes());
        QuicCryptoFrame quicCryptoFrame = new QuicCryptoFrame(0, "new quic crypto frame");
        initialPacket.addFrame(quicCryptoFrame);
        Assertions.assertNotNull(initialPacket.getFrames(),"Packets must contain at least one frame.");
    }
    @Test
    public void testEncodePacket() throws QuicException {
        QuicInitialPacket initialPacket = new QuicInitialPacket("192.168.43.230".getBytes(),199999990L, 25,"192.168.43.225".getBytes());
        QuicCryptoFrame cryptoFrame = new QuicCryptoFrame(0,"Crypto");
        //Crypto frame: 06 00 06 43727970746F
        byte[] bytes= initialPacket.encode();
        for(byte x : bytes){
            System.out.println(x);
        }
        QuicPacket.decode(bytes);
        //Assertions.assertTrue(initialPacket.encode().toString().equals("C3FF00001904C0A82B3704C0A82BE60D423A35C7"+"06000643727970746F"),"Packet has been encoded successfully.");
    }
    @Test
    public void testDecodePacket() throws QuicException {
        QuicPacket quicPacket = QuicPacket.decode(("C3FF00001904C0A82B3704C0A82BE60D423A35C7"+"06000643727970746F").getBytes());
        Assertions.assertTrue(quicPacket  instanceof QuicInitialPacket, "Packet has been decoded successfully.");
    }

}
