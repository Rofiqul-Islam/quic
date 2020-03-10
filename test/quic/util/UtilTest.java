package quic.util;

import org.junit.jupiter.api.Test;

public class UtilTest {

    @Test
    public void variableLengthIntegerLengthTest(){
        byte input =(byte)190;
        int x =Util.variableLengthIntegerLength(input);
        System.out.println(x);
    }

    @Test
    public void variableLengthIntegerTest(){
        long x = Util.variableLengthInteger(Util.hexStringToByteArray("ffff",2),0);
        System.out.println(x);
    }

    @Test
    void byteToHexTest(){
        byte b = (byte)(-63);
        System.out.println(Util.byteToHex(b));
    }

    @Test
    void hexToByteTest(){
        byte[] bytes = Util.hexStringToByteArray("ff000eeeeeeee33333333301",0);
        for(byte b:bytes){
            System.out.println(b);
        }
    }

    @Test
    void generatingVariableLengthIntegerTest(){
        byte[] bytes = Util.generateVariableLengthInteger(989L);
        for(byte b:bytes){
            System.out.println(b);
        }
        System.out.println(Util.variableLengthInteger(bytes,1));
    }
}
