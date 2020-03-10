package quic.util;

public class Util {

    public static int variableLengthIntegerLength(byte b){
        int temp = (int)b;
        int lenArry[] = new int[2];
        for(int c=7;c>=6;c--){
            int x = (int) Math.pow(2,c);
            if((x&temp)==0){
                lenArry[7-c]=0;
            }
            else{
                lenArry[7-c]=1;
            }
        }
        if(lenArry[0]==0 && lenArry[1]==0){
            return  1;
        }
        else if(lenArry[0]==0 && lenArry[1]==1){
            return 2;
        }
        else if(lenArry[0]==1 && lenArry[1]==0){
            return 4;
        }
        else if(lenArry[0]==1 && lenArry[1]==1){
            return 8;
        }

        return 0;
    }

    public static long variableLengthInteger(byte[] input,int type){
        if(type==0) {
            String s = bytesArrayToHex(input);
            Long result = Long.parseLong(s, 16);
            return result;
        }
        else if(type == 1){
            String s =Util.byteToHex((byte)(input[0]&63));
            byte [] temp = new byte[input.length-1];
            for(int i=1;i<input.length;i++){
                temp[i-1]=input[i];
            }
            s+=bytesArrayToHex(temp);
            //System.out.println("s = "+s);
            Long result = Long.parseLong(s, 16);
            return result;
        }
        return 0;
    }

    public static byte[] generateVariableLengthInteger(Long input){
        if(input<Math.pow(2,6)){              // adding 00 before the length
            byte[] temp = Util.hexStringToByteArray(Long.toHexString(input),1);
            temp[0]+=0;
            return temp;
        }
        else if(input<Math.pow(2,14)){        // adding 01 before the length
            byte[] temp = Util.hexStringToByteArray(Long.toHexString(input),2);
            temp[0]+=64;
            return temp;
        }
        else if(input<Math.pow(2,30)){        // adding 10 before the length
            byte[] temp = Util.hexStringToByteArray(Long.toHexString(input),4);
            temp[0]+=128;
            return temp;
        }
        else if(input<(long)Math.pow(2,62)){     //adding 11 before the integer
            byte[] temp = Util.hexStringToByteArray(Long.toHexString(input),8);
            temp[0]+=192;
            return temp;
        }
        return null;
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesArrayToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    public static String byteToHex(byte b){
        int v = b & 0xFF;
        String hex_string = HEX_ARRAY[v >>> 4]+"";
        hex_string+= HEX_ARRAY[v & 0x0F];
        return hex_string;
    }

    public static byte[] hexStringToByteArray(String s, int requiredLen) {
        if (requiredLen == 0) {
            int len = s.length();
            byte[] data = new byte[s.length() / 2];
            for (int i = 0; i < s.length(); i += 2) {
                data[i / 2] = (byte) (((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16)));

            }
            return data;
        } else {
            int len = s.length();
            int diff = requiredLen * 2 - len;
            for (int i = 0; i < diff; i++) {
                s = "0" + s;
            }
            byte[] data = new byte[s.length() / 2];
            for (int i = 0; i < s.length(); i += 2) {
                data[i / 2] = (byte) (((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i + 1), 16)));

            }
            return data;
        }
    }

}
