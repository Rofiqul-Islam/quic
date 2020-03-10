package quic.packet;

import quic.exception.QuicException;
import quic.frame.QuicFrame;
import quic.util.Util;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Represents IETF-QUIC Packet
 * Chapter 12.3
 *
 * @version 1.2
 */
public abstract class QuicPacket {

    /**
    The Destination Connection ID field follows the DCID Len and is between 0 and 20 bytes in length.
    */
    private byte[] dcID;

    /**
    This number is used in determining the cryptographic nonce for packet protection.
     Each endpoint maintains a separate packet number for sending and receiving.
     */
    private long packetNumber;

    /**
    List of frames included in each packet
     */
    private Set<QuicFrame> frames;

    /**
     * Value constructor for packet.QuicPacket
     * @param dcID Destination Connection ID
     * @param packetNumber Number of this packet generated by the endpoint
     */
    public QuicPacket(byte[] dcID, long packetNumber) {
        this.setDcID(dcID);
        this.setPacketNumber(packetNumber);
        this.frames=new HashSet<>();
    }

    /**
     * Encodes a packet into byte array
     * @return byte[]
     */
    public byte[] encode(){
        return new byte[3];
    }

    /**
     * Decodes byte array into packet object. The destination connection ID
     * size is used when the connection has already negotiated the size of the
     * ID.
     *
     * @param arr the array of bytes to decode
     * @param dcIdSize the destination connection ID size
     * @return the parsed packet
     */

    public static QuicPacket decode(byte[] arr, int dcIdSize) throws QuicException {
        return null;
    }

    /**
     * Decodes byte array into packet object
     * @param arr array of bytes of some packet
     * @return packet.QuicPacket
     */

    public static QuicPacket decode(byte[] arr) throws QuicException {

        System.out.println("---------------------------------------");
        int headerByte = (int)arr[0];
        if(headerByte<0){
            headerByte+=256;
        }
        int headerArry[] = new int[8];
        for(int c=7;c>=0;c--){
            int x = (int) Math.pow(2,c);
            if((x & headerByte)==0){
                headerArry[7-c]=0;
            }
            else{
                headerArry[7-c]=1;
            }
        }
        System.out.println(headerByte);
        System.out.println(headerArry[2]+" "+headerArry[3]);
        if(headerArry[0]==0){
            //shortheader
        }
        else if(headerArry[0]==1){                          //Long header
            if(headerArry[2]==0 && headerArry[3]==0){
                //intialpacket
                return quicLongHeaderPacketDecoder(0,arr,headerByte,headerArry);
            }
            else if(headerArry[2]==0 && headerArry[3]==1){
                //0-RTT
                return quicLongHeaderPacketDecoder(1,arr,headerByte,headerArry);
            }
            else if(headerArry[2]==1 && headerArry[3]==0){
                //handshake
                return quicLongHeaderPacketDecoder(2,arr,headerByte,headerArry);

            }

        }
        return null;
    }

    /**
     * Get destination connection id
     * @return dcId
     */
    public byte[] getDcID() {
        return dcID;
    }

    /**
     * Set destination connection id
     * @param dcID destination connection id
     */
    public void setDcID(byte[] dcID) {

        if(dcID!=null && dcID.length <=20) {
            this.dcID = dcID;
        }else{
            throw new IllegalArgumentException();
        }
    }

    /**
     * Retrieves packet number
     * @return packet number
     */
    public long getPacketNumber() {
        return packetNumber;
    }

    /**
     * Sets packet number
     * @param packetNumber number of the packet
     */
    public void setPacketNumber(long packetNumber) {
        if(packetNumber>=0L) {
            this.packetNumber = packetNumber;
        }else {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Gets the IETF-QUIC frames
     * @return frames associated with this packet
     */
    public Set<QuicFrame> getFrames()  {
        Set<QuicFrame>temp = new HashSet<>();
        Iterator<QuicFrame>iterator = frames.iterator();
        while(iterator.hasNext()){
            QuicFrame f=iterator.next();
            temp.add(f);
        }
        frames.removeAll(temp);
        return temp;
    }

    /**
     * Adds a frame to  this packet
     * @param frame the frame to add
     */
    public void addFrame(QuicFrame frame) {
        this.frames.add(frame);
    }

    public static QuicPacket quicLongHeaderPacketDecoder(int type, byte[] arr, int headerByte, int headerArry[]){
        int p=1;
        byte[] version_arr = new byte[4];
        int n = p;
        for(;n<p+4;n++){
            version_arr[n-p]=arr[n];
        }
        long version = Util.variableLengthInteger(version_arr,0)-4278190080L;
        System.out.println(version);
        p=n;
        ////////////////////////////
        int dcIdLenD=(int)arr[p];
        p++;
        byte[] dcIdD= new byte[20];
        int i=p;
        for(; i<p+dcIdLenD; i++){
            dcIdD[i-p]=arr[i];
        }
        System.out.println(dcIdLenD);
        p=i;
        ///////////////////////////
        int scIdLenD=(int)arr[p];
        p++;
        byte[] scIdD = new byte[20];
        int j=p;
        for(;j<p+scIdLenD;j++){
            scIdD[j-p]=arr[j];
        }
        p=j;
        ////////////////////////////
        int lengthSize = Util.variableLengthIntegerLength(arr[p]);
        byte[] len_arr = new byte[lengthSize];
        for(int c=p;c<lengthSize+p;c++){
            len_arr[c-p]=arr[c];
        }
        p+=lengthSize;
        long length = Util.variableLengthInteger(len_arr,1);
        System.out.println("length = "+length);
        ///////////////////////////////////////
        int packetNoLen = (headerByte & 3)+1;

        byte[] packNum_arr = new byte[packetNoLen];
        for(int c=p;c<packetNoLen+p;c++){
            packNum_arr[c-p]=arr[c];
            System.out.println("packet  = "+packNum_arr[c-p]);
        }
        p+=packetNoLen;
        long packetNum = Util.variableLengthInteger(packNum_arr,0);
        System.out.println(packetNum);
        /////////
        byte[] frameSetD = new byte[(int)(length-packetNoLen)];
        int k = p;
        for(;k<p+(length-packetNoLen);k++){
            frameSetD[k-p]=arr[k];
        }
        if(type==0){
            return new QuicInitialPacket(dcIdD,packetNum,version,scIdD);
        }
        else if(type == 1){
            return new QuicZeroRTTPacket(dcIdD,packetNum,version,scIdD);
        }
        else if(type == 2) {
            return new QuicHandshakePacket(dcIdD, packetNum, version, scIdD);
        }

        return null;
    }



}

