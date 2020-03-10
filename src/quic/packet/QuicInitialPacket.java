package quic.packet;

import quic.frame.QuicFrame;
import quic.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;

/**
 * Represents a QUIC Initial Packet. It carries the first CRYPTO frames sent
 * by the client and server to perform key exchange, and carries ACKs in either direction.
 *
 * @version 1.1
 */
public class QuicInitialPacket extends QuicLongHeaderPacket {

    int headerByte;
    int packetNumberLength;
    /**
     * Value constructor for QuicInitialPacket class
     * @param dcID destination connection ID
     * @param packetNumber number of the packet
     * @param version version of quic
     * @param scID source connections ID
     */
    public QuicInitialPacket(byte[] dcID, long packetNumber, long version, byte[] scID) {
        super(dcID,packetNumber,version,scID);
        this.setHeaderByte(packetNumber);
    }

    public int getHeaderByte() {
        return headerByte;
    }

    public void setHeaderByte(Long packetNumber) {
        if(packetNumber<Math.pow(2,8)) {
            this.headerByte = 192;
            this.packetNumberLength =1;
        }
        else if(packetNumber<Math.pow(2,16)){
            this.headerByte = 193;
            this.packetNumberLength = 2;
        }
        else if(packetNumber<Math.pow(2,24)) {
            this.headerByte = 194;
            this.packetNumberLength = 3;
        }
        else if(packetNumber<Math.pow(2,32)){
            this.headerByte = 195;
            this.packetNumberLength = 4;
        }
    }



    /**
     * Encodes initial packet
     * @return encoded byte array
     */
    @Override
    public byte[] encode()

    {
        ByteArrayOutputStream encoding = new ByteArrayOutputStream();
        try {
            encoding.write(Util.hexStringToByteArray(Util.byteToHex((byte)headerByte),1));
            encoding.write(Util.hexStringToByteArray(Long.toHexString(this.getVersion()),4));
            encoding.write(Util.hexStringToByteArray((Util.byteToHex((byte)this.getDcID().length)),1));
            encoding.write(Util.hexStringToByteArray(Util.bytesArrayToHex(this.getDcID()),this.getDcID().length));
            encoding.write(Util.hexStringToByteArray((Util.byteToHex((byte)this.getScID().length)),1));
            encoding.write(Util.hexStringToByteArray(Util.bytesArrayToHex(this.getScID()),this.getScID().length));

            long frameSize = 0;
            Iterator<QuicFrame> iterator1 = this.getFrames().iterator();
            while (iterator1.hasNext()) {
                QuicFrame f = iterator1.next();
                frameSize += f.encode().length;
            }
            encoding.write(Util.generateVariableLengthInteger(packetNumberLength + frameSize));
            encoding.write(Util.hexStringToByteArray((Long.toHexString(this.getPacketNumber())),packetNumberLength));
            Iterator<QuicFrame> iterator2 = this.getFrames().iterator();
            while (iterator2.hasNext()) {
                QuicFrame f = iterator2.next();
                encoding.write(f.encode());
            }

        } catch (IOException e) {
            System.out.println(e);
        }
        return encoding.toByteArray();
    }



}
