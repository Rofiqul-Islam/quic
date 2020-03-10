package quic.packet;

import quic.frame.QuicFrame;
import quic.util.Util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;

/**
 * Represents a QUIC 0-RTT packet.
 * A 0-RTT packet carries "early" data from the client to server as part of the first flight,
 * prior to handshake completion.
 *
 * @version 1.1
 */
public class QuicZeroRTTPacket extends QuicLongHeaderPacket {

    int headerByte;
    int packetNumberLength;
    /**
     * Value constructor for QuicZeroRTTPacket
     *
     * @param dcID Destination Connection ID
     * @param packetNumber number of the packet
     * @param version version of quic
     * @param scID source connections ID
     */
    public QuicZeroRTTPacket(byte[] dcID, long packetNumber, long version, byte[] scID) {
        super(dcID, packetNumber, version, scID);
    }

    public int getHeaderByte() {
        return headerByte;
    }

    public void setHeaderByte(Long packetNumber) {
        if(packetNumber<Math.pow(2,8)) {
            this.headerByte = 208;
        }
        else if(packetNumber<Math.pow(2,16)){
            this.headerByte = 209;
        }
        else if(packetNumber<Math.pow(2,24)) {
            this.headerByte = 210;
        }
        else if(packetNumber<Math.pow(2,32)){
            this.headerByte = 211;
        }
    }

    /**
     * Encodes Zero RTT packet
     * @return encoded byte array
     */
    @Override
    public byte[] encode() {
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
