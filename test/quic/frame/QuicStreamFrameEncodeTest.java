package quic.frame;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Jan Svacina
 * @version 1.1
 */
public class QuicStreamFrameEncodeTest {

    private static String streamFrame = "0a0203000400";

    private int streamId = 2;

    private int offset = 0;

    private boolean endOfStream = true;

    private String data = "0400";

    @DisplayName("Encode crypto packet without offset, default data")
    @Test
    void shouldEncodeCryptoPacketWithoutOffsetDefaultDataTest() {
        QuicStreamFrame qsf = new QuicStreamFrame(streamId, offset, endOfStream, data.getBytes());
        byte[] qsfBytes = new byte[0];
        try {
            qsfBytes = qsf.encode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        assertEquals(qsfBytes, streamFrame.getBytes());
    }


}
