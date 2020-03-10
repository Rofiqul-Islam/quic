package quic.frame;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Jan Svacina
 * @version 1.1
 */
public class QuicCryptoFrameGettersTest extends QuicBaseCryptoFrameTest {

    @DisplayName("Test getter of Data field in Quic Crypto frame with some data")
    @Test
    public void dataGetterSomeDataTest() {
        String expected = "06000008";
        String result = getDataFromObject(expected);
        assertEquals(expected, result);
    }

    @DisplayName("Test getter of Data field in Quic Crypto frame with empty data")
    @Test
    public void dataGetterEmptyDataTest() {
        String expected = "";
        String result = getDataFromObject(expected);
        assertEquals(expected, result);
    }

    @DisplayName("Test getter of Data field in Quic Crypto frame with no data")
    @Test
    public void dataGetterNoDataTest() {
        String expected = null;
        String result = getDataFromObject(expected);
        assertEquals(expected, result);
    }

    @DisplayName("Test getter of Data field in Quic Crypto frame with some offset")
    @Test
    public void dataGetterSomeOffsetTest() {
        int expected = 287;
        int result = getOffsetFromObject(expected);
        assertEquals(expected, result);
    }

    @DisplayName("Test getter of Data field in Quic Crypto frame with zero offset")
    @Test
    public void dataGetterZeroOffsetTest() {
        int expected = 0;
        int result = getOffsetFromObject(expected);
        assertEquals(expected, result);
    }

    @DisplayName("Test getter of Data field in Quic Crypto frame with negative offset")
    @Test
    public void dataGetterNegativeOffsetTest() {
        int expected = -9;
        int result = getOffsetFromObject(expected);
        int value = 0;
        assertEquals(value, result);
    }





}
