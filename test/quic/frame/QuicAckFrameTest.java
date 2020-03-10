package quic.frame;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.ArrayList;

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import quic.exception.QuicException;

class QuicAckFrameTest extends QuicFrame {
	
	ArrayList<QuicAckRange> ackRanges = new ArrayList<>();
	private QuicAckFrame quicAckFrameTest = new QuicAckFrame(-1, -1, -1, -1);

	@BeforeAll
	static void setUpBeforeClass() throws Exception {
	}

	@AfterAll
	static void tearDownAfterClass() throws Exception {
	}

	@BeforeEach
	void setUp() throws Exception {
	}

	@AfterEach
	void tearDown() throws Exception {
	}


	@Test
	void testQuicAckFrame() {
	
		//As per specification
		// Largest acknowledged value can not be negetive
		assertTrue(quicAckFrameTest.getLargestAck() >= 0);
		// Dealy value can not be negetive
		assertTrue(quicAckFrameTest.getDelay() >= 0);
		// Range count value can not be negetive
		assertTrue(quicAckFrameTest.getRangeCount() >= 0);
		// First ack range value can not be negetive
		assertTrue(quicAckFrameTest.getFirstAckRange() >= 0);
		// Ack ranges can not be empty
		assertTrue(quicAckFrameTest.getAckRanges().size() >= 1);
	
	}
	
	@Test
	void testLargestAcknowledged() {
	}
	
	@Test
	void testDelay() {
	
		//This value should be in microseconds
	}
	
	@Test
	void testRangeCount() {
	}
	
	@Test
	void testFirstAckRange() {
		
		//As per specification
		// First ack range should be started from the largest acknowledged
		assertTrue(quicAckFrameTest.getFirstAckRange() > quicAckFrameTest.getLargestAck());
	
	}
	
	@Test
	void testAckRanges() {
		
		//As per specification
		int tempLargestAck = this.quicAckFrameTest.getLargestAck();
		for (QuicAckRange ackRange : this.ackRanges) {
			
			
			int smallest = tempLargestAck - ackRange.getAckRange();
			// Smallest value can not be negetive
			assertTrue(smallest >= 0);
			tempLargestAck = tempLargestAck - ackRange.getAckRange() - ackRange.getGap();
			
			int largest = smallest - ackRange.getGap() - 2;
			// Largest value can not be negetive
			assertTrue(largest >= 0);
			
		}
		
		
		
	
	}
	
	@Test 
	void testDecode() throws QuicException, IOException {
		byte [] data = quicAckFrameTest.encode();
		QuicAckFrame decodedFrame = (QuicAckFrame) super.decode(data);
		assertEquals(this.quicAckFrameTest, decodedFrame, "Encode and decode miss matches");
	}
	@Test
	void testEncode() throws QuicException, IOException{
		QuicFrame ackFrame = new QuicAckFrame(10,5,10,1);
		System.out.println(ackFrame.encode());
	}

	@Override
	public byte[] encode() throws IOException {
		return null;
	}

}