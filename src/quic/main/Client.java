package quic.main;

import quic.util.Util;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Scanner;

public class Client {
    public static void main(String args[]) throws IOException
    {
        Scanner sc = new Scanner(System.in);

        // Step 1:Create the socket object for
        // carrying the data.
        DatagramSocket ds = new DatagramSocket();

        InetAddress ip = InetAddress.getByName("216.155.158.183");
        byte buf[] = null;

        // loop while user not enters "bye"
        while (true)
        {
            String inp = "c8ff00001908b634cb734c493b7c000045345c4cae5e25ff3e36e93c0c7799f1e89deaabd030687558dfd81f87c371e5318353ec3e1e1304fa71b52d828f3a07e41b85cfea0eb18ccdd4c51744acbc8ba2c177ffeebb1753b24452157a4d2e6addf34c01cf714ff7a9ec5f29f8fe4cef9d6eebe9012122f19eba9a99a90678b7a99385805a9c4661f76b84933afba74298eb7879c9d428c24f5f371bcc9d53628004ed74cb7dcba469c301002c7bc38a8ef5ecb0e64f35d91200abac0ae62bb8a008ddb1ca5cf309f935153a4781147c9d5233b6b36b5b15a5821d25098f88024580b5f59598ca5c6e84ac0c33abf57b2aadc960f08004d8a5d2a78e141ad01e27700993c913715a77c14c280029d78723a8f7654572f810d680e2f61b28c65143390ba5ead0923db9f8445e9bafb6aac5a9614849ee2c3afa96da7947362450bbd5553fe66ddc8e266266eb4aceabdd87b9377d1d8204b5f73a1a91819c3630e497d0a5027bd9c967ba62e9dde54d1d9170d912fbd0d3d93261a96998d81a8dce771c658dda5d081024652915136d6f364570bfdda302a52e2380a77b779e431e80b75f3a14903a89d4084008fafdd55de7db3b7104a1cf42baf06f4e4c95a62358edb167c639921de4fab735bb2ce367747904f47d25665ecf67bae9a3da2c04f83f887de4216bd52b4028451c629f27e03f8ae09d2b3bc4411b1dbbf19c7ab19cd2052b31ac9702a2e5df605be5e4ea81ae4435dc6b152ba214142b1cedc77312156949ade9e2e0457dcae9d280909956c147708e05ae41bb62d0b47ecb8e7dca079002ab456ced7f60d155bedec633e572491415a713d6872b59ead8f9784bde5e25ed70117e77decbd8adbc9ef756f9450b1390efaf7afd9e4624c8749d88638bfb9971c7ef19e9695b2c2b83eaf2539099980247c800d1a89f55b829ebf77aed80db6476b210fcf34b0939aafd8817a1c94d83335193c6508d5bcd1f78fac9341355e0fe74c8d3c1c1b2558bbe981808503f50c3b08e3446e8626951006c9c561acebf332cab59f96b05777bca734ee7f26dab7a764bb09f05e661e1ed7cb4fe2fbf8545d05a2b079c1e9799e4d01f554ffcb8eef68032fa66bc79cbb4276316ef0140724b5cdda02ee04f6c8e73e8b263f1f21c25d6746d9bd0150028c90ca1c5aa4735f841bcd5c393dc5227b8afb8b4ee7b5e1e3f19a2e20201900333bdd04574872b332ee5f4fdd487ab7b90ec3947eefb9cd7aeb0a600754913b007fff355cedaa4ad552211ff006071ac566148ea558094cda71c935f3ea6fcb4c28923bbb462076db84c91df4363cc71b927507f864b1539efc8c360f38ea573e4dae6db98a3909902429c26235aafaece45bcaa67acd70a1fa5a5a84f7d9d1415386269ad3f983af9cbe4cbdd086e7a832e88d560e39a15547d3ffe9d5cf014cfbf095492e44c422d673c080e053ce98dd702624befad070d8c80c642f0af272421c1e471cc9364f00aae6ea3662d55b9fc7d61c8acc05db87ca9347f342232ea4e975a2f6bff14889ce9be95bc553117532c74181eda71e71d3b5e6d794d1b25bcd869c1fe7eea045922880b50c9750c4b3bb5b4fe4406d9f0e8969d75a34bec87ab1e17a49ed3243672db5cfb358a5f6ba5b137c4305207f9f9cdb849aa8b598f269c5d56bf9bbac91dea06659f01a2b9f1bc72c0e8d62e813446b5251816609d90915a6341971dd2a2f842aa75669658d0fc99a4f005031a0ae74df37a5e5c76ce18d457e87e3dc2a5ed3bf5fbd378753ac68a49344ceb1478fdd7df1f157f5d25a55cbe49d90631b7ff2d1f49051d6bc810905c9d51f6659a2a93f125c02e412b2655bbec56e8ea11b4e0e2521b84e37d477e081dfa1e234ca70881f721c4de767c3369";

            // convert the String input into the byte array.
            buf = Util.hexStringToByteArray(inp,0);

            // Step 2 : Create the datagramPacket for sending
            // the data.
            DatagramPacket DpSend = new DatagramPacket(buf, buf.length,ip, 4433);

            // Step 3 : invoke the send call to actually send
            // the data.
            ds.send(DpSend);
            byte[] b1 = new byte[2048];
            DatagramPacket DpRecv = new DatagramPacket(b1,b1.length);
            ds.receive(DpRecv);
            System.out.println(DpRecv);

            // break the loop if user enters "bye"
            if (inp.equals("bye"))
                break;
        }
    }
}
