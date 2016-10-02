/*
** Copyright 2015, Mohamed Naufal
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

package xyz.hexene.localvpn;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import xyz.hexene.localvpn.TCB.TCBStatus;

public class TCPInput implements Runnable
{
    private static final String TAG = TCPInput.class.getSimpleName();
    private static final int HEADER_SIZE = Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE;

    private ConcurrentLinkedQueue<ByteBuffer> outputQueue;
    private Selector selector;
    private LocalVPNService localVPNService;



    public TCPInput(ConcurrentLinkedQueue<ByteBuffer> outputQueue, Selector selector, LocalVPNService localVPNService)
    {
        this.outputQueue = outputQueue;
        this.selector = selector;
        this.localVPNService = localVPNService;
    }

    @Override
    public void run()
    {
        try
        {
            Log.d(TAG, "Started");
            while (!Thread.interrupted())
            {
                int readyChannels = selector.select();

                if (readyChannels == 0) {
                    Thread.sleep(10);
                    continue;
                }

                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> keyIterator = keys.iterator();

                while (keyIterator.hasNext() && !Thread.interrupted())
                {
                    SelectionKey key = keyIterator.next();
                    if (key.isValid())
                    {
                        if (key.isConnectable())
                            processConnect(key, keyIterator);
                        else if (key.isReadable())
                            processInput(key, keyIterator);
                    }
                }
            }
        }
        catch (InterruptedException e)
        {
            Log.i(TAG, "Stopping");
        }
        catch (IOException e)
        {
            Log.w(TAG, e.toString(), e);
        }
    }

    private void processConnect(SelectionKey key, Iterator<SelectionKey> keyIterator)
    {
        TCB tcb = (TCB) key.attachment();
        Packet referencePacket = tcb.referencePacket;
        try
        {
            if (tcb.channel.finishConnect())
            {
                keyIterator.remove();
                tcb.status = TCBStatus.SYN_RECEIVED;

                // TODO: Set MSS for receiving larger packets from the device
                ByteBuffer responseBuffer = ByteBufferPool.acquire();
                referencePacket.updateTCPBuffer(responseBuffer, (byte) (Packet.TCPHeader.SYN | Packet.TCPHeader.ACK),
                        tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                outputQueue.offer(responseBuffer);

                tcb.mySequenceNum++; // SYN counts as a byte
                key.interestOps(SelectionKey.OP_READ);
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "Connection error: " + tcb.ipAndPort+ " " + e.toString());
            ByteBuffer responseBuffer = ByteBufferPool.acquire();
            referencePacket.updateTCPBuffer(responseBuffer, (byte) Packet.TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
            outputQueue.offer(responseBuffer);
            TCB.closeTCB(tcb);
        }
    }

    private void processInput(SelectionKey key, Iterator<SelectionKey> keyIterator)
    {
        keyIterator.remove();
        ByteBuffer receiveBuffer = ByteBufferPool.acquire();
        // Leave space for the header
        receiveBuffer.position(HEADER_SIZE);
        int readBytes = 0;

        TCB tcb = (TCB) key.attachment();
        synchronized (tcb)
        {
            Packet referencePacket = tcb.referencePacket;
            SocketChannel inputChannel = (SocketChannel) key.channel();

            try
            {
                readBytes = inputChannel.read(receiveBuffer);

                if (0 == tcb.totalByteTransferred){
                    byte[] tmpByte = receiveBuffer.array();
                    String firstString = new String(tmpByte, 0, readBytes).substring(4);//substring: skip the {0,0,0,0} head
                    String head = firstString.split("\r\n\r\n")[0];
                    tcb.headLength = head.length()+"\r\n\r\n".length()-HEADER_SIZE; // 4: length of "\r\n\r\n"  40: header size
                    Log.d("headlength",""+tcb.headLength);
                }
                tcb.totalByteTransferred+=readBytes;

            }
            catch (Exception e) //retry
            {
                Log.d(TAG, "Network read error: " + tcb.ipAndPort + " " + e.toString());
                retry(tcb, key);
                return;
            }

            if (readBytes == -1)
            {
                // End of stream, stop waiting until we push more data
                key.interestOps(0);
                tcb.waitingForNetworkData = false;

                if (tcb.status != TCBStatus.CLOSE_WAIT)
                {
                    ByteBufferPool.release(receiveBuffer);
                    return;
                }

                tcb.status = TCBStatus.LAST_ACK;
                referencePacket.updateTCPBuffer(receiveBuffer, (byte) Packet.TCPHeader.FIN, tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                tcb.mySequenceNum++; // FIN counts as a byte
            }
            else
            {
                // XXX: We should ideally be splitting segments by MTU/MSS, but this seems to work without
                referencePacket.updateTCPBuffer(receiveBuffer, (byte) (Packet.TCPHeader.PSH | Packet.TCPHeader.ACK),
                        tcb.mySequenceNum, tcb.myAcknowledgementNum, readBytes);
                tcb.mySequenceNum += readBytes; // Next sequence number
                receiveBuffer.position(HEADER_SIZE + readBytes);
            }
        }
        outputQueue.offer(receiveBuffer);
    }

    public void retry(TCB tcb, SelectionKey key){
        Packet referencePacket = tcb.referencePacket;
        int sourcePort = referencePacket.tcpHeader.sourcePort;
        while (true) {
            try {
                SocketChannel reconnectChannel = SocketChannel.open();
                boolean isHTTP = true;//default is not HTTP
                reconnectChannel.configureBlocking(true);//block mode
                localVPNService.protect(reconnectChannel.socket());
                reconnectChannel.connect(new InetSocketAddress(referencePacket.ip4Header.sourceAddress, sourcePort));
                OutputStream outputStream = reconnectChannel.socket().getOutputStream();
                InputStream inputStream = reconnectChannel.socket().getInputStream();
                tcb.channel = reconnectChannel;

                ByteBuffer requestBuffer = Constant.requestBufferMap.get(tcb.ipAndPort);

                /**
                 * not HTTP request
                 */
//                isHTTP = false;
//                int limit = requestBuffer.limit();
//                requestBuffer.flip();
//                byte[] msgByte = new byte[requestBuffer.remaining()];
//                for(int i=0;i<requestBuffer.remaining();i++){
//                    msgByte[i] = requestBuffer.get(requestBuffer.position()+i);
//                }
//                requestBuffer.limit(limit);
                //not HTTP-------end

                /**
                 * HTTP request
                 */
                isHTTP = true;
                byte[] rangeFieldRequest = ("Range: bytes=" + (tcb.totalByteTransferred-tcb.headLength) + "-\r\n\r\n").getBytes();
                int limit = requestBuffer.limit();
                requestBuffer.flip();
                byte[] msgByte = new byte[requestBuffer.remaining()+rangeFieldRequest.length-"\r\n".length()];// the tail of last request is "
                for(int i=0;i<requestBuffer.remaining();i++){
                    msgByte[i] = requestBuffer.get(requestBuffer.position()+i);
                }
                System.arraycopy(rangeFieldRequest, 0, msgByte, requestBuffer.remaining()-"\r\n".length(), rangeFieldRequest.length);// i-2: minus the length of "\r\n"
                requestBuffer.limit(limit);
                //HTTP--------end

                outputStream.write(msgByte);
                outputStream.flush();

//                String showRequest = new String(msgByte);
//                Log.d("Request","Request is:");
//                Log.d("Request", showRequest);


                int rc = 0, cutLength;
                byte[] buff = new byte[ByteBufferPool.BUFFER_SIZE];
                ByteBuffer receiveBuffer = ByteBufferPool.acquire();
                receiveBuffer.position(HEADER_SIZE);
                if (!isHTTP){//if the request is not HTTP , we have to download it from the head of the file, and skip the transferred part
                    /**
                     * Skip the transferred part.
                     */
                    int reconnectTotalByteCnt = 0;
                    while (tcb.totalByteTransferred > reconnectTotalByteCnt) {
                        rc = inputStream.read(buff, 0, ByteBufferPool.BUFFER_SIZE);
                        reconnectTotalByteCnt += rc;
                        Log.d("already", rc + "");
                    }
                    cutLength = reconnectTotalByteCnt - tcb.totalByteTransferred;

                }else {//request if HTTP, we can download it from the last break point.
                    rc = inputStream.read(buff, 0, ByteBufferPool.BUFFER_SIZE);
                    cutLength = rc - new String(buff, 0, rc).split("\r\n\r\n")[0].length() - "\r\n\r\n".length();// cut off the length of "\r\n\r\n"
                }

                /**
                 * Split out the new part near the break point.
                 */
                receiveBuffer.put(buff, rc - cutLength, cutLength);//where "38 bytes" bug happens because of "ByteBufferPool.BUFFER_SIZE-cutLength"
                referencePacket.updateTCPBuffer(receiveBuffer, (byte) (Packet.TCPHeader.PSH | Packet.TCPHeader.ACK),
                        tcb.mySequenceNum, tcb.myAcknowledgementNum, cutLength);
                tcb.mySequenceNum += cutLength; // Next sequence number
                receiveBuffer.position(HEADER_SIZE + cutLength);
                outputQueue.offer(receiveBuffer);
                tcb.totalByteTransferred += cutLength;

                receiveBuffer = ByteBufferPool.acquire();
                receiveBuffer.position(HEADER_SIZE);

                /**
                 * Download the rest of the file.
                 */
                while ((rc = reconnectChannel.read(receiveBuffer)) != -1) {
                    Log.d("new",rc+"");
                    referencePacket.updateTCPBuffer(receiveBuffer, (byte) (Packet.TCPHeader.PSH | Packet.TCPHeader.ACK),
                            tcb.mySequenceNum, tcb.myAcknowledgementNum, rc);
                    tcb.mySequenceNum += rc; // Next sequence number
                    receiveBuffer.position(HEADER_SIZE + rc);
                    outputQueue.offer(receiveBuffer);
                    receiveBuffer = ByteBufferPool.acquire();
                    receiveBuffer.position(HEADER_SIZE);

                }
                /**
                 * End of Stream Operation
                 */
                if (rc == -1) {
                    // End of stream, stop waiting until we push more data
                    key.interestOps(0);
                    tcb.waitingForNetworkData = false;

                    if (tcb.status != TCBStatus.CLOSE_WAIT) {
                        ByteBufferPool.release(receiveBuffer);
                        return;
                    }

                    tcb.status = TCBStatus.LAST_ACK;
                    referencePacket.updateTCPBuffer(receiveBuffer, (byte) Packet.TCPHeader.FIN, tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                    tcb.mySequenceNum++; // FIN counts as a byte
                }
                outputQueue.offer(receiveBuffer);
                Log.d("TCPInput", "Exception recovered");
                break;
            } catch (Exception e1) {
                Log.d("Reconnect","failed");
                try {Thread.sleep(500);} catch (InterruptedException e2) {e2.printStackTrace();}
            }
        }
    }
}
