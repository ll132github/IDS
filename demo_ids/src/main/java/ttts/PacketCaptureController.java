package ttts;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;


import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.JPacketHandler;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import java.util.*;


public class PacketCaptureController {
    private static Set<String> blacklistedIPs = new HashSet<>();
    private static Set<String> whitelistedIPs = new HashSet<>();
    private static Map<String, List<Long>> ipDdosMap = new HashMap<>();
    private static Map<String, List<Long>> ipPortMap = new HashMap<>();
    private static Map<String, List<Long>> PortMap = new HashMap<>();
    private static Map<String, List<Long>> ipRequestMap = new HashMap<>();
    private String pcapFilePath;
    private Pcap pcap;  // 用于管理抓包的Pcap对象
    private final int Count=10000;

    @FXML
    private TextField trafficPacketAddress;

    @FXML
    private TextField sourceIP;

    @FXML
    private TextField destinationIP;

    @FXML
    private TextField NCid;
    @FXML
    private TextField BLK_ip;
    @FXML
    private TextField WHI_ip;

    @FXML
    private TextArea infoDisplay;
    private int NCIdText;
    private boolean isDo=true;
    private String filePath = "F:\\JAVA_study\\HIDS\\demo_ids\\src\\main\\java\\ttts\\BLK_ip.txt";
    private String attfile="F:\\JAVA_study\\HIDS\\demo_ids\\src\\main\\java\\ttts\\attack_log.txt";
    private String whitefile="F:\\JAVA_study\\HIDS\\demo_ids\\src\\main\\java\\ttts\\white_ip.txt";
    List<PcapIf> alldevs = new ArrayList<>();
    StringBuilder errbuf = new StringBuilder();
    @FXML
    private void NCset() {
        String ncIdText = NCid.getText();
        NCIdText = Integer.parseInt(ncIdText);
        appendToInfoDisplay("选择的设备: " + NCIdText);
    }
    @FXML
    private void setBLK_ip() {
        String BLK_Text = BLK_ip.getText();
        String WhI_Text = WHI_ip.getText();
        if(!BLK_Text.isEmpty()) {
            try {
                FileWriter fileWriter = new FileWriter(filePath, true);
                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                bufferedWriter.write(BLK_Text);
                bufferedWriter.newLine();
                bufferedWriter.close();
                appendToInfoDisplay("黑名单ip已成功写入文件");
            } catch (IOException e) {
                appendToInfoDisplay("发生错误： " + e.getMessage());
            }
        }
        if(!WhI_Text.isEmpty()) {
            try {
                FileWriter fileWriter = new FileWriter(whitefile, true);
                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                bufferedWriter.write(WhI_Text);
                bufferedWriter.newLine();
                bufferedWriter.close();
                appendToInfoDisplay("白名单ip已成功写入文件");
            } catch (IOException e) {
                appendToInfoDisplay("发生错误： " + e.getMessage());
            }
        }

    }

    @FXML
    private void startPacketCapture() {
        appendToInfoDisplay("开始抓包检测");
        // 读取黑/白名单IP
        loadBlacklistedIPs();
        loadWhitelistedIPs();
            // 选择一个设备进行抓包
            PcapIf device = alldevs.get(NCIdText);
            // 打开设备
            int snaplen = 64 * 1024;           // 截获的数据包长度
            int flags = Pcap.MODE_PROMISCUOUS; // 混杂模式
            int timeout = 10 * 1000;           // 超时时间
             pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

            if (pcap == null) {
                System.err.printf("打开捕获设备时出错: %s", errbuf.toString());
                return;
            }

            // 创建pcap文件保存数据包
            String ofile = "captured_packets.pcap";
            PcapDumper dumper = pcap.dumpOpen(ofile);

            // 定义数据包处理程序
            JPacketHandler<String> jpacketHandler = new JPacketHandler<String>() {
                public void nextPacket(JPacket packet, String user) {

                    dumper.dump(packet);

                    Ip4 ip = new Ip4();
                    Tcp tcp = new Tcp();

                    if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                        String srcIP = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
                        String dstIP = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());
                        int srcPort=tcp.source();
                        int dstP = tcp.destination();
                        String dstPort=Integer.toString(dstP);
                        long currentTime = System.currentTimeMillis();
                        long timestamp = packet.getCaptureHeader().timestampInMillis();
                        appendToInfoDisplay("时间: "+timestamp+" 源IP: "+srcIP+" 目的IP:"+dstIP+"端口："+srcPort+"->"+dstP+"\n");

//                        new Thread(() -> {
                            // 检测黑名单IP访问
                            if (blacklistedIPs.contains(srcIP) || blacklistedIPs.contains(dstIP)) {
                                appendToInfoDisplay("检测到黑名单IP访问: " + srcIP + " -> " + dstIP + "----建议将其加入防火墙黑名单\n");
                                try {
                                    FileWriter fileWriter = new FileWriter(attfile, true);
                                    BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                                    bufferedWriter.write("时间: " + timestamp + "检测到黑名单IP访问: " + srcIP + " -> " + dstIP + "----建议将其加入防火墙黑名单");
                                    bufferedWriter.newLine();
                                    bufferedWriter.close();
                                } catch (IOException e) {
                                    appendToInfoDisplay("attack_log发生错误： " + e.getMessage());
                                }
                            }
                            // DoS攻击检测
                            ipRequestMap.putIfAbsent(srcIP, new ArrayList<>());
                            ipRequestMap.get(srcIP).add(currentTime);
                            ipRequestMap.get(srcIP).removeIf(time -> currentTime - time > 5000);
                            if (ipRequestMap.get(srcIP).size() > 10&& !whitelistedIPs.contains(srcIP)) {
                                appendToInfoDisplay("检测到疑似DoS攻击: " + srcIP +"在5秒内发送了超过10个请求！----建议将其加入黑名单\n");
                                try {
                                    FileWriter fileWriter = new FileWriter(attfile,true);
                                    BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                                    bufferedWriter.write("时间: "+timestamp+"检测到来自 "+srcIP+" 疑似DoS攻击! --------建议将其加入黑名单");
                                    bufferedWriter.newLine();
                                    bufferedWriter.close();
                                } catch (IOException e) {
                                    appendToInfoDisplay("attack_log发生错误： " + e.getMessage());
                                }
                            }
                                // 端口扫描检测
                                ipPortMap.putIfAbsent(srcIP, new ArrayList<>());
                                PortMap.putIfAbsent(dstPort, new ArrayList<>());
                                ipPortMap.get(srcIP).add(currentTime);
                                ipPortMap.get(srcIP).removeIf(time -> currentTime - time > 500);
                                if (ipPortMap.get(srcIP).size() > 50 || PortMap.get(dstPort).size() > 50) {
                                    appendToInfoDisplay("检测到疑似端口扫描攻击: " + srcIP + "在0.5秒内访问了超过50个端口！----建议将" + srcIP + "加入防火墙黑名单\n");
                                    try {
                                        FileWriter fileWriter = new FileWriter(attfile, true);
                                        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                                        bufferedWriter.write("时间: " + timestamp + "检测到来自 " + srcIP + " 端口扫描攻击! ----建议将" + srcIP + "加入黑名单");
                                        bufferedWriter.newLine();
                                        bufferedWriter.close();
                                    } catch (IOException e) {
                                        appendToInfoDisplay("attack_log发生错误： " + e.getMessage());
                                    }
                                }
                                // DDoS攻击检测
                                ipDdosMap.putIfAbsent(dstIP, new ArrayList<>());
                                ipDdosMap.get(dstIP).add(currentTime);
                                ipDdosMap.get(dstIP).removeIf(time -> currentTime - time > 5000);
                                if (ipDdosMap.get(dstIP).size() > 1000) {
                                    appendToInfoDisplay("检测到DDoS攻击: " + dstIP + "在0.5秒内被超过1000个IP访问！----建议重新路由或使用防火墙拦截假冒流量等\n");
                                    try {
                                        FileWriter fileWriter = new FileWriter(attfile, true);
                                        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                                        bufferedWriter.write("时间: " + timestamp + "检测疑似到DDoS攻击: " + dstIP + "在0.5秒内被超过1000个IP访问！----建议重新路由或使用防火墙拦截假冒流量等");
                                        bufferedWriter.newLine();
                                        bufferedWriter.close();
                                    } catch (IOException e) {
                                        appendToInfoDisplay("attack_log发生错误： " + e.getMessage());
                                    }
                                }
//                        });
                    }
                }
            };

            // 开始抓包

        new Thread(() -> {
            try {
                pcap.loop(Count, jpacketHandler, "JnetPcap rocks!");
            } catch (Exception e) {
                appendToInfoDisplay("抓包过程中发生错误: " + e.getMessage());
            } finally {
                pcap.close();
                dumper.close();
            }
        }).start();
    }

    @FXML
    private void stopPacketCapture() {
        if (pcap != null) {
            pcap.breakloop();
            appendToInfoDisplay("已停止抓包");
        }
    }
    @FXML
    private void startAnalysis() {
        // 读取黑/白名单IP
        loadBlacklistedIPs();
        loadWhitelistedIPs();
        pcapFilePath = trafficPacketAddress.getText();
        appendToInfoDisplay("开始分析流量包: " + pcapFilePath);
        // 获取pcap文件路径
        File pcapFile = new File(pcapFilePath);

        if (!pcapFile.exists()) {
            appendToInfoDisplay("pcap文件不存在: " + pcapFilePath);
            return;
        }
        // 打开pcap文件

        Pcap pcap = Pcap.openOffline(pcapFilePath, errbuf);
//        PcapDumper dumper = pcap.dumpOpen(pcapFilePath);
        if (pcap == null) {
            appendToInfoDisplay("无法打开pcap文件: " + errbuf.toString());
            return;
        }
        // 定义数据包处理程序
        JPacketHandler<String> jpacketHandler = new JPacketHandler<String>() {
            public void nextPacket(JPacket packet, String user) {
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                    String srcIP = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
                    String dstIP = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());
                    int dstP = tcp.destination();
                    int srcPort=tcp.source();
                    String dstPort = Integer.toString(dstP);
                    long currentTime = System.currentTimeMillis();
                    long timestamp = packet.getCaptureHeader().timestampInMillis();
                    appendToInfoDisplay("时间: "+timestamp+" 源IP: "+srcIP+" 目的IP:"+dstIP+"端口："+srcPort+"->"+dstP+"\n");
//                    new Thread(() -> {
                        // 检测黑名单IP访问
                        if (blacklistedIPs.contains(srcIP) || blacklistedIPs.contains(dstIP)) {
                            appendToInfoDisplay("检测到黑名单IP访问: " + srcIP + " -> " + dstIP + "----建议将其加入防火墙黑名单\n");
                            try {
                                FileWriter fileWriter = new FileWriter(attfile, true);
                                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                                bufferedWriter.write("时间: " + timestamp + "检测到黑名单IP访问: " + srcIP + " -> " + dstIP + "----建议将其加入防火墙黑名单");
                                bufferedWriter.newLine();
                                bufferedWriter.close();
                            } catch (IOException e) {
                                appendToInfoDisplay("attack_log发生错误： " + e.getMessage());
                            }
                        }
                        // DoS攻击检测
                        ipRequestMap.putIfAbsent(srcIP, new ArrayList<>());
                        ipRequestMap.get(srcIP).add(currentTime);
                        ipRequestMap.get(srcIP).removeIf(time -> currentTime - time > 5000);
                        if (ipRequestMap.get(srcIP).size() > 10&& !whitelistedIPs.contains(srcIP)) {
                            appendToInfoDisplay("检测到疑似DoS攻击: " + srcIP +"在5秒内发送了超过10个请求！----建议将其加入黑名单\n");
                            try {
                                FileWriter fileWriter = new FileWriter(attfile,true);
                                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                                bufferedWriter.write("时间: "+timestamp+"检测到来自 "+srcIP+" 疑似DoS攻击! --------建议将其加入黑名单");
                                bufferedWriter.newLine();
                                bufferedWriter.close();
                            } catch (IOException e) {
                                appendToInfoDisplay("attack_log发生错误： " + e.getMessage());
                            }
                        }
                        // 端口扫描检测
                        ipPortMap.putIfAbsent(srcIP, new ArrayList<>());
                        PortMap.putIfAbsent(dstPort, new ArrayList<>());
                        ipPortMap.get(srcIP).add(currentTime);
                        ipPortMap.get(srcIP).removeIf(time -> currentTime - time > 500);
                        if (ipPortMap.get(srcIP).size() > 50 || PortMap.get(dstPort).size() > 50) {
                            appendToInfoDisplay("检测到疑似端口扫描攻击: " + srcIP + "在0.5秒内访问了超过50个端口！----建议将" + srcIP + "加入防火墙黑名单\n");
                            try {
                                FileWriter fileWriter = new FileWriter(attfile, true);
                                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                                bufferedWriter.write("时间: " + timestamp + "检测到来自 " + srcIP + " 端口扫描攻击! ----建议将" + srcIP + "加入黑名单");
                                bufferedWriter.newLine();
                                bufferedWriter.close();
                            } catch (IOException e) {
                                appendToInfoDisplay("attack_log发生错误： " + e.getMessage());
                            }
                        }
                        // DDoS攻击检测
                        ipDdosMap.putIfAbsent(dstIP, new ArrayList<>());
                        ipDdosMap.get(dstIP).add(currentTime);
                        ipDdosMap.get(dstIP).removeIf(time -> currentTime - time > 5000);
                        if (ipDdosMap.get(dstIP).size() > 1000) {
                            appendToInfoDisplay("检测到DDoS攻击: " + dstIP + "在0.5秒内被超过1000个IP访问！----建议重新路由或使用防火墙拦截假冒流量等\n");
                            try {
                                FileWriter fileWriter = new FileWriter(attfile, true);
                                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                                bufferedWriter.write("时间: " + timestamp + "检测疑似到DDoS攻击: " + dstIP + "在0.5秒内被超过1000个IP访问！----建议重新路由或使用防火墙拦截假冒流量等");
                                bufferedWriter.newLine();
                                bufferedWriter.close();
                            } catch (IOException e) {
                                appendToInfoDisplay("attack_log发生错误： " + e.getMessage());
                            }
                        }
//                    });
                }
            }
        };
        // 读取数据包
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "JnetPcap rocks!");
    }

    @FXML
    private void filter() {
        pcapFilePath = trafficPacketAddress.getText();
        File pcapFile = new File(pcapFilePath);

        if (!pcapFile.exists()) {
            appendToInfoDisplay("pcap文件不存在: " + pcapFilePath);
            return;
        }

        // 打开pcap文件
        Pcap pcap = Pcap.openOffline(pcapFilePath, errbuf);
        if (pcap == null) {
            appendToInfoDisplay("无法打开pcap文件: " + errbuf.toString());
            return;
        }

        String userSourceIP = sourceIP.getText().trim();
        String userDestinationIP = destinationIP.getText().trim();

        // 定义数据包处理程序
        JPacketHandler<String> jpacketHandler = new JPacketHandler<String>() {
            public void nextPacket(JPacket packet, String user) {
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();

                if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                    String srcIP = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
                    String dstIP = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());
                    int srcPort = tcp.source();
                    int dstPort = tcp.destination();

                    boolean matchSource = userSourceIP.isEmpty() || userSourceIP.equals(srcIP);
                    boolean matchDestination = userDestinationIP.isEmpty() || userDestinationIP.equals(dstIP);

                    if (matchSource && matchDestination) {
                        long timestamp = packet.getCaptureHeader().timestampInMillis();
                        String output = String.format("时间: %d 源IP: %s 目的IP: %s 端口: %d -> %d",
                                timestamp, srcIP, dstIP, srcPort, dstPort);
                        appendToInfoDisplay(output);
                    }
                }
            }
        };

        // 读取数据包
        pcap.loop(Count, jpacketHandler, "JnetPcap rocks!");
    }




    private void appendToInfoDisplay(String message) {
        infoDisplay.appendText(message + "\n");

    }

@FXML
    private void findAllDevices() {
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {
            appendToInfoDisplay("无法读取设备列表: " + errbuf);
            return;
        }

        int i = 0;
        for (PcapIf device : alldevs) {
            String regex = "addr=\\[INET4:([^\\]]+)\\]";
            String ip_ad=device.getAddresses().toString();
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(ip_ad);

            if (matcher.find()) {
                String addrWithBrackets = matcher.group(); // 包括方括号
                String addr = i++ + "设备地址: " +  addrWithBrackets;
                appendToInfoDisplay(addr);

            } else {
                appendToInfoDisplay(i++ +"设备地址找不到.");

            }
        }
        }
    private  void loadBlacklistedIPs() {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                blacklistedIPs.add(line.trim());
            }
        } catch (IOException e) {
            System.err.println("无法读取黑名单文件: " + e.getMessage());
        }
    }
    private  void loadWhitelistedIPs() {
        try (BufferedReader br = new BufferedReader(new FileReader(whitefile))) {
            String line;
            while ((line = br.readLine()) != null) {
                whitelistedIPs.add(line.trim());
            }
        } catch (IOException e) {
            System.err.println("无法读取白名单文件: " + e.getMessage());
        }
    }
    }




