package id.nantiddos.network;

import id.nantiddos.Nantiddos;
import id.nantiddos.protection.AttackDetector;
import id.nantiddos.protection.ConnectionTracker;
import id.nantiddos.protection.IPManager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.messaging.PluginMessageListener;
import org.bukkit.scheduler.BukkitTask;

public class ProxyIntegration implements PluginMessageListener {
    private final Nantiddos plugin;
    private final Logger logger;
    private final IPManager ipManager;
    private final ConnectionTracker connectionTracker;
    private final AttackDetector attackDetector;

    private final String BUNGEE_CHANNEL = "BungeeCord";
    private final String VELOCITY_CHANNEL = "velocity:main";
    private final String NANTIDDOS_CHANNEL = "nantiddos:network";
    
    private boolean enabled = true;
    private boolean isProxyDetected = false;
    private String proxyType = "NONE";
    private String serverId = "unknown";
    private String networkId = "default";
    
    private final Map<String, ServerInfo> networkServers = new ConcurrentHashMap<>();
    private final Set<String> synchronizedIps = new HashSet<>();
    private final Map<String, Long> lastSyncTimes = new ConcurrentHashMap<>();
    
    private BukkitTask syncTask;
    private BukkitTask heartbeatTask;
    
    private int syncInterval;
    private boolean syncBlacklist;
    private boolean syncWhitelist;
    private boolean syncAttackData;
    private boolean masterServer;
    private String masterServerId;
    
    public ProxyIntegration(Nantiddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.ipManager = plugin.getIpManager();
        this.connectionTracker = plugin.getConnectionTracker();
        this.attackDetector = plugin.getAttackDetector();
        
        loadConfig();
        detectProxyType();
        registerChannels();
        startSyncTask();
        startHeartbeatTask();
        
        logger.info("Network protection system initialized with mode: " + proxyType);
        logger.info("Server ID: " + serverId + ", Network ID: " + networkId);
        logger.info("This server is " + (masterServer ? "designated as the MASTER server" : "operating as a NODE"));
    }

    public void loadConfig() {
        serverId = plugin.getConfig().getString("network.server-id", UUID.randomUUID().toString().substring(0, 8));
        networkId = plugin.getConfig().getString("network.network-id", "default");
        syncInterval = plugin.getConfig().getInt("network.sync-interval-seconds", 30);
        syncBlacklist = plugin.getConfig().getBoolean("network.sync-blacklist", true);
        syncWhitelist = plugin.getConfig().getBoolean("network.sync-whitelist", true);
        syncAttackData = plugin.getConfig().getBoolean("network.sync-attack-data", true);
        masterServer = plugin.getConfig().getBoolean("network.master-server", false);
        masterServerId = plugin.getConfig().getString("network.master-server-id", "");
        
        plugin.getConfig().set("network.server-id", serverId);
        plugin.saveConfig();
    }
    
    private void detectProxyType() {
        if (Bukkit.getServer().spigot().getConfig().getBoolean("settings.bungeecord", false)) {
            proxyType = "BUNGEECORD";
            isProxyDetected = true;
        } else {
            try {
                Class.forName("com.velocitypowered.api.proxy.ProxyServer");
                proxyType = "VELOCITY";
                isProxyDetected = true;
            } catch (ClassNotFoundException e) {
                proxyType = "NONE";
                isProxyDetected = false;
            }
        }
    }
    
    private void registerChannels() {
        Bukkit.getMessenger().registerOutgoingPluginChannel(plugin, BUNGEE_CHANNEL);
        Bukkit.getMessenger().registerIncomingPluginChannel(plugin, BUNGEE_CHANNEL, this);
        
        Bukkit.getMessenger().registerOutgoingPluginChannel(plugin, VELOCITY_CHANNEL);
        Bukkit.getMessenger().registerIncomingPluginChannel(plugin, VELOCITY_CHANNEL, this);
        
        Bukkit.getMessenger().registerOutgoingPluginChannel(plugin, NANTIDDOS_CHANNEL);
        Bukkit.getMessenger().registerIncomingPluginChannel(plugin, NANTIDDOS_CHANNEL, this);
    }
    
    private void startSyncTask() {
        if (syncTask != null && !syncTask.isCancelled()) {
            syncTask.cancel();
        }
        
        syncTask = Bukkit.getScheduler().runTaskTimer(plugin, () -> {
            if (!enabled || !isProxyDetected) return;
            
            if (masterServer) {
                broadcastNetworkData();
            } else if (masterServerId.isEmpty() || 
                      (networkServers.containsKey(masterServerId) && 
                      System.currentTimeMillis() - networkServers.get(masterServerId).lastHeartbeat < 120000)) {
                sendDataToMaster();
            } else {
                tryBecomeMaster();
            }
        }, 20 * 60, 20 * syncInterval);
    }
    
    private void startHeartbeatTask() {
        if (heartbeatTask != null && !heartbeatTask.isCancelled()) {
            heartbeatTask.cancel();
        }
        
        heartbeatTask = Bukkit.getScheduler().runTaskTimer(plugin, () -> {
            if (!enabled || !isProxyDetected) return;
            
            sendHeartbeat();
            cleanupStaleServers();
        }, 20 * 30, 20 * 60);
    }
    
    private void sendHeartbeat() {
        ByteArrayOutputStream msgBytes = new ByteArrayOutputStream();
        DataOutputStream msgOut = new DataOutputStream(msgBytes);
        
        try {
            msgOut.writeUTF("Heartbeat");
            msgOut.writeUTF(serverId);
            msgOut.writeUTF(networkId);
            msgOut.writeBoolean(masterServer);
            msgOut.writeInt(Bukkit.getOnlinePlayers().size());
            msgOut.writeInt(connectionTracker.getConnectionsCount());
            msgOut.writeInt(ipManager.getBlacklistedIps().size());
            msgOut.writeInt(attackDetector.getCurrentThreatLevel());
            
            sendPluginMessage("ALL", "Forward", "ONLINE", msgBytes.toByteArray());
        } catch (IOException e) {
            logger.warning("Failed to send heartbeat: " + e.getMessage());
        }
    }
    
    private void broadcastNetworkData() {
        if (syncBlacklist) {
            broadcastBlacklist();
        }
        
        if (syncWhitelist) {
            broadcastWhitelist();
        }
        
        if (syncAttackData) {
            broadcastAttackData();
        }
    }
    
    private void broadcastBlacklist() {
        Set<String> blacklistedIps = ipManager.getBlacklistedIps();
        
        if (blacklistedIps.isEmpty()) return;
        
        ByteArrayOutputStream msgBytes = new ByteArrayOutputStream();
        DataOutputStream msgOut = new DataOutputStream(msgBytes);
        
        try {
            msgOut.writeUTF("BlacklistSync");
            msgOut.writeUTF(serverId);
            msgOut.writeInt(blacklistedIps.size());
            
            for (String ip : blacklistedIps) {
                msgOut.writeUTF(ip);
            }
            
            sendPluginMessage("ALL", "Forward", "ONLINE", msgBytes.toByteArray());
            
        } catch (IOException e) {
            logger.warning("Failed to broadcast blacklist: " + e.getMessage());
        }
    }
    
    private void broadcastWhitelist() {
        Set<String> whitelistedIps = ipManager.getWhitelistedIps();
        
        if (whitelistedIps.isEmpty()) return;
        
        ByteArrayOutputStream msgBytes = new ByteArrayOutputStream();
        DataOutputStream msgOut = new DataOutputStream(msgBytes);
        
        try {
            msgOut.writeUTF("WhitelistSync");
            msgOut.writeUTF(serverId);
            msgOut.writeInt(whitelistedIps.size());
            
            for (String ip : whitelistedIps) {
                msgOut.writeUTF(ip);
            }
            
            sendPluginMessage("ALL", "Forward", "ONLINE", msgBytes.toByteArray());
            
        } catch (IOException e) {
            logger.warning("Failed to broadcast whitelist: " + e.getMessage());
        }
    }
    
    private void broadcastAttackData() {
        Map<String, AttackDetector.AttackData> attackDataMap = attackDetector.getAttackDataMap();
        List<String> highRiskIps = new ArrayList<>();
        
        for (Map.Entry<String, AttackDetector.AttackData> entry : attackDataMap.entrySet()) {
            if (entry.getValue().getCurrentRiskScore() >= 75) {
                highRiskIps.add(entry.getKey());
            }
        }
        
        if (highRiskIps.isEmpty()) return;
        
        ByteArrayOutputStream msgBytes = new ByteArrayOutputStream();
        DataOutputStream msgOut = new DataOutputStream(msgBytes);
        
        try {
            msgOut.writeUTF("AttackDataSync");
            msgOut.writeUTF(serverId);
            msgOut.writeInt(highRiskIps.size());
            
            for (String ip : highRiskIps) {
                AttackDetector.AttackData data = attackDataMap.get(ip);
                msgOut.writeUTF(ip);
                msgOut.writeInt(data.getCurrentRiskScore());
                msgOut.writeUTF(data.getPrimaryAttackType().name());
                msgOut.writeUTF(data.getAlertLevel().name());
            }
            
            sendPluginMessage("ALL", "Forward", "ONLINE", msgBytes.toByteArray());
            
        } catch (IOException e) {
            logger.warning("Failed to broadcast attack data: " + e.getMessage());
        }
    }
    
    private void sendDataToMaster() {
        if (!masterServerId.isEmpty()) {
            Set<String> recentlyModifiedIps = getRecentlyModifiedIPs();
            
            if (!recentlyModifiedIps.isEmpty()) {
                ByteArrayOutputStream msgBytes = new ByteArrayOutputStream();
                DataOutputStream msgOut = new DataOutputStream(msgBytes);
                
                try {
                    msgOut.writeUTF("NodeUpdate");
                    msgOut.writeUTF(serverId);
                    msgOut.writeInt(recentlyModifiedIps.size());
                    
                    for (String ip : recentlyModifiedIps) {
                        msgOut.writeUTF(ip);
                        msgOut.writeBoolean(ipManager.isBlacklisted(ip));
                        msgOut.writeBoolean(ipManager.isWhitelisted(ip));
                        
                        Map<String, AttackDetector.AttackData> attackDataMap = attackDetector.getAttackDataMap();
                        if (attackDataMap.containsKey(ip)) {
                            AttackDetector.AttackData data = attackDataMap.get(ip);
                            msgOut.writeBoolean(true);
                            msgOut.writeInt(data.getCurrentRiskScore());
                            msgOut.writeUTF(data.getPrimaryAttackType().name());
                        } else {
                            msgOut.writeBoolean(false);
                        }
                    }
                    
                    sendPluginMessage("ALL", "Forward", masterServerId, msgBytes.toByteArray());
                    
                } catch (IOException e) {
                    logger.warning("Failed to send data to master: " + e.getMessage());
                }
            }
        }
    }
    
    private Set<String> getRecentlyModifiedIPs() {
        Set<String> result = new HashSet<>();
        
        Set<String> blacklistedIps = ipManager.getBlacklistedIps();
        for (String ip : blacklistedIps) {
            if (!synchronizedIps.contains(ip) || 
                !lastSyncTimes.containsKey(ip) || 
                System.currentTimeMillis() - lastSyncTimes.get(ip) > 300000) {
                result.add(ip);
                lastSyncTimes.put(ip, System.currentTimeMillis());
            }
        }
        
        Map<String, AttackDetector.AttackData> attackDataMap = attackDetector.getAttackDataMap();
        for (Map.Entry<String, AttackDetector.AttackData> entry : attackDataMap.entrySet()) {
            if (entry.getValue().getCurrentRiskScore() >= 50 && 
                (!synchronizedIps.contains(entry.getKey()) || 
                !lastSyncTimes.containsKey(entry.getKey()) || 
                System.currentTimeMillis() - lastSyncTimes.get(entry.getKey()) > 300000)) {
                result.add(entry.getKey());
                lastSyncTimes.put(entry.getKey(), System.currentTimeMillis());
            }
        }
        
        return result;
    }
    
    private void tryBecomeMaster() {
        boolean shouldBecomeMaster = true;
        String highestServerId = serverId;
        
        for (Map.Entry<String, ServerInfo> entry : networkServers.entrySet()) {
            if (entry.getValue().lastHeartbeat > System.currentTimeMillis() - 120000 && 
                entry.getKey().compareTo(highestServerId) > 0) {
                highestServerId = entry.getKey();
                shouldBecomeMaster = false;
            }
        }
        
        if (shouldBecomeMaster) {
            masterServer = true;
            masterServerId = serverId;
            plugin.getConfig().set("network.master-server", true);
            plugin.saveConfig();
            
            logger.info("This server has become the master server for the network");
            
            sendMasterAnnouncement();
        }
    }
    
    private void sendMasterAnnouncement() {
        ByteArrayOutputStream msgBytes = new ByteArrayOutputStream();
        DataOutputStream msgOut = new DataOutputStream(msgBytes);
        
        try {
            msgOut.writeUTF("MasterAnnouncement");
            msgOut.writeUTF(serverId);
            msgOut.writeUTF(networkId);
            
            sendPluginMessage("ALL", "Forward", "ONLINE", msgBytes.toByteArray());
        } catch (IOException e) {
            logger.warning("Failed to send master announcement: " + e.getMessage());
        }
    }
    
    private void cleanupStaleServers() {
        Set<String> staleServers = new HashSet<>();
        
        for (Map.Entry<String, ServerInfo> entry : networkServers.entrySet()) {
            if (System.currentTimeMillis() - entry.getValue().lastHeartbeat > 300000) {
                staleServers.add(entry.getKey());
            }
        }
        
        for (String serverId : staleServers) {
            networkServers.remove(serverId);
        }
        
        if (!staleServers.isEmpty()) {
            logger.info("Removed " + staleServers.size() + " stale servers from network registry");
        }
    }
    
    public void shutdown() {
        if (syncTask != null && !syncTask.isCancelled()) {
            syncTask.cancel();
        }
        
        if (heartbeatTask != null && !heartbeatTask.isCancelled()) {
            heartbeatTask.cancel();
        }
        
        Bukkit.getMessenger().unregisterOutgoingPluginChannel(plugin, BUNGEE_CHANNEL);
        Bukkit.getMessenger().unregisterIncomingPluginChannel(plugin, BUNGEE_CHANNEL, this);
        
        Bukkit.getMessenger().unregisterOutgoingPluginChannel(plugin, VELOCITY_CHANNEL);
        Bukkit.getMessenger().unregisterIncomingPluginChannel(plugin, VELOCITY_CHANNEL, this);
        
        Bukkit.getMessenger().unregisterOutgoingPluginChannel(plugin, NANTIDDOS_CHANNEL);
        Bukkit.getMessenger().unregisterIncomingPluginChannel(plugin, NANTIDDOS_CHANNEL, this);
    }
    
    public void enableProtection(boolean enable) {
        this.enabled = enable;
    }
    
    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        if (!enabled) return;
        
        ByteArrayInputStream msgBytes = new ByteArrayInputStream(message);
        DataInputStream msgIn = new DataInputStream(msgBytes);
        
        try {
            if (channel.equals(BUNGEE_CHANNEL) || channel.equals(VELOCITY_CHANNEL)) {
                String subChannel = msgIn.readUTF();
                
                if (subChannel.equals("Forward") || subChannel.equals("BungeeCord")) {
                    String subchannel = msgIn.readUTF();
                    
                    if (subchannel.equals(NANTIDDOS_CHANNEL)) {
                        short len = msgIn.readShort();
                        byte[] data = new byte[len];
                        msgIn.readFully(data);
                        
                        processNetworkMessage(data);
                    }
                }
            } else if (channel.equals(NANTIDDOS_CHANNEL)) {
                processNetworkMessage(message);
            }
        } catch (IOException e) {
            logger.warning("Error processing plugin message: " + e.getMessage());
        }
    }
    
    private void processNetworkMessage(byte[] data) {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
        
        try {
            String messageType = in.readUTF();
            String sourceServer = in.readUTF();
            
            if (sourceServer.equals(serverId)) {
                return;
            }
            
            switch (messageType) {
                case "Heartbeat":
                    processHeartbeat(in, sourceServer);
                    break;
                case "BlacklistSync":
                    processBlacklistSync(in, sourceServer);
                    break;
                case "WhitelistSync":
                    processWhitelistSync(in, sourceServer);
                    break;
                case "AttackDataSync":
                    processAttackDataSync(in, sourceServer);
                    break;
                case "NodeUpdate":
                    processNodeUpdate(in, sourceServer);
                    break;
                case "MasterAnnouncement":
                    processMasterAnnouncement(in, sourceServer);
                    break;
            }
        } catch (IOException e) {
            logger.warning("Error processing network message: " + e.getMessage());
        }
    }
    
    private void processHeartbeat(DataInputStream in, String sourceServer) throws IOException {
        String networkId = in.readUTF();
        boolean isMaster = in.readBoolean();
        int playerCount = in.readInt();
        int connectionCount = in.readInt();
        int blacklistSize = in.readInt();
        int threatLevel = in.readInt();
        
        ServerInfo serverInfo = networkServers.computeIfAbsent(sourceServer, k -> new ServerInfo());
        serverInfo.lastHeartbeat = System.currentTimeMillis();
        serverInfo.networkId = networkId;
        serverInfo.isMaster = isMaster;
        serverInfo.playerCount = playerCount;
        serverInfo.connectionCount = connectionCount;
        serverInfo.blacklistSize = blacklistSize;
        serverInfo.threatLevel = threatLevel;
        
        if (isMaster && masterServerId.isEmpty()) {
            masterServerId = sourceServer;
        }
    }
    
    private void processBlacklistSync(DataInputStream in, String sourceServer) throws IOException {
        Set<String> blacklistedIps = new HashSet<>();
        int count = in.readInt();
        
        for (int i = 0; i < count; i++) {
            String ip = in.readUTF();
            blacklistedIps.add(ip);
            synchronizedIps.add(ip);
        }
        
        if (syncBlacklist && !masterServer) {
            for (String ip : blacklistedIps) {
                lastSyncTimes.put(ip, System.currentTimeMillis());
                ipManager.addToBlacklist(ip);
            }
        }
    }
    
    private void processWhitelistSync(DataInputStream in, String sourceServer) throws IOException {
        Set<String> whitelistedIps = new HashSet<>();
        int count = in.readInt();
        
        for (int i = 0; i < count; i++) {
            String ip = in.readUTF();
            whitelistedIps.add(ip);
            synchronizedIps.add(ip);
        }
        
        if (syncWhitelist && !masterServer) {
            for (String ip : whitelistedIps) {
                lastSyncTimes.put(ip, System.currentTimeMillis());
                ipManager.addToWhitelist(ip);
            }
        }
    }
    
    private void processAttackDataSync(DataInputStream in, String sourceServer) throws IOException {
        Map<String, AttackInfo> attackInfoMap = new HashMap<>();
        int count = in.readInt();
        
        for (int i = 0; i < count; i++) {
            String ip = in.readUTF();
            int riskScore = in.readInt();
            String attackTypeName = in.readUTF();
            String alertLevelName = in.readUTF();
            
            AttackInfo attackInfo = new AttackInfo();
            attackInfo.ip = ip;
            attackInfo.riskScore = riskScore;
            attackInfo.attackType = attackTypeName;
            attackInfo.alertLevel = alertLevelName;
            
            attackInfoMap.put(ip, attackInfo);
            synchronizedIps.add(ip);
        }
        
        if (syncAttackData && !masterServer) {
            for (Map.Entry<String, AttackInfo> entry : attackInfoMap.entrySet()) {
                String ip = entry.getKey();
                AttackInfo info = entry.getValue();
                
                if (info.riskScore >= 85 && !ipManager.isWhitelisted(ip)) {
                    ipManager.addToBlacklist(ip);
                }
                
                lastSyncTimes.put(ip, System.currentTimeMillis());
            }
        }
    }
    
    private void processNodeUpdate(DataInputStream in, String sourceServer) throws IOException {
        if (!masterServer) return;
        
        int count = in.readInt();
        
        for (int i = 0; i < count; i++) {
            String ip = in.readUTF();
            boolean isBlacklisted = in.readBoolean();
            boolean isWhitelisted = in.readBoolean();
            boolean hasAttackData = in.readBoolean();
            
            if (isBlacklisted && syncBlacklist) {
                ipManager.addToBlacklist(ip);
            }
            
            if (isWhitelisted && syncWhitelist) {
                ipManager.addToWhitelist(ip);
            }
            
            if (hasAttackData && syncAttackData) {
                int riskScore = in.readInt();
                String attackTypeName = in.readUTF();
                
                if (riskScore >= 85 && !ipManager.isWhitelisted(ip)) {
                    ipManager.addToBlacklist(ip);
                }
            }
            
            synchronizedIps.add(ip);
            lastSyncTimes.put(ip, System.currentTimeMillis());
        }
    }
    
    private void processMasterAnnouncement(DataInputStream in, String sourceServer) throws IOException {
        String networkId = in.readUTF();
        
        if (networkId.equals(this.networkId)) {
            ServerInfo serverInfo = networkServers.computeIfAbsent(sourceServer, k -> new ServerInfo());
            serverInfo.lastHeartbeat = System.currentTimeMillis();
            serverInfo.networkId = networkId;
            serverInfo.isMaster = true;
            
            if (!masterServer || sourceServer.compareTo(serverId) > 0) {
                masterServer = false;
                masterServerId = sourceServer;
                
                plugin.getConfig().set("network.master-server", false);
                plugin.getConfig().set("network.master-server-id", masterServerId);
                plugin.saveConfig();
                
                logger.info("Recognized server " + sourceServer + " as the master server");
            }
        }
    }
    
    private void sendPluginMessage(String targetServer, String subChannel, String targetName, byte[] data) {
        if (!isProxyDetected || Bukkit.getOnlinePlayers().isEmpty()) return;
        
        Player sender = Bukkit.getOnlinePlayers().iterator().next();
        
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(outBytes);
        
        try {
            out.writeUTF(subChannel);
            out.writeUTF(targetName);
            
            if (data != null) {
                if (proxyType.equals("BUNGEECORD")) {
                    out.writeShort(data.length);
                    out.write(data);
                } else {
                    out.writeInt(data.length);
                    out.write(data);
                }
            }
            
            sender.sendPluginMessage(plugin, proxyType.equals("BUNGEECORD") ? BUNGEE_CHANNEL : VELOCITY_CHANNEL, outBytes.toByteArray());
        } catch (IOException e) {
            logger.warning("Error sending plugin message: " + e.getMessage());
        }
    }
    
    public Set<String> getNetworkServers() {
        return networkServers.keySet();
    }
    
    public boolean isMasterServer() {
        return masterServer;
    }
    
    public String getMasterServerId() {
        return masterServerId;
    }
    
    public boolean isProxyEnabled() {
        return isProxyDetected;
    }
    
    public String getProxyType() {
        return proxyType;
    }
    
    private class ServerInfo {
        String networkId = "default";
        long lastHeartbeat = 0;
        boolean isMaster = false;
        int playerCount = 0;
        int connectionCount = 0;
        int blacklistSize = 0;
        int threatLevel = 0;
    }
    
    private class AttackInfo {
        String ip;
        int riskScore;
        String attackType;
        String alertLevel;
    }
}