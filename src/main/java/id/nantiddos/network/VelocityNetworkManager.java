package id.nantiddos.network;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.event.proxy.ProxyPingEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.messages.ChannelIdentifier;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import id.nantiddos.VelocityConfiguration;
import id.nantiddos.VelocityNantiDDoS;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class VelocityNetworkManager {
    private final ProxyServer server;
    private final Logger logger;
    private final VelocityNantiDDoS plugin;
    private final VelocityConfiguration config;
    
    private static final ChannelIdentifier NANTIDDOS_CHANNEL = 
            MinecraftChannelIdentifier.create("nantiddos", "network");
    
    private final Map<String, ServerInfo> networkServers = new ConcurrentHashMap<>();
    private final Set<String> synchronizedIps = Collections.synchronizedSet(new HashSet<>());
    
    private boolean enabled = true;
    
    @Inject
    public VelocityNetworkManager(ProxyServer server, Logger logger, VelocityNantiDDoS plugin, VelocityConfiguration config) {
        this.server = server;
        this.logger = logger;
        this.plugin = plugin;
        this.config = config;
        
        registerChannels();
        startTasks();
    }
    
    private void registerChannels() {
        server.getChannelRegistrar().register(NANTIDDOS_CHANNEL);
    }
    
    private void startTasks() {
        // Heartbeat task
        server.getScheduler().buildTask(plugin, this::sendHeartbeat)
            .repeat(30, TimeUnit.SECONDS)
            .schedule();
        
        // Data sync task
        server.getScheduler().buildTask(plugin, this::synchronizeData)
            .repeat(config.getSyncInterval(), TimeUnit.SECONDS)
            .schedule();
        
        // Cleanup task
        server.getScheduler().buildTask(plugin, this::cleanupStaleServers)
            .repeat(2, TimeUnit.MINUTES)
            .schedule();
    }
    
    @Subscribe
    public void onPluginMessage(PluginMessageEvent event) {
        if (!event.getIdentifier().equals(NANTIDDOS_CHANNEL)) return;
        
        try (ByteArrayInputStream byteIn = new ByteArrayInputStream(event.getData());
             DataInputStream in = new DataInputStream(byteIn)) {
            
            String messageType = in.readUTF();
            String sourceServer = in.readUTF();
            
            if (sourceServer.equals(config.getServerId())) return;
            
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
                case "AttackSync":
                    processAttackSync(in, sourceServer);
                    break;
                case "MasterAnnouncement":
                    processMasterAnnouncement(in, sourceServer);
                    break;
            }
            
        } catch (IOException e) {
            logger.error("Error processing plugin message: {}", e.getMessage());
        }
    }
    
    private void sendHeartbeat() {
        if (!enabled) return;
        
        try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(byteOut)) {
            
            out.writeUTF("Heartbeat");
            out.writeUTF(config.getServerId());
            out.writeUTF(config.getNetworkId());
            out.writeBoolean(config.isMasterServer());
            out.writeInt(server.getPlayerCount());
            out.writeInt(plugin.getConnectedIps().size());
            out.writeInt(plugin.getBlacklistedIps().size());
            out.writeInt(plugin.getCurrentThreatLevel());
            
            broadcastPluginMessage(byteOut.toByteArray());
            
        } catch (IOException e) {
            logger.error("Error sending heartbeat: {}", e.getMessage());
        }
    }
    
    private void synchronizeData() {
        if (!enabled) return;
        
        if (config.isMasterServer()) {
            if (config.isSyncBlacklist()) {
                synchronizeBlacklist();
            }
            
            if (config.isSyncWhitelist()) {
                synchronizeWhitelist();
            }
            
            if (config.isSyncAttackData()) {
                synchronizeAttackData();
            }
        } else {
            // If we lost connection to master, try to become master
            if (!config.getMasterServerId().isEmpty() && 
                !networkServers.containsKey(config.getMasterServerId())) {
                tryBecomeMaster();
            }
        }
    }
    
    private void synchronizeBlacklist() {
        Set<String> blacklistedIps = plugin.getBlacklistedIps();
        if (blacklistedIps.isEmpty()) return;
        
        try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(byteOut)) {
            
            out.writeUTF("BlacklistSync");
            out.writeUTF(config.getServerId());
            out.writeInt(blacklistedIps.size());
            
            for (String ip : blacklistedIps) {
                out.writeUTF(ip);
            }
            
            broadcastPluginMessage(byteOut.toByteArray());
            
        } catch (IOException e) {
            logger.error("Error synchronizing blacklist: {}", e.getMessage());
        }
    }
    
    private void synchronizeWhitelist() {
        Set<String> whitelistedIps = plugin.getWhitelistedIps();
        if (whitelistedIps.isEmpty()) return;
        
        try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(byteOut)) {
            
            out.writeUTF("WhitelistSync");
            out.writeUTF(config.getServerId());
            out.writeInt(whitelistedIps.size());
            
            for (String ip : whitelistedIps) {
                out.writeUTF(ip);
            }
            
            broadcastPluginMessage(byteOut.toByteArray());
            
        } catch (IOException e) {
            logger.error("Error synchronizing whitelist: {}", e.getMessage());
        }
    }
    
    private void synchronizeAttackData() {
        Map<String, Integer> suspiciousIps = plugin.getSuspiciousIps();
        if (suspiciousIps.isEmpty()) return;
        
        try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(byteOut)) {
            
            out.writeUTF("AttackSync");
            out.writeUTF(config.getServerId());
            out.writeInt(suspiciousIps.size());
            
            for (Map.Entry<String, Integer> entry : suspiciousIps.entrySet()) {
                out.writeUTF(entry.getKey());
                out.writeInt(entry.getValue());
            }
            
            broadcastPluginMessage(byteOut.toByteArray());
            
        } catch (IOException e) {
            logger.error("Error synchronizing attack data: {}", e.getMessage());
        }
    }
    
    private void announceAsMaster() {
        try (ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(byteOut)) {
            
            out.writeUTF("MasterAnnouncement");
            out.writeUTF(config.getServerId());
            out.writeUTF(config.getNetworkId());
            
            broadcastPluginMessage(byteOut.toByteArray());
            
        } catch (IOException e) {
            logger.error("Error announcing as master: {}", e.getMessage());
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
        
        if (isMaster && config.getMasterServerId().isEmpty()) {
            config.setMasterServerId(sourceServer);
        }
    }
    
    private void processBlacklistSync(DataInputStream in, String sourceServer) throws IOException {
        if (!config.isSyncBlacklist()) return;
        
        Set<String> blacklistedIps = new HashSet<>();
        int count = in.readInt();
        
        for (int i = 0; i < count; i++) {
            String ip = in.readUTF();
            blacklistedIps.add(ip);
            synchronizedIps.add(ip);
        }
        
        // Apply blacklist changes if this is not the master server
        if (!config.isMasterServer()) {
            for (String ip : blacklistedIps) {
                plugin.addToBlacklist(ip);
            }
        }
    }
    
    private void processWhitelistSync(DataInputStream in, String sourceServer) throws IOException {
        if (!config.isSyncWhitelist()) return;
        
        Set<String> whitelistedIps = new HashSet<>();
        int count = in.readInt();
        
        for (int i = 0; i < count; i++) {
            String ip = in.readUTF();
            whitelistedIps.add(ip);
            synchronizedIps.add(ip);
        }
        
        // Apply whitelist changes if this is not the master server
        if (!config.isMasterServer()) {
            for (String ip : whitelistedIps) {
                plugin.addToWhitelist(ip);
            }
        }
    }
    
    private void processAttackSync(DataInputStream in, String sourceServer) throws IOException {
        if (!config.isSyncAttackData()) return;
        
        Map<String, Integer> suspiciousIps = new HashMap<>();
        int count = in.readInt();
        
        for (int i = 0; i < count; i++) {
            String ip = in.readUTF();
            int riskScore = in.readInt();
            suspiciousIps.put(ip, riskScore);
            synchronizedIps.add(ip);
        }
        
        // Apply attack data if this is not the master server
        if (!config.isMasterServer()) {
            for (Map.Entry<String, Integer> entry : suspiciousIps.entrySet()) {
                if (entry.getValue() > config.getAutoblacklistThreshold()) {
                    plugin.addToBlacklist(entry.getKey());
                } else if (entry.getValue() > config.getBotScoreThreshold()) {
                    plugin.updateBotScore(entry.getKey(), entry.getValue());
                }
            }
        }
    }
    
    private void processMasterAnnouncement(DataInputStream in, String sourceServer) throws IOException {
        String networkId = in.readUTF();
        
        if (networkId.equals(config.getNetworkId())) {
            ServerInfo serverInfo = networkServers.computeIfAbsent(sourceServer, k -> new ServerInfo());
            serverInfo.lastHeartbeat = System.currentTimeMillis();
            serverInfo.networkId = networkId;
            serverInfo.isMaster = true;
            
            if (!config.isMasterServer() || sourceServer.compareTo(config.getServerId()) > 0) {
                config.setMasterServerId(sourceServer);
                logger.info("Recognized server {} as the master server", sourceServer);
            }
        }
    }
    
    private void cleanupStaleServers() {
        long now = System.currentTimeMillis();
        Set<String> staleServers = new HashSet<>();
        
        for (Map.Entry<String, ServerInfo> entry : networkServers.entrySet()) {
            if (now - entry.getValue().lastHeartbeat > 5 * 60 * 1000) { // 5 minutes
                staleServers.add(entry.getKey());
            }
        }
        
        for (String serverId : staleServers) {
            networkServers.remove(serverId);
            
            // If the master server went offline, try to become the new master
            if (serverId.equals(config.getMasterServerId())) {
                tryBecomeMaster();
            }
        }
    }
    
    private void tryBecomeMaster() {
        boolean shouldBecomeMaster = true;
        String highestServerId = config.getServerId();
        
        for (Map.Entry<String, ServerInfo> entry : networkServers.entrySet()) {
            String serverId = entry.getKey();
            ServerInfo info = entry.getValue();
            
            if (System.currentTimeMillis() - info.lastHeartbeat < 2 * 60 * 1000 && // 2 minutes
                serverId.compareTo(highestServerId) > 0) {
                highestServerId = serverId;
                shouldBecomeMaster = false;
            }
        }
        
        if (shouldBecomeMaster) {
            config.setMasterServer(true);
            config.setMasterServerId(config.getServerId());
            logger.info("This server is now the master server for network {}", config.getNetworkId());
            announceAsMaster();
        }
    }
    
    private void broadcastPluginMessage(byte[] data) {
        for (RegisteredServer target : server.getAllServers()) {
            target.sendPluginMessage(NANTIDDOS_CHANNEL, data);
        }
    }
    
    public Map<String, ServerInfo> getNetworkServers() {
        return new HashMap<>(networkServers);
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public static class ServerInfo {
        private long lastHeartbeat = System.currentTimeMillis();
        private String networkId = "default";
        private boolean isMaster = false;
        private int playerCount = 0;
        private int connectionCount = 0;
        private int blacklistSize = 0;
        private int threatLevel = 0;
        
        public boolean isMaster() {
            return isMaster;
        }
    }
}